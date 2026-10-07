#!/usr/bin/env python3
"""Exercise the upstream README backends against real, isolated services."""
import argparse
import base64
import contextlib
import http.server
import json
import os
import pathlib
import pwd
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse

from test_http_plugin import MQTT, free_port

from test_hashes import PASSWORD, password_hash
DB_PASSWORD = "local-db-password"


def wait_port(port, process=None):
    for _ in range(200):
        if process is not None and process.poll() is not None:
            raise AssertionError(f"Service exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"Service did not listen on {port}")


@contextlib.contextmanager
def process(command, logfile, env=None):
    with open(logfile, "w") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            yield child
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.results = []
        self.sequence = 0

    def check(self, name, function):
        try:
            function()
            self.results.append({"name": name, "status": "PASS"})
            print(f"PASS {name}", flush=True)
        except Exception:
            detail = traceback.format_exc()
            self.results.append({"name": name, "status": "FAIL", "detail": detail})
            print(f"FAIL {name}\n{detail}", flush=True)
        (self.root / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")

    @contextlib.contextmanager
    def broker(self, options, extra="", psk=False, env=None):
        self.sequence += 1
        port = free_port()
        path = self.root / f"broker-{self.sequence}"
        plugin = self.args.build / ("auth-psk.so" if psk else "auth-plug.so")
        config = (f"user {pwd.getpwuid(os.getuid()).pw_name}\n"
                  f"listener {port} 127.0.0.1\nallow_anonymous false\n"
                  f"global_plugin {plugin}\nlog_type all\n"
                  "plugin_opt_auth_cacheseconds 0\nplugin_opt_acl_cacheseconds 0\n")
        config += "".join(f"plugin_opt_{key} {value}\n" for key, value in options.items())
        path.with_suffix(".conf").write_text(config + extra)
        with process([str(self.args.deps / "mosquitto/sbin/mosquitto"), "-c",
                      str(path.with_suffix('.conf'))], path.with_suffix('.log'), env) as child:
            try:
                wait_port(port, child)
                maps = pathlib.Path(f"/proc/{child.pid}/maps").read_text()
                assert str(self.args.deps / "openssl/lib/libcrypto.so.3") in maps
                assert str(self.args.deps / "openssl/lib/libssl.so.3") in maps
                assert "libcrypto.so.10" not in maps and "libssl.so.10" not in maps
                yield port, child
                assert child.poll() is None, "Broker crashed during the test"
            except Exception:
                print(path.with_suffix('.log').read_text()[-6000:], flush=True)
                raise
        assert child.returncode == 0, f"Broker shutdown failed: {child.returncode}"

    def connect(self, port, user="alice", password=PASSWORD, allowed=True, clientid="test"):
        client = MQTT(port, user, password, clientid)
        assert (client.result == 0) == allowed, (user, client.result, allowed)
        return client

    def auth(self, options):
        with self.broker(options) as (port, _):
            for user, pwd, allowed in [("alice", PASSWORD, True), ("alice", "wrong", False),
                                       ("missing", PASSWORD, False), (None, None, False),
                                       ("alice", "", False)]:
                self.connect(port, user, pwd, allowed).close()

    def delivery(self, port, user="alice", topic="allowed/topic", allowed=True,
                 subscriber="observer", read_allowed=True, clientid="writer"):
        reader = self.connect(port, subscriber, clientid="reader")
        writer = self.connect(port, user, password=PASSWORD if user is not None else None, clientid=clientid)
        try:
            assert reader.subscribe(topic) == 0, "Observer must be able to subscribe"
            writer.publish(topic, b"fixture-message")
            reader.sock.settimeout(.3 if not (allowed and read_allowed) else 3)
            try:
                kind, data = reader.read()
            except socket.timeout:
                assert not (allowed and read_allowed), "Expected publication was lost"
            else:
                assert allowed and read_allowed, "Forbidden publication was delivered"
                size = struct.unpack("!H", data[:2])[0]
                assert kind == 0x30 and data[2:2+size].decode() == topic
                assert data[2+size:] == b"fixture-message"
        finally:
            reader.close()
            writer.close()

    def acl(self, options, unrestricted=False, backend_super=False):
        options = {**options, "superusers": "observer"}
        with self.broker(options) as (port, _):
            self.delivery(port)
            self.delivery(port, topic="forbidden/topic", allowed=unrestricted)
            client = self.connect(port, clientid="subscriber")
            try:
                assert client.subscribe("allowed/topic") == 0
                assert client.subscribe("forbidden/topic") == (0 if unrestricted else 128)
            finally:
                client.close()
            if backend_super:
                self.delivery(port, user="admin", topic="forbidden/topic")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deps", type=pathlib.Path, required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--artifacts-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.deps, args.build = args.deps.resolve(), args.build.resolve()
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    suite = Suite(args, args.artifacts_dir.resolve())
    root = suite.root
    users = {name: password_hash() for name in ("alice", "observer", "admin", "file-only")}
    users.update({digest: password_hash(digest=digest) for digest in ("sha1", "sha256", "sha512")})
    passwords = root / "passwords"
    passwords.write_text("".join(f"{name}:{value}\n" for name, value in users.items()))
    aclfile = root / "acl"
    aclfile.write_text("user alice\ntopic allowed/#\ntopic read read/#\ntopic write write/#\n"
                       "pattern pattern/%u/%c/#\nuser observer\ntopic #\n")
    files = dict(backends="files", password_file=passwords, acl_file=aclfile)
    db = root / "users.sqlite"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY, pw TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, ?)", users.items())
        conn.execute("INSERT INTO users VALUES ('db-only', ?)", (password_hash(),))
        conn.execute("INSERT INTO users VALUES (?, ?)", ("psk-client", "a1b2c3d4e5f60708"))
    sqlite = dict(backends="sqlite", dbpath=db, sqliteuserquery="SELECT pw FROM users WHERE username=?")
    cdb = root / "users.cdb"
    payload = "".join(f"+{len(k)},{len(v)}:{k}->{v}\n" for k, v in users.items()) + "\n"
    subprocess.run([str(args.build / "tinycdb/cdb"), "-c", str(cdb)],
                   input=payload.encode(), check=True)

    for name, options in [("Files", files), ("SQLite", sqlite), ("CDB", dict(backends="cdb", cdbname=cdb))]:
        suite.check(f"{name}: valid, invalid, unknown, empty and anonymous authentication", lambda o=options: suite.auth(o))
        suite.check(f"{name}: ACL contract and static superuser", lambda o=options, n=name: suite.acl(o, unrestricted=n != "Files"))

    def hashes():
        subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('test_hashes.py')),
                        '--build', str(args.build), '--openssl-prefix', str(args.deps / 'openssl')], check=True)
    suite.check("PBKDF2: SHA1/SHA256/SHA512, RAW_SALT, Django, malformed hashes, np and expansion", hashes)

    def file_patterns():
        with suite.broker({**files, "superusers": "observer"}) as (port, _):
            for client in ("device", "x" * 700):
                suite.delivery(port, topic=f"pattern/alice/{client}/data", clientid=client)
            suite.delivery(port, topic="pattern/other/device/data", allowed=False, clientid="device")
            suite.delivery(port, topic="read/item", allowed=False)
            suite.delivery(port, topic="write/item")
            suite.delivery(port, user="observer", subscriber="alice", topic="read/item")
    suite.check("Files: read/write rules and username/client ID patterns including long IDs", file_patterns)

    def wills():
        with suite.broker({**files, "superusers": "observer"}) as (port, _):
            for topic, allowed in [("allowed/will", True), ("forbidden/will", False)]:
                observer = suite.connect(port, "observer", clientid="observer")
                assert observer.subscribe(topic) == 0
                client = MQTT(port, "alice", PASSWORD, "will-client", will=(topic, "last-will"))
                assert client.result == 0
                client.close()
                observer.sock.settimeout(2 if allowed else .3)
                try:
                    _, data = observer.read()
                    assert allowed and data.endswith(b"last-will")
                except socket.timeout:
                    assert not allowed
                finally:
                    observer.close()
    suite.check("Will messages: allowed delivery and denied-topic suppression", wills)

    def auth_cache():
        with suite.broker({**sqlite, "auth_cacheseconds": 1, "auth_cachejitter": 0}) as (port, _):
            suite.connect(port).close()
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE users SET pw=? WHERE username='alice'", (password_hash("changed"),))
            suite.connect(port).close()
            suite.connect(port, "missing", allowed=False).close()
            with sqlite3.connect(db) as conn:
                conn.execute("INSERT INTO users VALUES ('missing', ?)", (password_hash(),))
            suite.connect(port, "missing", allowed=False).close()
            time.sleep(2.1)
            suite.connect(port, allowed=False).close()
            suite.connect(port, "alice", "changed").close()
            suite.connect(port, "missing").close()
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE users SET pw=? WHERE username='alice'", (password_hash(),))
            conn.execute("DELETE FROM users WHERE username='missing'")
    suite.check("Authentication cache: positive/negative entries, password isolation and TTL expiry", auth_cache)

    def cache_isolation():
        with sqlite3.connect(db) as conn:
            conn.execute("INSERT INTO users VALUES ('cache:alice', ?)", (password_hash("secret"),))
        with suite.broker({**sqlite, "auth_cacheseconds": 30}) as (port, _):
            suite.connect(port, "cache:alice", "secret").close()
            suite.connect(port, "cache", "alice:secret", allowed=False).close()
    suite.check("Authentication cache: colon-delimited credentials cannot share an entry", cache_isolation)

    def multiple():
        with suite.broker({**sqlite, **files, "backends": "files,sqlite", "superusers": "obs*"}) as (port, _):
            suite.connect(port, "file-only").close()
            suite.connect(port, "db-only").close()
            suite.connect(port, "psk-client", "wrong", False).close()
            suite.delivery(port, topic="forbidden/topic")  # SQLite grants ACLs in the chain.
        with suite.broker({**files, "anonusername": "observer"}, "allow_anonymous true\n") as (port, _):
            suite.connect(port, None, None).close()
            suite.delivery(port, user=None, topic="anonymous/topic")
    suite.check("Multiple backends: authentication, ACL fallback, glob superuser and anonymous mapping", multiple)

    with contextlib.ExitStack() as stack:
        redis_port, mem_port, ldap_port = free_port(), free_port(), free_port()
        for name, port, command in [
            ("redis", redis_port, ["redis-server", "--bind", "127.0.0.1", "--port", str(redis_port),
                                    "--save", "", "--appendonly", "no", "--requirepass", DB_PASSWORD]),
            ("memcached", mem_port, ["memcached", "-u", pwd.getpwuid(os.getuid()).pw_name,
                                     "-l", "127.0.0.1", "-p", str(mem_port), "-U", "0"]),
        ]:
            child = stack.enter_context(process(command, root / f"{name}.log"))
            wait_port(port, child)
        import redis
        store = redis.Redis(host="127.0.0.1", port=redis_port, db=2, password=DB_PASSWORD)
        for user, hashed in users.items():
            store.set(f"user:{user}", hashed)
            store.set(f"acl:{user}-allowed/topic", 7)
            with socket.create_connection(("127.0.0.1", mem_port)) as sock:
                value = hashed.encode()
                sock.sendall(f"set {user} 0 0 {len(value)}\r\n".encode() + value + b"\r\n")
                assert sock.recv(100) == b"STORED\r\n"
                sock.sendall(f"set {user}-allowed/topic 0 0 1\r\n7\r\n".encode())
                assert sock.recv(100) == b"STORED\r\n"
        for name, options in [
            ("Redis", dict(backends="redis", redis_host="127.0.0.1", redis_port=redis_port, redis_db=2,
                           redis_pass=DB_PASSWORD, redis_userquery="GET user:%s", redis_aclquery="GET acl:%s-%s")),
            ("Memcached", dict(backends="memcached", memcached_host="127.0.0.1", memcached_port=mem_port, memcached_aclquery="enabled")),
        ]:
            suite.check(f"{name}: authentication", lambda o=options: suite.auth(o))
            suite.check(f"{name}: exact-topic ACL allow/deny and static superuser", lambda o=options: suite.acl(o))

        for backend, port in [("mysql", 23306), ("postgres", 25432)]:
            def database_tests(backend=backend, port=port):
                if backend == "mysql":
                    import pymysql
                    conn = pymysql.connect(host="127.0.0.1", port=port, user="root", password=DB_PASSWORD, database="mqtt")
                else:
                    import psycopg2
                    conn = psycopg2.connect(host="127.0.0.1", port=port, user="postgres", password=DB_PASSWORD, dbname="mqtt")
                try:
                    with conn.cursor() as cur:
                        cur.execute("DROP TABLE IF EXISTS acl")
                        cur.execute("DROP TABLE IF EXISTS users")
                        cur.execute("CREATE TABLE users (username VARCHAR(100), pw VARCHAR(300), super INT)")
                        cur.execute("CREATE TABLE acl (username VARCHAR(100), topic VARCHAR(300), rw INT)")
                        for user, hashed in users.items():
                            cur.execute("INSERT INTO users VALUES (%s,%s,%s)", (user, hashed, int(user == "admin")))
                            cur.execute("INSERT INTO acl VALUES (%s,%s,%s)", (user, "allowed/#", 7))
                        if backend == "mysql":
                            cur.execute("INSERT INTO acl VALUES (%s,%s,%s)", ("alice", "pattern/%u/%c/#", 7))
                    conn.commit()
                    marker = "'%s'" if backend == "mysql" else "$1"
                    access = "%d" if backend == "mysql" else "$2"
                    options = dict(backends=backend, host="127.0.0.1", port=port,
                                   user="root" if backend == "mysql" else "postgres", **{"pass": DB_PASSWORD}, dbname="mqtt",
                                   userquery=f"SELECT pw FROM users WHERE username={marker}",
                                   superquery=f"SELECT super FROM users WHERE username={marker}",
                                   aclquery=f"SELECT topic FROM acl WHERE username={marker} AND (rw & {access}) > 0")
                    suite.auth(options)
                    suite.acl(options, backend_super=True)
                    with suite.broker(options) as (mqtt_port, _):
                        suite.connect(mqtt_port, "' OR '1'='1", allowed=False).close()
                    if backend == "mysql":
                        with suite.broker({**options, "superusers": "observer"}) as (mqtt_port, _):
                            suite.delivery(mqtt_port, topic="pattern/alice/device/item", clientid="device")
                            suite.delivery(mqtt_port, topic="pattern/other/device/item", clientid="device", allowed=False)
                        with suite.broker({**options, "userquery": "SELECT pw FROM users WHERE username='%s' AND 'device'='%s'"}) as (mqtt_port, _):
                            suite.connect(mqtt_port, clientid="device").close()
                            suite.connect(mqtt_port, clientid="wrong", allowed=False).close()
                            suite.connect(mqtt_port, clientid="x' OR '1'='1", allowed=False).close()
                            suite.connect(mqtt_port, clientid="x" * 700, allowed=False).close()
                finally:
                    conn.close()
            suite.check(f"{backend}: authentication, wildcard ACL, SQL parameters and backend superuser", database_tests)

        def mongo_tests():
            import pymongo
            from bson import ObjectId
            client = pymongo.MongoClient("mongodb://127.0.0.1:27027", serverSelectionTimeoutMS=5000)
            db = client.mqtt
            db.users.delete_many({})
            db.topics.delete_many({})
            db.users.insert_many([dict(username=u, password=h, superuser=u == "admin", topics=["allowed/#"])
                                  for u, h in users.items()])
            options = dict(backends="mongo", mongo_uri="mongodb://127.0.0.1:27027", mongo_database="mqtt")
            try:
                suite.auth(options)
                suite.acl(options, backend_super=True)
                for topics in ({"allowed/#": "rw"}, ["allowed/#"], "list-name", 0, 17, ObjectId()):
                    db.users.update_one({"username": "alice"}, {"$set": {"topics": topics}})
                    if not isinstance(topics, (dict, list)):
                        db.topics.insert_one({"_id": topics, "topics": ["allowed/#"]})
                    suite.acl(options)
                db.users.update_one({"username": "alice"}, {"$set": {"topics": {"read/#": "r", "write/#": "w", "pattern/%u/%c/#": "rw"}}})
                with suite.broker({**options, "superusers": "observer"}) as (port, _):
                    suite.delivery(port, user="observer", subscriber="alice", topic="read/item")
                    suite.delivery(port, topic="read/item", allowed=False)
                    suite.delivery(port, topic="write/item")
                    suite.delivery(port, topic="pattern/alice/device/item", clientid="device")
            finally:
                client.close()
        suite.check("MongoDB: authentication, superuser, ACL arrays/maps and string/integer/ObjectId references", mongo_tests)

        ldap_db = root / "ldap-db"
        ldap_db.mkdir()
        ldap_conf = root / "slapd.conf"
        ldap_conf.write_text(f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile {root}/slapd.pid
argsfile {root}/slapd.args
modulepath /usr/lib/ldap
moduleload back_mdb
database mdb
maxsize 10485760
suffix "dc=example,dc=org"
rootdn "cn=admin,dc=example,dc=org"
rootpw {DB_PASSWORD}
directory {ldap_db}
access to * by * read
""")
        # The distro's system-service AppArmor profile excludes test directories.
        ldap_executable = root / "slapd-fixture"
        shutil.copy2(shutil.which("slapd"), ldap_executable)
        child = stack.enter_context(process([str(ldap_executable), "-f", str(ldap_conf), "-h", f"ldap://127.0.0.1:{ldap_port}", "-d", "1"], root / "ldap.log"))
        wait_port(ldap_port, child)
        ldif = "dn: dc=example,dc=org\nobjectClass: domain\ndc: example\n\n"
        for user in users:
            ldif += (f"dn: uid={user},dc=example,dc=org\nobjectClass: inetOrgPerson\n"
                     f"cn: {user}\nsn: Test\nuid: {user}\nuserPassword: {PASSWORD}\n\n")
        subprocess.run(["ldapadd", "-x", "-H", f"ldap://127.0.0.1:{ldap_port}", "-D", "cn=admin,dc=example,dc=org",
                        "-w", DB_PASSWORD], input=ldif.encode(), check=True, stdout=subprocess.DEVNULL)
        ldap = dict(backends="ldap", ldap_uri=f"ldap://127.0.0.1:{ldap_port}/dc=example,dc=org?cn?sub?(uid=@)",
                    binddn="cn=admin,dc=example,dc=org", bindpw=DB_PASSWORD)
        suite.check("LDAP: user search/bind and default unrestricted ACL", lambda: (suite.auth(ldap), suite.acl(ldap, unrestricted=True)))
        def ldap_deny():
            with suite.broker({**ldap, "ldap_acl_deny": "true", "superusers": "observer"}) as (port, _):
                suite.delivery(port, allowed=False)
        suite.check("LDAP: ldap_acl_deny rejects publication", ldap_deny)

        jwt_events = []
        http_acl_allowed = True
        http_auth_allowed = True
        http_events = []
        class API(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode(), keep_blank_values=True)
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                if self.path.startswith("/http/"):
                    http_events.append((self.path, form, self.headers.get("Authorization"), self.headers.get("Host")))
                    if self.path == "/http/user":
                        status = 200 if http_auth_allowed and form.get("password") == [PASSWORD] else 403
                    elif self.path == "/http/super":
                        status = 200 if form.get("username") == ["admin"] else 403
                    else:
                        status = 200 if form.get("username") == ["observer"] or (http_acl_allowed and form.get("topic") == ["allowed/topic"] and form.get("username") != ["a:alice"]) else 403
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                jwt_events.append((self.path, token, form))
                status = 403
                if self.path == "/user" and token in ("alice", "observer", "admin"):
                    status = 200
                if self.path == "/super" and token == "admin":
                    status = 200
                if self.path == "/acl" and form.get("topic") == ["allowed/topic"]:
                    status = 200
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()
        api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
        threading.Thread(target=api.serve_forever, daemon=True).start()
        stack.callback(api.server_close)
        stack.callback(api.shutdown)
        jwt = dict(backends="jwt", http_ip="127.0.0.1", http_hostname="127.0.0.1", http_port=api.server_port,
                   http_getuser_uri="/user", http_superuser_uri="/super", http_aclcheck_uri="/acl")
        def jwt_test():
            suite.acl(jwt, backend_super=True)
            with suite.broker({**jwt, "http_getuser_params": "fixture=MQTT_FIXTURE"},
                              env={**os.environ, "MQTT_FIXTURE": "space & equals=value"}) as (port, _):
                suite.connect(port).close()
                suite.connect(port, "missing", allowed=False).close()
                suite.connect(port, "alice", "ignored-password").close()
                c = suite.connect(port, clientid="id&=space value")
                c.publish("allowed/topic", b"test")
                c.close()
            assert any(form.get("fixture") == ["space & equals=value"] for _, _, form in jwt_events)
            assert any(form.get("clientid") == ["id&=space value"] for _, _, form in jwt_events)
        suite.check("JWT: bearer validation, superuser, ACL, ignored password and form/environment encoding", jwt_test)

        http_options_config = {**jwt, "backends": "http", "http_getuser_uri": "/http/user", "http_superuser_uri": "/http/super",
                "http_aclcheck_uri": "/http/acl", "http_retry_count": 0}
        def http_options():
            env = {**os.environ, "MQTT_FIXTURE": "space & equals=value"}
            params = {f"http_{method}_params": "fixture=MQTT_FIXTURE" for method in ("getuser", "superuser", "aclcheck")}
            with suite.broker({**http_options_config, **params, "http_basic_auth_key": base64.b64encode(b"api-user:api-password").decode()}, env=env) as (port, _):
                suite.delivery(port)
                suite.delivery(port, user="admin", topic="forbidden/topic")
            expected = "Basic " + base64.b64encode(b"api-user:api-password").decode()
            assert all(form.get("fixture") == ["space & equals=value"] and auth == expected
                       for _, form, auth, _ in http_events)
            assert {path for path, *_ in http_events} == {"/http/user", "/http/super", "/http/acl"}
        suite.check("HTTP: backend superuser, Basic authentication and environment parameters on all endpoints", http_options)

        def invalid_environment():
            for config in (http_options_config, jwt):
                for params, value in [("fixture", "value"), ("fixture=MQTT_FIXTURE", "x" * 2000)]:
                    with suite.broker({**config, "http_getuser_params": params},
                                      env={**os.environ, "MQTT_FIXTURE": value}) as (port, _):
                        suite.connect(port, allowed=False).close()
        suite.check("HTTP/JWT: malformed and oversized environment parameters fail closed", invalid_environment)

        def acl_cache():
            nonlocal http_acl_allowed
            with suite.broker({**http_options_config, "acl_cacheseconds": 1, "acl_cachejitter": 0}) as (port, _):
                suite.delivery(port)
                http_acl_allowed = False
                suite.delivery(port)
                time.sleep(2.1)
                suite.delivery(port, allowed=False)
                http_acl_allowed = True
                suite.delivery(port, allowed=False)
                time.sleep(2.1)
                suite.delivery(port)
        suite.check("ACL cache: grant/denial reuse, revocation and TTL expiry", acl_cache)

        def acl_cache_isolation():
            with suite.broker({**http_options_config, "acl_cacheseconds": 30}) as (port, _):
                suite.delivery(port, clientid="c:a")
                suite.delivery(port, user="a:alice", clientid="c", allowed=False)
        suite.check("ACL cache: colon-delimited client IDs and usernames cannot share grants", acl_cache_isolation)

        def zero_cache():
            nonlocal http_auth_allowed
            with suite.broker({**http_options_config, "auth_cacheseconds": 0}) as (port, _):
                suite.connect(port).close()
                http_auth_allowed = False
                suite.connect(port, allowed=False).close()
                http_auth_allowed = True
                suite.connect(port).close()
        suite.check("HTTP: disabling the authentication cache applies revocation immediately", zero_cache)

    def psk_test():
        with suite.broker({**sqlite, "psk_database": "sqlite"},
                          "psk_hint fixture\nuse_identity_as_username true\n", psk=True) as (port, _):
            common = ["-h", "127.0.0.1", "-p", str(port), "--psk-identity", "psk-client", "--tls-version", "tlsv1.2"]
            sub = subprocess.Popen([str(args.deps / "mosquitto/bin/mosquitto_sub"), *common,
                                    "--psk", "a1b2c3d4e5f60708", "-t", "psk/topic", "-C", "1", "-W", "5"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                time.sleep(.5)
                subprocess.run([str(args.deps / "mosquitto/bin/mosquitto_pub"), *common, "--psk", "a1b2c3d4e5f60708",
                                "-t", "psk/topic", "-m", "encrypted-message"], check=True, timeout=8, capture_output=True)
                output, error = sub.communicate(timeout=8)
                assert sub.returncode == 0 and output.strip() == b"encrypted-message", error
                bad = subprocess.run([str(args.deps / "mosquitto/bin/mosquitto_pub"), *common, "--psk", "0000000000000000",
                                      "-t", "psk/topic", "-m", "must-deny"], timeout=8, capture_output=True)
                assert bad.returncode != 0
            finally:
                if sub.poll() is None:
                    sub.kill()
                    sub.wait()
    suite.check("TLS-PSK: SQLite identity lookup, encrypted delivery and incorrect key rejection", psk_test)
    (root / "results.json").write_text(json.dumps(suite.results, indent=2) + "\n")
    passed = sum(item["status"] == "PASS" for item in suite.results)
    print(f"{passed}/{len(suite.results)} backend scenarios passed", flush=True)
    raise SystemExit(passed != len(suite.results))


if __name__ == "__main__":
    main()
