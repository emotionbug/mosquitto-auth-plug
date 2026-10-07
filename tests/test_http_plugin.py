#!/usr/bin/env python3
"""Verify the HTTP plugin using an isolated broker and mock API."""
import argparse
import http.server
import json
import pathlib
import os
import pwd
import socket
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def mqtt_string(value):
    data = value.encode("utf-8")
    return struct.pack("!H", len(data)) + data


class MQTT:
    def __init__(self, port, username=None, password=None, clientid="test", keepalive=60, will=None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=20)
        flags = 2 | (128 if username is not None else 0) | (64 if password is not None else 0)
        if will is not None:
            flags |= 4
        data = mqtt_string("MQTT") + bytes([4, flags]) + struct.pack("!H", keepalive) + mqtt_string(clientid)
        if will is not None:
            data += mqtt_string(will[0]) + mqtt_string(will[1])
        if username is not None:
            data += mqtt_string(username)
        if password is not None:
            data += mqtt_string(password)
        self.send(0x10, data)
        try:
            kind, result = self.read()
        except EOFError:
            # API failures may cause the broker to disconnect without CONNACK.
            self.result = -1
            return
        assert kind == 0x20, (kind, result)
        self.result = result[1]

    def send(self, kind, data):
        remaining = len(data)
        length = bytearray()
        while True:
            digit = remaining % 128
            remaining //= 128
            length.append(digit | (128 if remaining else 0))
            if not remaining:
                break
        self.sock.sendall(bytes([kind]) + length + data)

    def exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError("The broker closed the connection.")
            data += chunk
        return data

    def read(self):
        kind = self.exact(1)[0]
        size, factor = 0, 1
        while True:
            digit = self.exact(1)[0]
            size += (digit & 127) * factor
            factor *= 128
            if not digit & 128:
                break
        return kind, self.exact(size)

    def subscribe(self, topic):
        self.send(0x82, b"\x00\x01" + mqtt_string(topic) + b"\x00")
        kind, data = self.read()
        assert kind == 0x90 and data[:2] == b"\x00\x01", (kind, data)
        return data[2]

    def publish(self, topic, payload):
        self.send(0x32, mqtt_string(topic) + b"\x00\x02" + payload)
        kind, data = self.read()
        assert kind == 0x40 and data == b"\x00\x02", (kind, data)

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True, type=pathlib.Path)
    parser.add_argument("--plugin", required=True, type=pathlib.Path)
    parser.add_argument("--openssl-prefix", required=True, type=pathlib.Path)
    parser.add_argument("--curl-prefix", required=True, type=pathlib.Path)
    parser.add_argument("--artifacts-dir", type=pathlib.Path)
    args = parser.parse_args()
    if args.artifacts_dir:
        args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    events, statuses, clients = [], {}, []
    password = "local-only+&= pässwörd"
    revoked_reads, revoked_writes = set(), set()

    class API(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            form = urllib.parse.parse_qs(body.decode(), keep_blank_values=True)
            events.append((self.path, form, self.headers.get_content_type()))
            user = form.get("username", [""])[0]
            if self.path == "/auth/user":
                status = statuses.get(user, 200 if form.get("password") == [password] else 403)
            elif self.path == "/auth/super":
                # Model an API that rejects a superuser check without a password.
                status = 403
            elif self.path == "/auth/acl":
                status = 200 if user == "observer" or form.get("topic") == ["allowed/topic"] else 403
                access = form.get("acc", [""])[0]
                if (access == "1" and user in revoked_reads) or (access == "2" and user in revoked_writes):
                    status = 403
                if user == "acl-error":
                    status = 500
            else:
                status = 404
            if user == "timeout":
                time.sleep(11)
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Length", "0")
            self.end_headers()

    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.start()
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="mqtt-http-plugin-") as directory:
        folder = pathlib.Path(directory)
        conf = folder / "test.conf"
        conf.write_text(f"""user {pwd.getpwuid(os.getuid()).pw_name}
allow_anonymous false
listener {port} 127.0.0.1
global_plugin {args.plugin.resolve()}
plugin_opt_backends http
plugin_opt_http_ip 127.0.0.1
plugin_opt_http_port {api.server_port}
plugin_opt_http_hostname 127.0.0.1
plugin_opt_http_getuser_uri /auth/user
plugin_opt_http_superuser_uri /auth/super
plugin_opt_http_aclcheck_uri /auth/acl
plugin_opt_http_retry_count 0
plugin_opt_auth_cacheseconds 0
plugin_opt_acl_cacheseconds 0
""")
        with (folder / "broker.log").open("w") as log:
            broker = subprocess.Popen([str(args.broker.resolve()), "-c", str(conf)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if broker.poll() is not None:
                        raise AssertionError((folder / "broker.log").read_text())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError("The broker did not start.")

                def connect(user=None, pw=None, clientid="test", keepalive=60):
                    client = MQTT(port, user, pw, clientid, keepalive)
                    clients.append(client)
                    assert broker.poll() is None, "The broker exited after an authentication request."
                    return client

                checks = []
                assert connect().result != 0
                assert connect("vehicle", "wrong").result != 0
                assert connect("vehicle", "").result != 0
                assert connect("", password).result != 0
                checks.append("anonymous_and_bad_password_denied")
                for code in (204, 302, 403, 500):
                    user = f"status-{code}"
                    statuses[user] = code
                    assert connect(user, password).result != 0
                checks.append("only_http_200_allowed")

                observer = connect("observer", password, "observer")
                assert observer.result == 0 and observer.subscribe("#") == 0
                publisher = connect("vehicle", password, "client&extra=value")
                assert publisher.result == 0
                publisher.publish("allowed/topic", b"valid-message")
                kind, payload = observer.read()
                assert kind >> 4 == 3 and payload.endswith(b"valid-message")
                checks.append("authenticated_publish_and_receive")
                publisher.publish("denied/topic", b"must-not-arrive")
                observer.sock.settimeout(.5)
                try:
                    observer.read()
                    raise AssertionError("A denied topic was delivered.")
                except socket.timeout:
                    pass
                checks.append("acl_denied_publish_not_delivered")

                acl_error = connect("acl-error", password, "acl-error")
                assert acl_error.result == 0
                try:
                    acl_error.publish("allowed/topic", b"api-error-must-not-arrive")
                except EOFError:
                    assert broker.poll() is None, "The broker exited after an ACL request."
                try:
                    observer.read()
                    raise AssertionError("A message was delivered during an ACL API failure.")
                except socket.timeout:
                    pass
                checks.append("acl_api_error_denied")

                assert publisher.subscribe("denied/topic") == 128
                assert publisher.subscribe("allowed/topic") == 0
                checks.append("subscribe_acl_denied_and_allowed")
                # Reconnect with a clean session so self-delivery cannot interfere with PUBACK checks.
                publisher.close()
                publisher = connect("vehicle", password, "client&extra=value", keepalive=0)
                assert publisher.result == 0
                publisher.publish("allowed/topic", b"keepalive-zero")
                assert observer.read()[1].endswith(b"keepalive-zero")
                checks.append("clean_session_reconnect_with_keepalive_zero")

                revoked_writes.add("vehicle")
                publisher.publish("allowed/topic", b"revoked-write")
                try:
                    observer.read()
                    raise AssertionError("A revoked publish permission was still granted.")
                except socket.timeout:
                    pass
                revoked_writes.remove("vehicle")
                publisher.publish("allowed/topic", b"write-restored")
                assert observer.read()[1].endswith(b"write-restored")
                checks.append("write_acl_revocation_and_recovery_without_cache")

                reader = connect("reader", password, "reader")
                assert reader.result == 0 and reader.subscribe("allowed/topic") == 0
                publisher.publish("allowed/topic", b"before-read-revocation")
                assert reader.read()[1].endswith(b"before-read-revocation")
                assert observer.read()[1].endswith(b"before-read-revocation")
                revoked_reads.add("reader")
                publisher.publish("allowed/topic", b"after-read-revocation")
                assert observer.read()[1].endswith(b"after-read-revocation")
                reader.sock.settimeout(.5)
                try:
                    reader.read()
                    raise AssertionError("A revoked read permission was still granted.")
                except socket.timeout:
                    pass
                reader.close()
                checks.append("read_acl_rechecked_after_subscription")

                statuses["revoked"] = 200
                assert connect("revoked", password, "revoked").result == 0
                statuses["revoked"] = 403
                assert connect("revoked", password, "revoked-again").result != 0
                checks.append("authentication_revocation_without_cache")
                statuses["recovery"] = 500
                assert connect("recovery", password, "recovery-fail").result != 0
                statuses["recovery"] = 200
                assert connect("recovery", password, "recovery-ok").result == 0
                checks.append("authentication_recovers_after_api_error")

                encoded = connect("user&extra=value", password, "encoded")
                assert encoded.result == 0
                encoded.publish("allowed/topic", b"encoded-username")
                assert observer.read()[1].endswith(b"encoded-username")
                assert any(path.endswith("/acl") and form.get("username") == ["user&extra=value"] and "extra" not in form for path, form, _ in events)
                checks.append("username_form_encoding")
                for user, clientid in (("user+wildcard", "normal"), ("normal", "client#wildcard")):
                    dangerous = connect(user, password, clientid)
                    assert dangerous.result == 0 and dangerous.subscribe("allowed/topic") == 128
                checks.append("wildcard_identity_acl_denied")

                user_events = [form for path, form, _ in events if path.endswith("/user") and form.get("username") == ["vehicle"]]
                assert any(form.get("password") == [password] for form in user_events)
                assert any(path.endswith("/acl") and form.get("clientid") == ["client&extra=value"] and "extra" not in form for path, form, _ in events)
                assert all(content == "application/x-www-form-urlencoded" for _, _, content in events)
                assert all(path != "/must-not-follow" for path, _, _ in events)
                checks.append("form_encoding_and_no_redirect")

                loaded = pathlib.Path(f"/proc/{broker.pid}/maps").read_text()
                assert "libcrypto.so.10" not in loaded and "libssl.so.10" not in loaded
                for prefix, library in ((args.openssl_prefix, "libcrypto.so.3"), (args.openssl_prefix, "libssl.so.3"), (args.curl_prefix, "libcurl.so")):
                    assert any(str(prefix.resolve()) in line and library in line for line in loaded.splitlines()), library
                checks.append("private_openssl_and_curl_loaded_without_so10")

                assert connect("timeout", password, "timeout").result != 0
                checks.append("http_timeout_denied")
                api.shutdown()
                api.server_close()
                assert connect("offline", password, "offline").result != 0
                checks.append("http_connection_failure_denied")
            except Exception:
                print((folder / "broker.log").read_text())
                raise
            finally:
                for client in clients:
                    client.close()
                broker.terminate()
                broker.wait(timeout=10)
                if args.artifacts_dir:
                    shutil.copyfile(folder / "broker.log", args.artifacts_dir / "broker.log")
                api.shutdown()
                api.server_close()
        logged = (folder / "broker.log").read_text()
        assert password not in logged and urllib.parse.quote(password, safe="") not in logged
        checks.append("password_not_logged")
        report = json.dumps({"result": "PASS", "checks": checks}, ensure_ascii=False, indent=2)
        if args.artifacts_dir:
            (args.artifacts_dir / "results.json").write_text(report + "\n", encoding="utf-8")
        print(report)


if __name__ == "__main__":
    main()
