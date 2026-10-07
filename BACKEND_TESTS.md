# Backend regression coverage

The inventory comes from the [original README at upstream commit 34c1ab0](https://github.com/jpmens/mosquitto-auth-plug/blob/34c1ab00ce22f0e32faf3a2563019fb97e60e687/README.md). Every backend in its capability table is exercised against a real Mosquitto 2.1.2 process. Memcached, which is implemented but omitted from that table, is included as well.

CI uses Ubuntu 24.04 x86-64, GCC and Clang, OpenSSL 3.5.9, curl 8.22.0, cJSON 1.7.19, and MongoDB C Driver 1.30.12. It runs 18 HTTP checks and 31 additional backend scenarios for each compiler, plus sanitizer and static-analysis checks. A scenario can contain multiple positive and negative assertions. Test credentials, database records, PSKs, listeners, and API fixtures are synthetic. No production services or certificates are used.

## Matrix

| Backend | Service or format | Exercised behavior |
| --- | --- | --- |
| CDB | Bundled TinyCDB 0.78 | Password lookup; invalid, missing, empty and anonymous credential rejection; intentionally unrestricted ACLs |
| Files | Password and ACL files | Authentication; default/read/write topic rules; wildcard topics; `%u`/`%c` expansion; long client IDs; static superuser |
| HTTP | Local form API | Authentication; HTTP status/error/timeout handling; publish, subscribe and read ACLs; revocation; superuser; Basic authentication; request and environment encoding; long Host headers |
| JWT | Local bearer-token API | Delegated token validation; rejected token; password ignored as documented; superuser; ACL; client ID/environment encoding |
| LDAP | Ubuntu OpenLDAP/slapd | Search and user bind; invalid/missing credentials; RFC 4515 escaping; repeated filter placeholders; long usernames; failed-bind cleanup; default unrestricted ACL; `ldap_acl_deny=true` |
| MongoDB | MongoDB 7.0; MongoDB C Driver 1.30.12 | Password lookup; malformed password/type rejection; superuser; wildcard ACL arrays and read/write maps; mixed-type ACL arrays; string, integer (including zero) and ObjectId topic-list references; `%u`/`%c` expansion |
| MySQL | MySQL 8.4; Ubuntu MariaDB client library | Password and superuser queries; wildcard ACL query; username/client ID SQL escaping; long client IDs; two-parameter user query; `%u`/`%c` ACL expansion |
| PostgreSQL | PostgreSQL 16; Ubuntu libpq | Parameterized password/superuser/ACL queries; wildcard ACLs; quoted username rejection |
| Redis | Ubuntu Redis/hiredis | Password-protected connection; database selection; custom user/ACL queries; argument-boundary preservation for spaces and percent signs; exact-topic ACL allow/deny; static superuser |
| SQLite | Ubuntu SQLite3 | Bound password query; credential rejection; intentionally unrestricted ACLs; fallback authentication |
| TLS-PSK | OpenSSL 3 with SQLite key storage | Identity/key lookup; real TLS 1.2 encrypted publish/receive; wrong-key rejection; broker shutdown |
| Memcached | Ubuntu Memcached/libmemcached | Password lookup; exact-topic ACLs; missing-key denial; static superuser |

All brokers are checked for liveness and successful shutdown. Process maps must load the selected `libcrypto.so.3` and `libssl.so.3`. Build dependency checks reject legacy OpenSSL SONAMEs, including `libcrypto.so.10`, and unresolved dependencies.

## Shared behavior

- PBKDF2 SHA-1/SHA-256/SHA-512 verification, wrong passwords and malformed hash rejection.
- Separate `RAW_SALT` and `SUPPORT_DJANGO_HASHERS` builds, plus `np` hash generation.
- Static superuser glob matching, anonymous username mapping, multiple backend authentication and ACL fallback.
- Allowed and denied Will messages.
- Positive and negative authentication/ACL caching, password changes, expiration and cache disabling.
- Credential and ACL cache isolation when identities contain colons.
- Invalid and oversized environment mappings fail closed without terminating the broker.
- Strict Base64/PBKDF2 parsing rejects truncated input, unsupported digests, invalid iterations and trailing fields.
- AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer exercise parsing and option cleanup; cppcheck covers all C translation units; Valgrind runs the 18-check HTTP suite and fails on definite shutdown leaks.

The HTTP suite also checks reconnects, wildcard-identity rejection, read checks after subscribing, and absence of plaintext/encoded passwords in logs.

## Compatibility details

CDB and SQLite do not implement restrictive ACLs: authenticated clients can access arbitrary topics. LDAP also allows all topics unless `ldap_acl_deny` is enabled. These are upstream contracts, and the tests explicitly verify them. An unrestricted backend in a chain can grant a request another backend does not grant; the implementation checks the configured ACL chain rather than binding ACL evaluation to the authentication backend.

Database ACL queries receive Mosquitto access values 1 (read), 2 (write), and 4 (subscribe). The SQL fixtures use bit masks: 5 permits read/subscribe, 2 permits write, and 7 permits all three. Redis and Memcached retain their upstream numeric comparison and exact-topic behavior; fixtures use 7 for a full grant. Files read permissions and MongoDB `r` mappings include subscribe access.

JWT delegates bearer-token validation to the configured HTTP service; the plugin does not verify JWT signatures itself. Its upstream success rule accepts 2xx responses. The HTTP backend requires exactly 200. A nonempty MQTT password is still required before JWT dispatch even though the JWT backend does not inspect it.

The test matrix covers these concrete combinations. It does not certify every historical server/library release, MySQL/PostgreSQL client certificate option, HTTPS trust-store configuration, every MongoDB field alias, jitter distribution, cluster/failover topology, or production load. TLS-PSK is exercised with SQLite, not every possible backing database. Authentication caching should remain disabled for policies depending on a client ID because its key is username/password. The tests are not a CVE-free guarantee.

## Run locally

Use a disposable Ubuntu 24.04 environment. Install the packages listed in [the workflow](.github/workflows/http-plugin.yml). Build dependencies into a directory containing `mosquitto`, `openssl`, `curl`, `cjson`, and `mongo` prefixes:

```bash
bash .ci/build-dependencies.sh "$PWD/build/deps"
```

Start disposable services using Docker or Podman. Ports match the test runner; the `mqtt` database is reserved for fixtures and its `users`, `acl`, and MongoDB `topics` collections are rewritten by tests.

```bash
docker run -d --name mqtt-test-mysql -p 127.0.0.1:23306:3306 \
  -e MYSQL_ROOT_PASSWORD=local-db-password -e MYSQL_ROOT_HOST=% -e MYSQL_DATABASE=mqtt mysql:8.4
docker run -d --name mqtt-test-postgres -p 127.0.0.1:25432:5432 \
  -e POSTGRES_PASSWORD=local-db-password -e POSTGRES_DB=mqtt postgres:16
docker run -d --name mqtt-test-mongo -p 127.0.0.1:27027:27017 mongo:7.0
```

Wait for the database services to become ready, then run:

```bash
CC=gcc bash .ci/build-backends.sh "$PWD/build/deps" "$PWD/build/backends-gcc"
CC=clang bash .ci/run-security-checks.sh "$PWD/build/deps/openssl" "$PWD/build/security"
python3 tests/test_backends.py --deps "$PWD/build/deps" \
  --build "$PWD/build/backends-gcc" --artifacts-dir "$PWD/build/backends-gcc/tests"
```

The runner creates its own temporary Redis, Memcached, and LDAP processes and stops them on exit. LDAP runs a private copy of the installed `slapd` executable because the distribution's system-service AppArmor profile only permits its standard configuration/database paths. The fixture keeps its executable, configuration and database in the test directory without modifying the system service or its profile. Use a fresh artifacts directory for each run; fixtures and broker logs remain there for diagnosis. Repeat with `CC=clang` and a separate output directory. The workflow also runs the HTTP-only build and its dedicated suite described in [COMPATIBILITY.md](COMPATIBILITY.md). Remove the three disposable containers when finished.

CI publishes build/linker logs, broker logs, and per-scenario JSON results in the existing `http-plugin-evidence` artifact for 14 days. It does not publish binaries or deploy services.

## Decision log

- Purpose: test the original backend promises while retaining the HTTP deployment build.
- Constraints: archived C backends predate Mosquitto 2.1; different backends have different ACL contracts.
- Alternatives: HTTP-only tests, mocked backend functions, or real broker/backend integration tests.
- Decision: compile all implemented password backends together, build TLS-PSK separately, and exercise actual services with both compilers.
- Rationale: protocol tests expose authentication, ACL, library-loading and shutdown failures that compile checks cannot detect.
- Fixes: installed Mosquitto headers; PSK callback and validation; Files subscribe checks and dynamic pattern expansion; nullable expansion inputs; JWT/HTTP dynamic buffers and cleanup; bounded environment parameters; LDAP filter escaping and connection cleanup; strict PBKDF2/Base64 parsing; SQL result checks; Redis command argument boundaries; MongoDB type checks; CDB descriptor cleanup; backend and option cleanup; SHA-256 cache keys.
- Tradeoffs: more CI dependencies and runtime; service versions are tested major/minor lines rather than claims about all releases.
- Invariants: deny invalid credentials, preserve each documented ACL policy, keep fixtures isolated, preserve licenses, and never depend on legacy OpenSSL SONAMEs.
