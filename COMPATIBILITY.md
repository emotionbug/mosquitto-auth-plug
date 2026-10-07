# HTTP backend compatibility

This branch is based on archived upstream `jpmens/mosquitto-auth-plug` commit `34c1ab00ce22f0e32faf3a2563019fb97e60e687`. The tested platform is Linux x86-64 with Mosquitto 2.1.2, OpenSSL 3.5.9, and curl 8.22.0. This document describes the HTTP-only deployment build. [BACKEND_TESTS.md](BACKEND_TESTS.md) covers regression tests for every backend listed in the original README. Older Mosquitto versions are outside the tested scope. The BSD license and third-party notices remain in [LICENSE.txt](LICENSE.txt).

## Changes

- Use the Mosquitto 2.1 installed headers and API v4 callback signatures.
- Read usernames and client IDs from the broker instead of accumulating per-client copies.
- URL-encode client IDs and remove password-bearing POST body logs.
- Accept only HTTP 200 for authentication. APIs that previously relied on HTTP 204 must update their contract.
- Use the correct long types for libcurl response codes and timeout arguments.
- Match curl string allocation/free rules and remove a double free in environment parameter handling.
- Provide an HTTP-only build with explicit RUNPATHs for OpenSSL 3, libcurl, and libmosquitto.

## Build

Install a C compiler, Bash, binutils, and development headers/shared libraries for all three dependencies. Install cJSON development headers required by the Mosquitto headers. Each dependency prefix must use `lib` as its library directory.

```bash
bash build-http.sh /opt/mosquitto-2.1.2 /opt/openssl-3.5.9 /opt/curl-8.22.0 build/http
python3 tests/test_http_plugin.py \
  --broker /opt/mosquitto-2.1.2/sbin/mosquitto \
  --plugin build/http/auth-plug.so \
  --openssl-prefix /opt/openssl-3.5.9 \
  --curl-prefix /opt/curl-8.22.0
```

Build OpenSSL first, then build curl and Mosquitto against that same OpenSSL installation. Rebuild for the target operating system, architecture, glibc, and installation paths. Do not symlink an old OpenSSL SONAME to a new library.

Outputs include `auth-plug.so`, license notices, SHA-256 checksums, ELF/ldd output, source file checksums, and build information. Direct dependencies are `libmosquitto.so.1`, `libcrypto.so.3`, `libcurl.so.4`, and `libc.so.6`; `libssl.so.3` is also loaded indirectly. The build fails if it detects an old OpenSSL SONAME or an unresolved dependency. The integration test additionally checks the running broker's process maps.

## HTTP contract

```text
allow_anonymous false
global_plugin /opt/mosquitto-2.1.2/lib/auth-plug.so
plugin_opt_backends http
plugin_opt_http_ip 127.0.0.1
plugin_opt_http_port 8080
plugin_opt_http_getuser_uri /auth/user
plugin_opt_http_superuser_uri /auth/super
plugin_opt_http_aclcheck_uri /auth/acl
plugin_opt_http_retry_count 0
plugin_opt_auth_cacheseconds 0
plugin_opt_acl_cacheseconds 0
plugin_opt_log_quiet true
```

Set the URLs for your API. Requests use POST with `application/x-www-form-urlencoded`. Authentication sends username/password; ACL checks send username/topic/acc/clientid. As in upstream, the client ID is empty for user checks and the password is empty for superuser checks. If a superuser API requires a password and returns 403, the plugin continues with the ACL API. Subscribe access is represented by value 4. Existing pattern-ACL protections reject usernames or client IDs containing `+`, `#`, or `/`.

The HTTP-only build does not use the files backend's `acl_file` option. This example disables caches and additional retries so permission changes and API failures take effect immediately, at the cost of increased API traffic. Each HTTP request has a 10-second timeout and runs synchronously; load-test the expected connection and message volume. The backend suite tests Basic authentication and environment parameter injection (`http_*_params`), including rejection of malformed mappings and encoded parameters exceeding the 1024-byte buffer.

## Tests

Use Python 3.8 or later and run as a regular user. Tests launch a real Mosquitto process and a mock HTTP API on localhost using temporary paths and ports. They require no production API or credentials.

The suite covers 18 checks:

1. Reject anonymous, empty-credential, and incorrect-password connections.
2. Accept only HTTP 200; reject 204, 302, 403, and 500.
3. Authenticate and deliver allowed messages.
4. Block denied-topic messages.
5. Block messages on ACL API failures while keeping the broker alive.
6. Allow and deny subscriptions according to ACL results.
7. Reconnect with CleanSession and Keep Alive 0.
8. Apply publish permission revocation and recovery without cached grants.
9. Recheck read permissions after a subscription has been established.
10. Apply authentication revocation without cached grants.
11. Recover authentication after an API error.
12. Preserve username form encoding.
13. Reject wildcard identities during ACL checks.
14. Preserve password/client ID encoding and avoid following redirects.
15. Load the intended OpenSSL/curl libraries without `.so.10`.
16. Reject connections on HTTP timeout.
17. Reject connections when the API is unavailable.
18. Keep plaintext and encoded passwords out of broker logs.

API errors can result in a disconnect instead of a refusal CONNACK; the suite also checks broker liveness. `--artifacts-dir` preserves the broker log and, on success, `results.json`.

## CI

[Plugin backend compatibility](.github/workflows/http-plugin.yml) runs on pushes to `openssl3-http` and `master`, pull requests targeting those branches, and manual dispatch. GitHub displays the manual dispatch menu only when the workflow exists on the default branch; pushes to the working branch can still trigger it.

On Ubuntu 24.04, CI builds pinned SHA-256 source archives for OpenSSL 3.5.9, curl 8.22.0, and Mosquitto 2.1.2. It then builds and tests the plugin separately with GCC and Clang. Selected OpenSSL EVP, TLS, X.509, and verification tests also run. cJSON comes from the runner's operating-system development package.

The same job builds the remaining backends and a separate TLS-PSK variant, starts disposable MySQL 8.4, PostgreSQL 16 and MongoDB 7.0 services, and runs the [backend suite](BACKEND_TESTS.md). Redis, LDAP and Memcached fixtures start locally on temporary ports. Both compiler builds must pass the HTTP and backend suites.

Build logs, dependency information, and test results are retained for 14 days in the `http-plugin-evidence` artifact, including failure logs. CI does not deploy binaries. The workflow token has only `contents: read` permissions and does not require production secrets.

To reproduce the dependency build, install C/C++ compilers, Clang, CMake 3.18 or later, Perl, Python 3.8 or later, cJSON development headers, curl, and trusted CA certificates:

```bash
bash .ci/build-dependencies.sh "$PWD/build/deps"
CC=gcc bash build-http.sh "$PWD/build/deps/mosquitto" "$PWD/build/deps/openssl" "$PWD/build/deps/curl" "$PWD/build/gcc"
python3 tests/test_http_plugin.py \
  --broker "$PWD/build/deps/mosquitto/sbin/mosquitto" \
  --plugin "$PWD/build/gcc/auth-plug.so" \
  --openssl-prefix "$PWD/build/deps/openssl" \
  --curl-prefix "$PWD/build/deps/curl" \
  --artifacts-dir "$PWD/build/gcc/tests"
```

Passing tests does not establish the absence of all vulnerabilities, compatibility with untested backend configurations, or equivalence to a deployment-specific authentication policy. Upstream is archived, so dependency updates and regression testing are maintained in this fork.

## Decision log

- Purpose: retain HTTP form authentication while removing the old OpenSSL ABI dependency.
- Constraints: archived C plugin, older Mosquitto headers/callbacks, synchronous libcurl requests.
- Alternatives: install legacy libraries alongside current ones, migrate to another authentication product, or rebuild this HTTP backend.
- Decision: fix identified compatibility, memory, and encoding issues and build only the HTTP backend.
- Rationale: preserve the form API and verify actual library loading through integration tests.
- Tradeoffs: reproducible builds and removal of the old ABI, with ongoing fork maintenance and deployment load testing required.
- Invariants: permit only HTTP 200, deny authentication on failures, avoid logging passwords, and preserve license notices.
