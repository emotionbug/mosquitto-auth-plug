# Security

## Supported build

Security maintenance targets the versions listed in [README.md](README.md). The build scripts pin Mosquitto, OpenSSL, curl, cJSON, and MongoDB C Driver source archives and verify their SHA-256 digests. Runtime evidence rejects unresolved libraries, legacy OpenSSL SONAMEs such as `libcrypto.so.10`, and fallback to operating-system cJSON or MongoDB C Driver libraries.

## Enforced controls

- LDAP usernames are escaped according to RFC 4515 before filter substitution. Filter buffers account for every placeholder, failed binds close their connection, search results are released on every path, and a search error denies the request without terminating Mosquitto.
- Base64 decoding validates complete four-byte groups, padding and destination capacity before reading or writing. PBKDF2 records have bounded length, salt, derived-key size and iteration count; only SHA-1, SHA-256 and SHA-512 identifiers are accepted. Derived keys are compared with `CRYPTO_memcmp`.
- HTTP and JWT URLs and Host headers use length-derived allocations. libcurl strings, headers, handles and request bodies are released on all request failures.
- Redis substitutes identities through hiredis format arguments so spaces and percent signs cannot change command parsing. MongoDB validates BSON types before reading UTF-8 values.
- Database result pointers are checked before dereference. SQLite closes failed handles and rejects an unprepared query. CDB releases both its mapping and file descriptor.
- Plugin options, backend-owned strings, cache entries and backend handles are released at shutdown. Authentication and ACL cache keys use SHA-256 over length-prefixed fields.
- TLS-PSK values must be nonempty, even-length hexadecimal strings that fit in Mosquitto's destination buffer.

## Verification

`.ci/run-security-checks.sh` builds focused boundary tests with AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer, then runs cppcheck across all C files. `.ci/run-valgrind-http.sh` runs the complete HTTP suite and fails on definite leaks at broker shutdown. The integration suite adds hostile LDAP, Redis, HTTP, PBKDF2 and BSON inputs and checks that the broker remains alive. GCC and Clang builds exercise every backend documented in [BACKEND_TESTS.md](BACKEND_TESTS.md).

Run the local checks after building the pinned dependencies:

```bash
CC=clang bash .ci/run-security-checks.sh "$PWD/build/deps/openssl" "$PWD/build/security"
```

## Limits

These checks cover the source and dependency versions in the supported build. They do not prove that no vulnerability exists, assess production configuration or credentials, replace continuous fuzzing and load testing, or cover untested operating systems and library versions. cJSON utilities are excluded; Mosquitto uses the core parser only. Other backend client libraries supplied by Ubuntu remain subject to Ubuntu security updates. Re-run the workflow and review vendor advisories whenever a pinned dependency or operating-system package changes.

Report suspected vulnerabilities privately to the fork owner before publishing exploit details.
