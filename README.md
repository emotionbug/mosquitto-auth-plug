# mosquitto-auth-plug

Forked from [jpmens/mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

## Supported versions

| Component | Version |
| --- | --- |
| Mosquitto | 2.1.2 |
| OpenSSL | 3.5.9 |
| curl / libcurl | 8.22.0 |
| cJSON | 1.7.19, utilities disabled |
| MongoDB C Driver | 1.30.12 |
| Platform | Linux x86-64 |
| Authentication backends | [Tested backend matrix](BACKEND_TESTS.md) |

Compatibility is tested with the versions above. See the backend matrix for tested features and limitations; older Mosquitto versions have not been verified.

See [COMPATIBILITY.md](COMPATIBILITY.md) for build, configuration, and test instructions.

[GitHub Actions](https://github.com/emotionbug/mosquitto-auth-plug/actions/workflows/http-plugin.yml) builds with GCC and Clang, runs AddressSanitizer/UndefinedBehaviorSanitizer, cppcheck and a Valgrind broker-shutdown check, and exercises authentication and ACL behavior against a real broker and backend services. See [SECURITY.md](SECURITY.md) for the security controls and remaining limits.

## License

See [LICENSE.txt](LICENSE.txt) for the BSD license and third-party notices.
