# mosquitto-auth-plug

Forked from [jpmens/mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

## Supported versions

| Component | Version |
| --- | --- |
| Mosquitto | 2.1.2 |
| OpenSSL | 3.5.9 |
| curl / libcurl | 8.22.0 |
| Platform | Linux x86-64 |
| Authentication backends | [Tested backend matrix](BACKEND_TESTS.md) |

Compatibility is tested with the versions above. See the backend matrix for tested features and limitations; older Mosquitto versions have not been verified.

See [COMPATIBILITY.md](COMPATIBILITY.md) for build, configuration, and test instructions.

[GitHub Actions](https://github.com/emotionbug/mosquitto-auth-plug/actions/workflows/http-plugin.yml) builds with GCC and Clang and runs authentication and ACL regression tests against a real broker and backend services.

## License

See [LICENSE.txt](LICENSE.txt) for the BSD license and third-party notices.
