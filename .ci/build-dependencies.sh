#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 BUILD_ROOT" >&2
  exit 2
fi
build_root=$(realpath -m "$1")
mkdir -p "$build_root"
cd "$build_root"
exec > >(tee "$build_root/build.log") 2>&1
jobs=${BUILD_JOBS:-2}

# Use the documented dependency versions and verify pinned archive hashes.
curl -fL --retry 3 https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz -o openssl-3.5.9.tar.gz
curl -fL --retry 3 https://github.com/curl/curl/releases/download/curl-8_22_0/curl-8.22.0.tar.gz -o curl-8.22.0.tar.gz
curl -fL --retry 3 https://mosquitto.org/files/source/mosquitto-2.1.2.tar.gz -o mosquitto-2.1.2.tar.gz
sha256sum -c <<'CHECKSUMS'
603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  openssl-3.5.9.tar.gz
d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1  curl-8.22.0.tar.gz
fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02  mosquitto-2.1.2.tar.gz
CHECKSUMS

tar -xzf openssl-3.5.9.tar.gz
(
  cd openssl-3.5.9
  ./Configure --prefix="$build_root/openssl" --openssldir="$build_root/openssl/ssl" \
    --libdir=lib shared -Wl,-rpath,"$build_root/openssl/lib"
  make -j"$jobs"
  make test TESTS='test_evp test_sslapi test_x509 test_verify'
  make install_sw
)

tar -xzf curl-8.22.0.tar.gz
(
  cd curl-8.22.0
  LDFLAGS="-Wl,-rpath,$build_root/openssl/lib" ./configure \
    --prefix="$build_root/curl" --libdir="$build_root/curl/lib" \
    --with-openssl="$build_root/openssl" --enable-shared --disable-static \
    --without-libpsl --without-libidn2 --without-zlib --without-brotli --without-zstd \
    --without-nghttp2 --without-nghttp3 --without-libssh2 \
    --disable-ldap --disable-ldaps --disable-docs --disable-manual
  make -j"$jobs"
  make install
)

tar -xzf mosquitto-2.1.2.tar.gz
cmake -S mosquitto-2.1.2 -B mosquitto-build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$build_root/mosquitto" \
  -DCMAKE_INSTALL_LIBDIR=lib -DOPENSSL_ROOT_DIR="$build_root/openssl" \
  "-DCMAKE_INSTALL_RPATH=$build_root/mosquitto/lib;$build_root/openssl/lib" \
  -DWITH_TLS=ON -DWITH_WEBSOCKETS=OFF -DWITH_APPS=OFF -DWITH_CTRL_SHELL=OFF \
  -DWITH_PLUGINS=OFF -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DWITH_LTO=OFF
cmake --build mosquitto-build --parallel "$jobs"
cmake --install mosquitto-build
"$build_root/openssl/bin/openssl" version -a
"$build_root/curl/bin/curl" --version
"$build_root/mosquitto/sbin/mosquitto" -h
