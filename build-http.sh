#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 MOSQUITTO_PREFIX OPENSSL_PREFIX CURL_PREFIX OUTPUT_DIR" >&2
  exit 2
fi
mosquitto_prefix=$(realpath "$1")
openssl_prefix=$(realpath "$2")
curl_prefix=$(realpath "$3")
output_dir=$(realpath -m "$4")
source_dir=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$output_dir"
cd "$source_dir"

# Build only the HTTP backend without the legacy Makefile defaults.
"${CC:-cc}" -std=gnu99 -fPIC -shared -O2 -Wall -DBE_HTTP \
  -I"$mosquitto_prefix/include" -I"$openssl_prefix/include" -I"$curl_prefix/include" \
  auth-plug.c base64.c pbkdf2-check.c log.c envs.c hash.c cache.c be-http.c \
  -L"$mosquitto_prefix/lib" -L"$openssl_prefix/lib" -L"$curl_prefix/lib" \
  -Wl,-rpath,"$mosquitto_prefix/lib:$openssl_prefix/lib:$curl_prefix/lib" \
  -lmosquitto -lcrypto -lcurl -o "$output_dir/auth-plug.so"

cp LICENSE.txt "$output_dir/LICENSE.mosquitto-auth-plug.txt"
readelf -d "$output_dir/auth-plug.so" > "$output_dir/dynamic.txt"
ldd "$output_dir/auth-plug.so" > "$output_dir/ldd.txt"
ldd "$mosquitto_prefix/lib/libmosquitto.so.1" > "$output_dir/mosquitto-ldd.txt"
if grep -Eq 'lib(crypto|ssl)\.so\.(10|1[.]|0[.])|not found' \
    "$output_dir/ldd.txt" "$output_dir/mosquitto-ldd.txt" || \
    grep -Eq 'libcjson\.so[^ ]* => /(usr/)?lib/' "$output_dir/mosquitto-ldd.txt"; then
  echo "A legacy TLS library, system cJSON, or unresolved dependency remains." >&2
  cat "$output_dir/ldd.txt" "$output_dir/mosquitto-ldd.txt" >&2
  exit 1
fi
sha256sum "$output_dir/auth-plug.so" > "$output_dir/auth-plug.so.sha256"
sha256sum auth-plug.c be-http.c cache.c log.c userdata.h > "$output_dir/source-files.sha256"
printf 'source_dir=%s\n' "$source_dir" > "$output_dir/build-info.txt"
"${CC:-cc}" --version >> "$output_dir/build-info.txt"
"$openssl_prefix/bin/openssl" version -a >> "$output_dir/build-info.txt"
"$curl_prefix/bin/curl" --version >> "$output_dir/build-info.txt"
printf 'Built: %s/auth-plug.so\n' "$output_dir"
