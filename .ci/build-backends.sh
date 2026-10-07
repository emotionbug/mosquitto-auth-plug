#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 DEPENDENCY_PREFIX OUTPUT_DIR" >&2
  exit 2
fi
deps=$(realpath "$1")
out=$(realpath -m "$2")
cd "$(dirname "$0")/.."
mkdir -p "$out/tinycdb"
cp -r contrib/tinycdb-0.78/. "$out/tinycdb/"
make -C "$out/tinycdb" CC="${CC:-cc}" CFLAGS='-O2 -fPIC' libcdb.a cdb
includes=(-I"$deps/mosquitto/include" -I"$deps/openssl/include" -I"$deps/curl/include"
  -I"$deps/cjson/include" -I"$out/tinycdb")
libs=(-L"$deps/mosquitto/lib" -L"$deps/openssl/lib" -L"$deps/curl/lib"
  -Wl,-rpath,"$deps/mosquitto/lib:$deps/openssl/lib:$deps/curl/lib:$deps/cjson/lib:$deps/mongo/lib" -lmosquitto -lcrypto -lcurl
  -Wl,--no-as-needed -lssl -Wl,--as-needed)
common=(auth-plug.c base64.c pbkdf2-check.c log.c envs.c hash.c cache.c backends.c)
crypto=(-L"$deps/openssl/lib" -Wl,-rpath,"$deps/openssl/lib" -lcrypto)
export PKG_CONFIG_PATH="$deps/mongo/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
packages=(sqlite3 hiredis libmariadb libpq libmongoc-1.0 libbson-1.0 libmemcached)
read -r -a package_flags <<< "$(pkg-config --cflags --libs "${packages[@]}")"
backends=(cdb files http jwt ldap mongo mysql postgres redis sqlite memcached)
flags=()
sources=()
for backend in "${backends[@]}"; do
  flags+=("-DBE_${backend^^}")
  sources+=("be-$backend.c")
done
"${CC:-cc}" -std=gnu99 -fPIC -shared -O2 -Wall -DLDAP_DEPRECATED=1 \
  "${includes[@]}" "${flags[@]}" "${common[@]}" "${sources[@]}" \
  "${package_flags[@]}" "$out/tinycdb/libcdb.a" -lldap -llber "${libs[@]}" -o "$out/auth-plug.so"
"${CC:-cc}" -std=gnu99 -fPIC -shared -O2 -Wall -DBE_SQLITE -DBE_PSK \
  "${includes[@]}" "${common[@]}" be-sqlite.c -lsqlite3 "${libs[@]}" -o "$out/auth-psk.so"
"${CC:-cc}" -std=gnu99 -O2 "${includes[@]}" np.c base64.c "${crypto[@]}" -o "$out/np"
for variant in default raw-salt django; do
  extra=()
  [[ $variant != raw-salt ]] || extra+=(-DRAW_SALT)
  [[ $variant != django ]] || extra+=(-DSUPPORT_DJANGO_HASHERS)
  "${CC:-cc}" -std=gnu99 -fPIC -shared -O2 "${extra[@]}" "${includes[@]}" \
    pbkdf2-check.c base64.c backends.c "${crypto[@]}" -o "$out/hash-$variant.so"
done
for plugin in "$out"/*.so; do
  ldd "$plugin" > "$plugin.ldd.txt"
  if grep -Eq 'lib(crypto|ssl)\.so\.(10|1[.]|0[.])|not found' "$plugin.ldd.txt"; then
    cat "$plugin.ldd.txt" >&2
    exit 1
  fi
  if grep -Eq 'lib(cjson|mongoc-1[.]0|bson-1[.]0)\.so[^ ]* => /(usr/)?lib/' "$plugin.ldd.txt"; then
    echo "A system cJSON or Mongo C Driver library was selected." >&2
    cat "$plugin.ldd.txt" >&2
    exit 1
  fi
done
