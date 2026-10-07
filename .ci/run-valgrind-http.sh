#!/usr/bin/env bash
set -euo pipefail

BROKER=${1:?usage: run-valgrind-http.sh BROKER PLUGIN OPENSSL_PREFIX CURL_PREFIX CJSON_PREFIX OUTPUT_DIR}
PLUGIN=${2:?}
OPENSSL_PREFIX=${3:?}
CURL_PREFIX=${4:?}
CJSON_PREFIX=${5:?}
OUTPUT_DIR=${6:?}

mkdir -p "$OUTPUT_DIR"
export VALGRIND_BROKER="$BROKER"
cat > "$OUTPUT_DIR/mosquitto-valgrind" <<'WRAPPER'
#!/usr/bin/env bash
exec valgrind --quiet --leak-check=full --show-leak-kinds=definite \
  --errors-for-leak-kinds=definite --error-exitcode=99 \
  "$VALGRIND_BROKER" "$@"
WRAPPER
chmod 700 "$OUTPUT_DIR/mosquitto-valgrind"

python3 tests/test_http_plugin.py \
  --broker "$OUTPUT_DIR/mosquitto-valgrind" \
  --plugin "$PLUGIN" \
  --openssl-prefix "$OPENSSL_PREFIX" \
  --curl-prefix "$CURL_PREFIX" \
  --cjson-prefix "$CJSON_PREFIX" \
  --artifacts-dir "$OUTPUT_DIR/tests"
