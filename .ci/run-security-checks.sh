#!/usr/bin/env bash
set -euo pipefail

OPENSSL_PREFIX=${1:?usage: run-security-checks.sh OPENSSL_PREFIX [OUTPUT_DIR]}
OUTPUT_DIR=${2:-build/security}
CC=${CC:-clang}

mkdir -p "$OUTPUT_DIR"

"$CC" -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer -g \
  -I"$OPENSSL_PREFIX/include" \
  tests/test_security.c base64.c pbkdf2-check.c hash.c \
  -L"$OPENSSL_PREFIX/lib" -Wl,-rpath,"$OPENSSL_PREFIX/lib" -lcrypto \
  -o "$OUTPUT_DIR/test-security"

ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$OUTPUT_DIR/test-security"

cppcheck --enable=warning,performance,portability --error-exitcode=1 \
  --suppress=invalidPrintfArgType_sint --suppress=uninitvar \
  --std=c11 --force --quiet ./*.c
