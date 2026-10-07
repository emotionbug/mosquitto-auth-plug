#!/usr/bin/env python3
"""Check password formats with only the selected OpenSSL library loaded."""
import argparse
import base64
import ctypes
import os
import pathlib
import subprocess

PASSWORD = "local-only-password"


def password_hash(password=PASSWORD, digest="sha256", raw=False, django=False):
    import hashlib
    salt = b"fixture-salt"
    text_salt = base64.b64encode(salt).decode() if raw else salt.decode()
    key = hashlib.pbkdf2_hmac(digest, password.encode(), salt, 1000)
    prefix = "pbkdf2_" if django else "PBKDF2$"
    return f"{prefix}{digest}$1000${text_salt}${base64.b64encode(key).decode()}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True, type=pathlib.Path)
    parser.add_argument("--openssl-prefix", required=True, type=pathlib.Path)
    args = parser.parse_args()
    def hashes():
        for variant in ("default", "raw-salt", "django"):
            lib = ctypes.CDLL(str(args.build / f"hash-{variant}.so"))
            maps = pathlib.Path(f"/proc/{os.getpid()}/maps").read_text()
            assert str(args.openssl_prefix.resolve() / "lib/libcrypto.so.3") in maps
            lib.pbkdf2_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            for digest in ("sha1", "sha256", "sha512"):
                hashed = password_hash(digest=digest, raw=variant == "raw-salt", django=variant == "django").encode()
                assert lib.pbkdf2_check(PASSWORD.encode(), hashed) == 1, (variant, digest)
                assert lib.pbkdf2_check(b"wrong", hashed) == 0
            for malformed in (
                b"", b"PBKDF2$sha256", b"PBKDF2$md5$1000$salt$AAAA",
                b"PBKDF2$sha256$0$salt$AAAA", b"PBKDF2$sha256$-1$salt$AAAA",
                b"PBKDF2$sha256$10000001$salt$AAAA", b"PBKDF2$sha256$12x$salt$AAAA",
                b"PBKDF2$sha256$1000$salt$A", b"PBKDF2$sha256$1000$salt$AAAA$trailing",
            ):
                assert lib.pbkdf2_check(PASSWORD.encode(), malformed) == 0
        lib = ctypes.CDLL(str(args.build / "hash-default.so"))
        hashed = subprocess.check_output([str(args.build / "np"), "-p", PASSWORD, "-i", "1000"]).strip()
        assert lib.pbkdf2_check(PASSWORD.encode(), hashed) == 1
        lib.t_expand.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        libc = ctypes.CDLL(None)
        libc.free.argtypes = [ctypes.c_void_p]
        for client, user, expected in [(b"device", b"alice", b"device/alice/%x"), (None, None, b"//%x")]:
            result = ctypes.c_void_p()
            lib.t_expand(client, user, b"%c/%u/%x", ctypes.byref(result))
            assert ctypes.string_at(result) == expected
            libc.free(result)
    hashes()


if __name__ == "__main__":
    main()
