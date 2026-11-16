#!/usr/bin/env python3
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: decrypt-aegis-operator.py <wrap-key> <encrypted-blob> <output>", file=sys.stderr)
        return 2

    wrap_key = Path(sys.argv[1]).read_bytes()
    blob = Path(sys.argv[2]).read_bytes()
    if len(wrap_key) != 32 or len(blob) < 28:
        print("invalid input length", file=sys.stderr)
        return 1

    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    operator_key = AESGCM(wrap_key).decrypt(nonce, ciphertext + tag, None)
    Path(sys.argv[3]).write_bytes(operator_key)
    print(f"decrypted operator key: {len(operator_key)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
