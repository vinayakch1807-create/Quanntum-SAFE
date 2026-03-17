from __future__ import annotations

import argparse
import sys
from pathlib import Path

import lockbox_crypto


def _cmd_init(args: argparse.Namespace) -> int:
    lockbox_crypto.initialize_master_key(
        args.phrase,
        kem_algorithm=args.kem,
        kem_backend=args.backend,
        overwrite=args.overwrite,
    )
    print("Master key initialized.")
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    ciphertext = lockbox_crypto.encrypt_text_with_master_phrase(args.phrase, args.text)
    if args.out:
        Path(args.out).write_text(ciphertext, encoding="utf-8")
    else:
        print(ciphertext)
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    if args.ciphertext_file:
        ciphertext = Path(args.ciphertext_file).read_text(encoding="utf-8")
    else:
        ciphertext = args.ciphertext
    plaintext = lockbox_crypto.decrypt_text_with_master_phrase(args.phrase, ciphertext)
    print(plaintext)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="Quantum-Safe Digital Lockbox")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create or overwrite the local master key")
    p_init.add_argument("--phrase", required=True)
    p_init.add_argument("--kem", default="Kyber768")
    p_init.add_argument("--backend", choices=["oqs", "pqcrypto"])
    p_init.add_argument("--overwrite", action="store_true")
    p_init.set_defaults(func=_cmd_init)

    p_encrypt = sub.add_parser("encrypt", help="Encrypt text into a PQC payload")
    p_encrypt.add_argument("--phrase", required=True)
    p_encrypt.add_argument("--text", required=True)
    p_encrypt.add_argument("--out")
    p_encrypt.set_defaults(func=_cmd_encrypt)

    p_decrypt = sub.add_parser("decrypt", help="Decrypt a PQC payload back to plaintext")
    p_decrypt.add_argument("--phrase", required=True)
    cipher_group = p_decrypt.add_mutually_exclusive_group(required=True)
    cipher_group.add_argument("--ciphertext")
    cipher_group.add_argument("--ciphertext-file")
    p_decrypt.set_defaults(func=_cmd_decrypt)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
