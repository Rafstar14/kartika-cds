"""gen_key.py: Cross-platform key generator for KARTIKA-CDS.
Generates Ed25519 asymmetric keypair and HMAC symmetric key.
Works on Windows, Linux, and macOS without requiring bash.

Usage:
    python gen_key.py
"""
import os
import sys
from pathlib import Path

def main():
    base = Path(__file__).resolve().parent.parent
    os.chdir(base)

    keys_dir = base / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Symmetric HMAC key (fallback)
    hmac_key = base / "diode.key"
    if not hmac_key.exists():
        hmac_key.write_bytes(os.urandom(32))
        print("[+] diode.key dibuat (kunci simetris HMAC-SHA256).")
    else:
        print("[=] diode.key sudah ada, dilewati.")

    # Asymmetric Ed25519 keypair
    priv_path = keys_dir / "guard_ed25519.priv"
    pub_path = keys_dir / "guard_ed25519.pub"

    if not priv_path.exists():
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            print("[!] Modul 'cryptography' belum terinstal.")
            print("    Jalankan: pip install cryptography")
            sys.exit(1)

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        priv_path.write_bytes(priv_bytes)
        pub_path.write_bytes(pub_bytes)
        print(f"[+] Pasangan kunci Ed25519 dibuat:")
        print(f"    Private: {priv_path}")
        print(f"    Public : {pub_path}")
    else:
        print("[=] Kunci Ed25519 sudah ada, dilewati.")

    print("\n[OK] Semua kunci kriptografi siap digunakan.")


if __name__ == "__main__":
    main()
