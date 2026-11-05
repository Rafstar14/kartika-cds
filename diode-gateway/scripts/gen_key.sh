#!/usr/bin/env bash
# Membuat pasangan kunci Asimetris Ed25519 (keys/guard_ed25519.priv & .pub)
# SERTA kunci simetris cadangan (diode.key) untuk kompatibilitas penuh.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p keys
if [ ! -e diode.key ]; then
  head -c 32 /dev/urandom > diode.key
  echo "diode.key dibuat (izin 600)."
fi
if [ ! -e keys/guard_ed25519.priv ]; then
  python3 - <<'PY'
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
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
Path("keys/guard_ed25519.priv").write_bytes(priv_bytes)
Path("keys/guard_ed25519.pub").write_bytes(pub_bytes)
PY
  chmod 600 keys/guard_ed25519.priv
  chmod 644 keys/guard_ed25519.pub
  echo "Pasangan kunci Asimetris Ed25519 dibuat di keys/ (guard_ed25519.priv & guard_ed25519.pub)."
fi
