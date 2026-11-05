"""Konfigurasi bersama KARTIKA-CDS & Diode Gateway.
Semua nilai dapat disesuaikan melalui environment variable.
"""
import os
from pathlib import Path

BASE = Path(os.environ.get("DIODE_HOME", Path(__file__).resolve().parent.parent))
DATA = Path(os.environ.get("DIODE_DATA", BASE / "data"))
LOW_DIR = DATA / "low"
HIGH_DIR = DATA / "high"
KEYS_DIR = Path(os.environ.get("DIODE_KEYS_DIR", BASE / "keys"))


def _int(name, default):
    return int(os.environ.get(name, default))


def _float(name, default):
    return float(os.environ.get(name, default))


# --- Jaringan & Kriptografi -----------------------------------------------
KEY_FILE = Path(os.environ.get("DIODE_KEY_FILE", BASE / "diode.key"))
PRIV_KEY_FILE = Path(os.environ.get("DIODE_PRIV_KEY", KEYS_DIR / "guard_ed25519.priv"))
PUB_KEY_FILE = Path(os.environ.get("DIODE_PUB_KEY", KEYS_DIR / "guard_ed25519.pub"))

RX_HOST = os.environ.get("DIODE_RX_HOST", "10.10.10.3")   # tujuan sender
RX_BIND = os.environ.get("DIODE_RX_BIND", "0.0.0.0")      # alamat dengar receiver
RX_PORT = _int("DIODE_RX_PORT", 9999)

# --- Batas dan parameter transfer -----------------------------------------
MAX_FILE_BYTES = _int("DIODE_MAX_FILE_BYTES", 10 * 1024 * 1024)
CHUNK_SIZE = 1024          # byte data per datagram (aman dari fragmentasi MTU)
FEC_GROUP = 4              # 4 data chunks + 2 parity chunks (RS(4,2) GF(256))
FEC_PARITY = 2             # jumlah shard paritas per grup (P0 XOR, P1 GF256)
PASSES = _int("DIODE_PASSES", 3)
PACE_S = _float("DIODE_PACE_S", 0.002)

TRANSFER_TIMEOUT_S = _int("DIODE_TRANSFER_TIMEOUT_S", 180)
IDLE_TIMEOUT_S = _int("DIODE_IDLE_TIMEOUT_S", 20)
MAX_CONCURRENT = _int("DIODE_MAX_CONCURRENT", 4)
REPLAY_WINDOW_S = _int("DIODE_REPLAY_WINDOW_S", 300)

# --- Kebijakan file (Mendukung Dokumen, Citra, Konfigurasi Radar & Firmware OT) ---
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".txt": "text/plain",
    ".cfg": "text/plain",
    ".bin": "application/octet-stream",
}

# Engine yang WAJIB aktif (Fail-Closed).
REQUIRED_ENGINES = {
    e.strip() for e in os.environ.get("DIODE_REQUIRE_ENGINES", "yara,clamav").split(",") if e.strip()
}


def load_key(mode: str = "auto") -> bytes:
    """Memuat kunci autentikasi paket.
    Jika pasangan kunci asimetris Ed25519 tersedia di keys/, gunakan Ed25519:
      - mode='sign' -> kembalikan b'ED25519_PRIV:' + 32B raw private key
      - mode='verify' -> kembalikan b'ED25519_PUB:' + 32B raw public key
    Jika tidak ada, fallback ke kunci simetris diode.key (minimal 32 byte).
    """
    if mode == "sign" and PRIV_KEY_FILE.exists():
        raw = PRIV_KEY_FILE.read_bytes().strip()
        if len(raw) == 64:
            raw = bytes.fromhex(raw.decode("ascii"))
        return b"ED25519_PRIV:" + raw[:32]
    if mode == "verify" and PUB_KEY_FILE.exists():
        raw = PUB_KEY_FILE.read_bytes().strip()
        if len(raw) == 64:
            raw = bytes.fromhex(raw.decode("ascii"))
        return b"ED25519_PUB:" + raw[:32]
    try:
        key = KEY_FILE.read_bytes()
    except FileNotFoundError:
        raise SystemExit(f"Kunci tidak ditemukan di {KEY_FILE}. Jalankan scripts/gen_key.sh dulu.")
    if len(key) < 32:
        raise SystemExit(f"Kunci di {KEY_FILE} terlalu pendek (minimal 32 byte).")
    return key
