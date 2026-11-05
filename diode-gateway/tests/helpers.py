import hashlib
import random
import struct
import zlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEY = b"k" * 32

_priv = Ed25519PrivateKey.generate()
_pub = _priv.public_key()
ED_PRIV_KEY = b"ED25519_PRIV:" + _priv.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
ED_PUB_KEY = b"ED25519_PUB:" + _pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def make_png(extra=b""):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = zlib.compress(b"\x00\xff\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", raw)
        + chunk(b"IEND", b"")
        + extra
    )


def make_pdf(body=b""):
    return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


def make_firmware(major=2, minor=5, payload=b"RADAR_DSP_IMAGE_OK" * 20):
    hdr = struct.pack(">4sHHI", b"KRTK", major, minor, len(payload))
    body = hdr + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(">I", crc)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rand_bytes(n, seed=1):
    return random.Random(seed).randbytes(n)
