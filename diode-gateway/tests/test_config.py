from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from common import config
from common import protocol as P


def test_load_key_raw_32_bytes_with_whitespace(tmp_path, monkeypatch):
    """Pastikan 32-byte raw bytes yang diawali atau diakhiri byte whitespace ASCII
    tidak terpangkas oleh .strip().
    """
    priv_file = tmp_path / "guard_ed25519.priv"
    pub_file = tmp_path / "guard_ed25519.pub"

    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)
    monkeypatch.setattr(config, "PUB_KEY_FILE", pub_file)

    # Buat kunci dengan byte whitespace di ujung-ujungnya (0x0A = newline, 0x20 = space)
    # Byte 0 = 0x0A, byte 31 = 0x20
    # Dalam implementasi lama, .strip() memangkas ini menjadi 30 bytes!
    raw_priv = b"\n" + b"X" * 30 + b" "
    assert len(raw_priv) == 32
    assert len(raw_priv.strip()) == 30

    # Buat public key yang valid atau raw 32 byte dengan whitespace
    raw_pub = b"\t" + b"Y" * 30 + b"\r"
    assert len(raw_pub) == 32
    assert len(raw_pub.strip()) == 30

    priv_file.write_bytes(raw_priv)
    pub_file.write_bytes(raw_pub)

    loaded_priv = config.load_key("sign")
    loaded_pub = config.load_key("verify")

    assert loaded_priv == b"ED25519_PRIV:" + raw_priv
    assert len(loaded_priv) == 13 + 32
    assert loaded_pub == b"ED25519_PUB:" + raw_pub
    assert len(loaded_pub) == 12 + 32


def test_load_key_functional_ed25519_with_whitespace_bytes(tmp_path, monkeypatch):
    """Cari/buat kunci Ed25519 acak yang memiliki byte whitespace di ujung,
    dan uji end-to-end penandatanganan dan verifikasi paket.
    """
    priv_file = tmp_path / "guard_ed25519.priv"
    pub_file = tmp_path / "guard_ed25519.pub"

    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)
    monkeypatch.setattr(config, "PUB_KEY_FILE", pub_file)

    # Buat seed 32-byte spesifik yang berujung byte whitespace
    # Ed25519 seed dapat berupa sembarang 32 bytes
    seed = b"\x20" + b"\x01" * 30 + b"\x0a"
    priv = Ed25519PrivateKey.from_private_bytes(seed)
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
    assert priv_bytes == seed
    assert priv_bytes[0] == 0x20 and priv_bytes[-1] == 0x0A

    priv_file.write_bytes(priv_bytes)
    pub_file.write_bytes(pub_bytes)

    k_priv = config.load_key("sign")
    k_pub = config.load_key("verify")

    # Pastikan tidak crash dengan ValueError: An Ed25519 private key is 32 bytes long
    pkt = P.pack(P.T_DATA, b"\x01" * 16, P.build_chunk(1, b"test-payload"), k_priv)
    ptype, fid, body = P.unpack(pkt, k_pub)
    assert ptype == P.T_DATA
    assert fid == b"\x01" * 16
    assert P.parse_chunk(body) == (1, b"test-payload")


def test_load_key_hex_formats(tmp_path, monkeypatch):
    """Pastikan kunci dalam format hex (64 karakter) dengan atau tanpa newline/CRLF
    tetap terbaca dan ter-parse dengan benar.
    """
    priv_file = tmp_path / "guard_ed25519.priv"
    pub_file = tmp_path / "guard_ed25519.pub"

    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)
    monkeypatch.setattr(config, "PUB_KEY_FILE", pub_file)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 1. Hex 64 karakter tanpa newline
    priv_file.write_text(priv_raw.hex(), encoding="ascii")
    pub_file.write_text(pub_raw.hex(), encoding="ascii")
    assert config.load_key("sign") == b"ED25519_PRIV:" + priv_raw
    assert config.load_key("verify") == b"ED25519_PUB:" + pub_raw

    # 2. Hex 64 karakter dengan newline '\n'
    priv_file.write_bytes(priv_raw.hex().encode("ascii") + b"\n")
    pub_file.write_bytes(pub_raw.hex().encode("ascii") + b"\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + priv_raw
    assert config.load_key("verify") == b"ED25519_PUB:" + pub_raw

    # 3. Hex 64 karakter dengan '\r\n' dan leading whitespace
    priv_file.write_bytes(b"  " + priv_raw.hex().encode("ascii") + b"\r\n")
    pub_file.write_bytes(b"\t" + pub_raw.hex().encode("ascii") + b"\r\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + priv_raw
    assert config.load_key("verify") == b"ED25519_PUB:" + pub_raw

    # 4. Hex dengan UTF-8 BOM (\xef\xbb\xbf)
    priv_file.write_bytes(b"\xef\xbb\xbf" + priv_raw.hex().encode("ascii") + b"\r\n")
    pub_file.write_bytes(b"\xef\xbb\xbf" + pub_raw.hex().encode("ascii") + b"\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + priv_raw
    assert config.load_key("verify") == b"ED25519_PUB:" + pub_raw

    # 5. Hex terformat dengan spasi antar byte
    spaced_priv = " ".join([priv_raw.hex()[i:i+2] for i in range(0, 64, 2)]).encode("ascii")
    spaced_pub = " ".join([pub_raw.hex()[i:i+2] for i in range(0, 64, 2)]).encode("ascii")
    priv_file.write_bytes(spaced_priv + b"\n")
    pub_file.write_bytes(spaced_pub + b"\r\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + priv_raw
    assert config.load_key("verify") == b"ED25519_PUB:" + pub_raw


def test_load_key_raw_32_bytes_with_editor_newline(tmp_path, monkeypatch):
    """Jika editor menambahkan newline di akhir file 32-byte binary,
    dan byte ujung adalah whitespace, byte ujung tidak boleh ikut hilang.
    """
    priv_file = tmp_path / "guard_ed25519.priv"
    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)

    raw_32 = b"\x20" + b"\x10" * 30 + b"\x0d"  # byte 0 = space, byte 31 = \r

    # \n (33 byte)
    priv_file.write_bytes(raw_32 + b"\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + raw_32

    # \r (33 byte)
    priv_file.write_bytes(raw_32 + b"\r")
    assert config.load_key("sign") == b"ED25519_PRIV:" + raw_32

    # \r\n (34 byte)
    priv_file.write_bytes(raw_32 + b"\r\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + raw_32

    # \n\n (34 byte)
    priv_file.write_bytes(raw_32 + b"\n\n")
    assert config.load_key("sign") == b"ED25519_PRIV:" + raw_32

    # UTF-8 BOM prefix (35 byte)
    priv_file.write_bytes(b"\xef\xbb\xbf" + raw_32)
    assert config.load_key("sign") == b"ED25519_PRIV:" + raw_32


def test_load_key_fallback_to_symmetric(tmp_path, monkeypatch):
    """Jika mode='auto' atau file asimetris tidak ada, fallback ke diode.key."""
    priv_file = tmp_path / "nonexistent.priv"
    pub_file = tmp_path / "nonexistent.pub"
    key_file = tmp_path / "diode.key"

    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)
    monkeypatch.setattr(config, "PUB_KEY_FILE", pub_file)
    monkeypatch.setattr(config, "KEY_FILE", key_file)

    hmac_key = b"H" * 32
    key_file.write_bytes(hmac_key)

    assert config.load_key("auto") == hmac_key
    assert config.load_key("sign") == hmac_key
    assert config.load_key("verify") == hmac_key


def test_load_key_symmetric_file_too_short(tmp_path, monkeypatch):
    """diode.key harus minimal 32 byte."""
    priv_file = tmp_path / "nonexistent.priv"
    key_file = tmp_path / "diode.key"

    monkeypatch.setattr(config, "PRIV_KEY_FILE", priv_file)
    monkeypatch.setattr(config, "KEY_FILE", key_file)

    key_file.write_bytes(b"short")
    with pytest.raises(SystemExit) as exc_info:
        config.load_key("auto")
    assert "terlalu pendek" in str(exc_info.value)
