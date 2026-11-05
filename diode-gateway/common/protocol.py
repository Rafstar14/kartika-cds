"""Format paket UDP satu arah dengan dukungan:
1. Kriptografi Asimetris Ed25519 (64B signature) ATAU HMAC-SHA256 (32B tag).
2. True Galois Field GF(2^8) Reed-Solomon / Vandermonde Erasure Coding RS(4, 2):
   - Mampu memulihkan 1 paket hilang (via XOR P0) maupun 2 paket hilang sekaligus
     dalam grup yang sama (via Gauss-Jordan GF(256) matriks P0 + P1) tanpa ACK!
"""
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

MAGIC = b"DIOD"
VERSION = 1
T_HEADER, T_DATA, T_PARITY, T_EOF = 1, 2, 3, 4

# Flag bit tinggi pada byte versi menandakan tanda tangan asimetris Ed25519 (64 byte)
FLAG_ED25519 = 0x80

_PRE = struct.Struct(">4sBB16s")
PRE_LEN = _PRE.size            # 22 byte
HMAC_LEN = 32
ED25519_LEN = 64
MAX_DATAGRAM = 1450
MAX_NAME_BYTES = 200

_HDR = struct.Struct(">QIHQH32sH")   # size, n_chunks, chunk_size, ts, fec_group, sha256, name_len
_CHUNK = struct.Struct(">IH")        # index (atau kode grup paritas), panjang payload


class ProtocolError(Exception):
    pass


# --- Tabel Galois Field GF(2^8) dengan polinomial primitif 0x11d -----------
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]

# Tabel perkalian cepat GF(256) untuk faktor skalar
_GF_MUL_TABLE = [[0] * 256 for _ in range(256)]
for _a in range(1, 256):
    for _b in range(1, 256):
        _GF_MUL_TABLE[_a][_b] = _GF_EXP[_GF_LOG[_a] + _GF_LOG[_b]]


def gf_mul(a: int, b: int) -> int:
    return _GF_MUL_TABLE[a][b]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return _GF_EXP[255 - _GF_LOG[a]]


def gf_scale_bytes(data: bytes, factor: int) -> bytes:
    if factor == 0:
        return bytes(len(data))
    if factor == 1:
        return data
    tbl = _GF_MUL_TABLE[factor]
    return bytes(tbl[b] for b in data)


def xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def rs_encode_group(padded_chunks: list[bytes]) -> tuple[bytes, bytes]:
    """Menghasilkan 2 shard paritas (P0, P1) untuk hingga 4 data chunks:
    - P0 = D0 ^ D1 ^ D2 ^ D3 (Koefisien [1, 1, 1, 1])
    - P1 = 1*D0 ^ 2*D1 ^ 4*D2 ^ 8*D3 dalam GF(256) (Koefisien [1, 2, 4, 8])
    """
    cs = len(padded_chunks[0])
    p0 = bytes(cs)
    p1 = bytes(cs)
    coeffs_p1 = (1, 2, 4, 8)
    for idx, ch in enumerate(padded_chunks):
        p0 = xor(p0, ch)
        p1 = xor(p1, gf_scale_bytes(ch, coeffs_p1[idx]))
    return p0, p1


def rs_recover_group(k_len: int, cs: int, have_data: dict[int, bytes], p0: bytes = None, p1: bytes = None) -> dict[int, bytes]:
    """Memulihkan hingga 2 data chunk yang hilang dalam satu grup berukuran k_len (<=4).
    Mengembalikan dictionary {local_idx: recovered_padded_bytes}.
    """
    missing = [i for i in range(k_len) if i not in have_data]
    if not missing:
        return {}
    # Kasus 1: Hanya 1 chunk hilang dan P0 tersedia -> XOR cepat
    if len(missing) == 1 and p0 is not None:
        m = missing[0]
        acc = p0
        for i, ch in have_data.items():
            acc = xor(acc, ch)
        return {m: acc}
    # Kasus 2: 1 chunk hilang tapi hanya P1 yang tersedia -> selesaikan persamaan linear GF(256)
    coeffs_p1 = (1, 2, 4, 8)
    if len(missing) == 1 and p1 is not None:
        m = missing[0]
        acc = p1
        for i, ch in have_data.items():
            acc = xor(acc, gf_scale_bytes(ch, coeffs_p1[i]))
        return {m: gf_scale_bytes(acc, gf_inv(coeffs_p1[m]))}
    # Kasus 3: 2 chunk hilang (m0, m1) dan KEDUA P0 serta P1 tersedia -> eliminasi 2x2 di GF(256)!
    if len(missing) == 2 and p0 is not None and p1 is not None:
        m0, m1 = missing[0], missing[1]
        # D_m0 ^ D_m1 = P0 ^ sum_{known}(D_i) = S0
        s0 = p0
        # c0*D_m0 ^ c1*D_m1 = P1 ^ sum_{known}(c_i * D_i) = S1
        s1 = p1
        for i, ch in have_data.items():
            s0 = xor(s0, ch)
            s1 = xor(s1, gf_scale_bytes(ch, coeffs_p1[i]))
        c0, c1 = coeffs_p1[m0], coeffs_p1[m1]
        # Substitusi D_m0 = S0 ^ D_m1 ke persamaan kedua:
        # (c0 ^ c1) * D_m1 = S1 ^ (c0 * S0)
        denom = gf_inv(c0 ^ c1)
        rhs = xor(s1, gf_scale_bytes(s0, c0))
        d_m1 = gf_scale_bytes(rhs, denom)
        d_m0 = xor(s0, d_m1)
        return {m0: d_m0, m1: d_m1}
    return {}


# --- Helper Kriptografi (Ed25519 & HMAC-SHA256) ---------------------------
def _parse_key(key: bytes):
    """Mendeteksi apakah key adalah Ed25519 atau HMAC simetris."""
    if key.startswith(b"ED25519_PRIV:"):
        seed = key[len(b"ED25519_PRIV:"):]
        return "ed25519_priv", Ed25519PrivateKey.from_private_bytes(seed)
    if key.startswith(b"ED25519_PUB:"):
        pub = key[len(b"ED25519_PUB:"):]
        return "ed25519_pub", Ed25519PublicKey.from_public_bytes(pub)
    return "hmac", key


def pack(ptype: int, file_id: bytes, body: bytes, key: bytes) -> bytes:
    ktype, kobj = _parse_key(key)
    if ktype == "ed25519_priv":
        pre = _PRE.pack(MAGIC, VERSION | FLAG_ED25519, ptype, file_id)
        sig = kobj.sign(pre + body)
        return pre + body + sig
    elif ktype == "ed25519_pub":
        raise ProtocolError("tidak bisa menandatangani paket menggunakan public key")
    else:
        pre = _PRE.pack(MAGIC, VERSION, ptype, file_id)
        tag = hmac.new(kobj, pre + body, hashlib.sha256).digest()
        return pre + body + tag


def unpack(data: bytes, key: bytes):
    if len(data) < PRE_LEN + HMAC_LEN or len(data) > MAX_DATAGRAM:
        raise ProtocolError("ukuran datagram tidak valid")
    magic, ver_flag, ptype, fid = _PRE.unpack(data[:PRE_LEN])
    is_ed = bool(ver_flag & FLAG_ED25519)
    ver = ver_flag & 0x7F
    if magic != MAGIC or ver != VERSION or ptype not in (T_HEADER, T_DATA, T_PARITY, T_EOF):
        raise ProtocolError("magic/versi/tipe tidak dikenal")

    ktype, kobj = _parse_key(key)
    if is_ed:
        if len(data) < PRE_LEN + ED25519_LEN:
            raise ProtocolError("datagram Ed25519 terlalu pendek")
        pre, body, sig = data[:PRE_LEN], data[PRE_LEN:-ED25519_LEN], data[-ED25519_LEN:]
        if ktype == "ed25519_priv":
            pub_key = kobj.public_key()
        elif ktype == "ed25519_pub":
            pub_key = kobj
        else:
            raise ProtocolError("paket menggunakan Ed25519 tetapi receiver dikonfigurasi dengan kunci HMAC")
        try:
            pub_key.verify(sig, pre + body)
        except InvalidSignature:
            raise ProtocolError("tanda tangan Ed25519 tidak valid")
        return ptype, fid, body
    else:
        if ktype != "hmac":
            raise ProtocolError("paket menggunakan HMAC tetapi receiver mewajibkan Ed25519")
        pre, body, tag = data[:PRE_LEN], data[PRE_LEN:-HMAC_LEN], data[-HMAC_LEN:]
        if not hmac.compare_digest(tag, hmac.new(kobj, pre + body, hashlib.sha256).digest()):
            raise ProtocolError("hmac tidak valid")
        return ptype, fid, body


def build_header(size, n_chunks, chunk_size, ts, fec_group, sha256: bytes, name: str) -> bytes:
    nb = name.encode("utf-8")[:MAX_NAME_BYTES]
    return _HDR.pack(size, n_chunks, chunk_size, ts, fec_group, sha256, len(nb)) + nb


def parse_header(body: bytes) -> dict:
    if len(body) < _HDR.size:
        raise ProtocolError("header terlalu pendek")
    size, n, cs, ts, k, sha, nl = _HDR.unpack(body[:_HDR.size])
    raw = body[_HDR.size:]
    if nl > MAX_NAME_BYTES or nl != len(raw):
        raise ProtocolError("panjang nama tidak cocok")
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("nama bukan UTF-8")
    return {"size": size, "n_chunks": n, "chunk_size": cs, "ts": ts, "fec_group": k, "sha256": sha, "name": name}


def build_chunk(index: int, payload: bytes) -> bytes:
    return _CHUNK.pack(index, len(payload)) + payload


def parse_chunk(body: bytes):
    if len(body) < _CHUNK.size:
        raise ProtocolError("chunk terlalu pendek")
    idx, ln = _CHUNK.unpack(body[:_CHUNK.size])
    payload = body[_CHUNK.size:]
    if ln != len(payload):
        raise ProtocolError("panjang chunk tidak cocok")
    return idx, payload


# --- Aritmetika chunk ------------------------------------------------------
def n_chunks(size: int, cs: int) -> int:
    return -(-size // cs)


def chunk_len(idx: int, size: int, cs: int) -> int:
    n = n_chunks(size, cs)
    return cs if idx < n - 1 else size - (n - 1) * cs


def n_groups(n: int, k: int) -> int:
    return -(-n // k)


def group_range(g: int, n: int, k: int) -> range:
    return range(g * k, min((g + 1) * k, n))


def pad(b: bytes, size: int) -> bytes:
    return b + bytes(size - len(b))
