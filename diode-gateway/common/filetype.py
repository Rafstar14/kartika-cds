"""Pemeriksaan tipe, magic bytes, dan struktur mendalam file (Termasuk deteksi Polyglot
serta validasi paket Firmware OT 'KRTK' dan Konfigurasi Radar '.cfg').
Mendukung pemeriksaan berbasis RAM buffer (anti-TOCTOU) maupun path file.
"""
import re
import struct
import unicodedata
import zlib
from pathlib import Path
from typing import Union

from . import config

_EXEC_SIGS = [
    (b"MZ", "executable Windows (PE/DOS)"),
    (b"\x7fELF", "executable Linux (ELF)"),
    (b"#!", "skrip dengan shebang"),
    (b"\xcf\xfa\xed\xfe", "executable macOS (Mach-O)"),
    (b"\xfe\xed\xfa\xcf", "executable macOS (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / class Java"),
    (b"PK\x03\x04", "arsip ZIP/Office/JAR"),
    (b"Rar!\x1a\x07", "arsip RAR"),
    (b"7z\xbc\xaf\x27\x1c", "arsip 7-Zip"),
    (b"\x1f\x8b\x08", "arsip GZIP"),
]
_SIGS = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".bin": [b"KRTK"],
}


def sanitize_name(raw):
    """Kembalikan (nama_bersih, ekstensi, kode_error). Nama asli TIDAK pernah
    dipakai sebagai path di disk; ini hanya label tampilan."""
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKC", name).strip()
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).lstrip(". ")
    if not name:
        return None, None, "NAME_REJECTED"
    ext = Path(name).suffix.lower()
    if ext not in config.ALLOWED_TYPES:
        return None, ext, "EXT_NOT_ALLOWED"
    if len(name) > 100:
        name = name[: 100 - len(ext)] + ext
    return name, ext, ""


def _read_bytes(source: Union[bytes, bytearray, Path, str], max_bytes: int = None) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source[:max_bytes]) if max_bytes else bytes(source)
    with open(source, "rb") as f:
        return f.read(max_bytes) if max_bytes else f.read()


def _libmagic_buffer(data: bytes):
    try:
        import magic  # opsional
        return magic.from_buffer(data, mime=True)
    except Exception:
        return None


def check_magic(source: Union[bytes, Path, str], ext: str):
    """(ok, kode, detail) untuk kecocokan ekstensi vs isi biner."""
    head = _read_bytes(source, 4096)
    for sig, label in _EXEC_SIGS:
        if head.startswith(sig):
            return False, "FORMAT_SPOOFING_DETECTED", f"isi file adalah {label}, bukan {ext}"
    if ext in _SIGS and not any(head.startswith(s) for s in _SIGS[ext]):
        return False, "FORMAT_SPOOFING_DETECTED", f"ekstensi {ext} tetapi isi bukan {ext[1:].upper()} yang valid"
    detail = f"tanda tangan cocok dengan {ext}"
    if ext == ".bin":
        return True, "", "tanda tangan firmware OT KRTK valid"
    mime = _libmagic_buffer(head)
    if mime is not None:
        if ext in (".txt", ".cfg"):
            good = mime.startswith("text/")
        else:
            good = mime == config.ALLOWED_TYPES[ext]
        if not good:
            return False, "FORMAT_SPOOFING_DETECTED", f"libmagic mendeteksi {mime}, diharapkan {config.ALLOWED_TYPES[ext]}"
        detail += f"; libmagic: {mime}"
    return True, "", detail


def _png_problem(d: bytes):
    if len(d) < 20:
        return "file terlalu pendek"
    pos, first = 8, True
    while pos + 8 <= len(d):
        length, ctype = struct.unpack(">I4s", d[pos:pos + 8])
        end = pos + 8 + length + 4
        if end > len(d):
            return "ukuran chunk melebihi ukuran file"
        if zlib.crc32(d[pos + 4:end - 4]) & 0xFFFFFFFF != struct.unpack(">I", d[end - 4:end])[0]:
            return f"CRC chunk {ctype.decode('latin1', errors='replace')} salah"
        if first and ctype != b"IHDR":
            return "chunk pertama bukan IHDR"
        first = False
        pos = end
        if ctype == b"IEND":
            return None if pos == len(d) else "ada data tambahan setelah IEND (kemungkinan polyglot)"
    return "chunk IEND tidak ditemukan"


def _bin_firmware_problem(d: bytes):
    """Format paket firmware OT KARTIKA:
    [4B 'KRTK'][2B major][2B minor][4B payload_len][payload][4B CRC32]
    """
    if len(d) < 16:
        return "paket firmware KRTK terlalu pendek (<16 byte)"
    magic, maj, min_v, plen = struct.unpack(">4sHHI", d[:12])
    if magic != b"KRTK":
        return "header magic bukan KRTK"
    if 12 + plen + 4 != len(d):
        return "panjang payload firmware tidak konsisten (ada data tambahan/polyglot)"
    expected_crc = struct.unpack(">I", d[-4:])[0]
    actual_crc = zlib.crc32(d[:-4]) & 0xFFFFFFFF
    if expected_crc != actual_crc:
        return "CRC32 internal paket firmware KRTK tidak cocok"
    return None


def check_structure(source: Union[bytes, Path, str], ext: str):
    """(ok, kode, detail): struktur internal dan data tambahan yang disisipkan."""
    d = _read_bytes(source)
    problem = None
    if ext == ".png":
        problem = _png_problem(d)
    elif ext == ".jpg":
        if not d.endswith(b"\xff\xd9"):
            problem = "tidak berakhir dengan marker EOI (FFD9); kemungkinan ada data tambahan"
    elif ext == ".pdf":
        tail = d[-1024:]
        i = tail.rfind(b"%%EOF")
        if i < 0:
            problem = "penanda %%EOF tidak ditemukan"
        elif tail[i + 5:].strip(b"\r\n \t\x00"):
            problem = "ada data setelah %%EOF"
    elif ext in (".txt", ".cfg"):
        if b"\x00" in d:
            problem = "mengandung byte NUL (bukan teks murni)"
        else:
            try:
                d.decode("utf-8-sig")
            except UnicodeDecodeError:
                problem = "bukan teks UTF-8 yang valid"
    elif ext == ".bin":
        problem = _bin_firmware_problem(d)
    if problem:
        return False, "STRUCTURE_INVALID", problem
    return True, "", "struktur file konsisten"
