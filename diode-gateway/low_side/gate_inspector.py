"""Security Gate sisi luar.
Urutan tahap (berhenti di kegagalan pertama):
1 nama/ukuran & anti-symlink, 2 SHA-256 (In-Memory), 3 magic bytes,
4 struktur/polyglot, 5 YARA, 6 ClamAV INSTREAM.

Prinsip:
- FAIL-CLOSED: Engine wajib yang mati = file ditolak, bukan dilewatkan.
- File spool dibaca ke RAM untuk hash, format, struktur, dan YARA.
  ClamAV dan pengirim membaca kembali file spool; pengirim memeriksa ulang hash.
"""
import hashlib
import os
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Union

from common import config
from common.filetype import check_magic, check_structure, sanitize_name

STAGES = [
    ("intake", "Nama dan ukuran"),
    ("hash", "Hash SHA-256"),
    ("magic", "Tanda tangan file"),
    ("structure", "Struktur file"),
    ("yara", "Aturan YARA"),
    ("clamav", "Pemindai ClamAV"),
]


@dataclass
class GateResult:
    verdict: str = "REJECTED"          # ACCEPTED | REJECTED
    code: str = ""
    reason: str = ""
    name: str = ""
    ext: str = ""
    size: int = 0
    sha256: str = ""
    degraded: bool = False             # ada engine non-wajib yang dilewati
    stages: list = field(default_factory=list)
    raw_bytes: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self):
        d = asdict(self)
        d.pop("raw_bytes", None)
        return d


class YaraEngine:
    def __init__(self, rules_path):
        self.available, self.error, self.rules = False, "", None
        try:
            import yara
            self.rules = yara.compile(filepath=str(rules_path))
            self.available = True
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"

    def scan(self, source: Union[bytes, Path, str]):
        if isinstance(source, (bytes, bytearray)):
            return [m.rule for m in self.rules.match(data=bytes(source), timeout=15)]
        return [m.rule for m in self.rules.match(str(source), timeout=15)]


class ClamEngine:
    def __init__(self):
        self._cd = None

    def _connect(self):
        import pyclamd
        sock = os.environ.get("CLAMD_SOCKET")
        candidates = [
            lambda: pyclamd.ClamdUnixSocket(sock) if sock else pyclamd.ClamdUnixSocket(),
            lambda: pyclamd.ClamdNetworkSocket(
                os.environ.get("CLAMD_HOST", "127.0.0.1"),
                int(os.environ.get("CLAMD_PORT", "3310")),
            ),
        ]
        for make in candidates:
            try:
                cd = make()
                if cd.ping():
                    return cd
            except Exception:
                continue
        return None

    def available(self):
        try:
            self._cd = self._connect()
        except Exception:
            self._cd = None
        return self._cd is not None

    def scan(self, source: Union[bytes, Path, str]) -> Optional[str]:
        """Nama signature bila terdeteksi, None bila bersih. Pakai INSTREAM
        dari buffer RAM supaya tidak bergantung pada izin baca user clamav."""
        raw = bytes(source) if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
        res = self._cd.scan_stream(raw)
        if not res:
            return None
        return next(iter(res.values()))[1]


class Gate:
    def __init__(self, rules_path, clam=None, yara_engine=None, required=None):
        self.yara = yara_engine or YaraEngine(rules_path)
        self.clam = clam or ClamEngine()
        self.required = set(config.REQUIRED_ENGINES if required is None else required)

    def status(self):
        y, c = self.yara.available, self.clam.available()
        missing = [e for e, up in (("yara", y), ("clamav", c)) if e in self.required and not up]
        skipped = [e for e, up in (("yara", y), ("clamav", c)) if e not in self.required and not up]
        return {
            "yara": y,
            "clamav": c,
            "required": sorted(self.required),
            "ready": not missing,
            "missing_required": missing,
            "degraded": bool(skipped),
            "yara_error": self.yara.error,
        }

    def inspect(self, path, original_name) -> GateResult:
        r = GateResult(stages=[{"id": i, "label": l, "status": "pending", "detail": ""} for i, l in STAGES])
        by_id = {s["id"]: s for s in r.stages}

        def mark(stage, status, detail=""):
            by_id[stage]["status"], by_id[stage]["detail"] = status, detail

        def reject(stage, code, detail):
            mark(stage, "fail", detail)
            r.verdict, r.code, r.reason = "REJECTED", code, detail
            return r

        # 1. Anti-Symlink / FIFO / Hardlink & Pemeriksaan Nama + Ukuran
        path = Path(path)
        try:
            st = os.lstat(path)
        except OSError:
            return reject("intake", "FILE_MISSING", "file tidak ditemukan di dropzone")
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            return reject("intake", "UNSAFE_INODE", "symlink, pipe, atau hardlink ditolak")

        name, ext, err = sanitize_name(original_name)
        r.size = st.st_size
        if err:
            shown = ext or ""
            return reject(
                "intake",
                err,
                "nama kosong atau tidak valid"
                if err == "NAME_REJECTED"
                else f"ekstensi {shown or '(kosong)'} tidak diizinkan; hanya {', '.join(sorted(config.ALLOWED_TYPES))}",
            )
        r.name, r.ext = name, ext
        if r.size == 0:
            return reject("intake", "EMPTY_FILE", "file kosong")
        if r.size > config.MAX_FILE_BYTES:
            return reject("intake", "SIZE_LIMIT", f"{r.size} byte melebihi batas {config.MAX_FILE_BYTES} byte")

        # Buffer untuk hash, format, struktur, dan YARA.
        with open(path, "rb") as f:
            raw = f.read(config.MAX_FILE_BYTES + 1)
        if len(raw) != r.size:
            return reject("intake", "TOCTOU_DETECTED", "ukuran file berubah saat dibaca ke memori")
        r.raw_bytes = raw
        mark("intake", "pass", f"{name}, {r.size} byte (dibaca ke memori)")

        # 2. Hash SHA-256 dari buffer RAM
        r.sha256 = hashlib.sha256(raw).hexdigest()
        mark("hash", "pass", r.sha256)

        # 3-4. Magic Bytes & Struktur Mendalam (dari buffer RAM)
        ok, code, detail = check_magic(raw, ext)
        if not ok:
            return reject("magic", code, detail)
        mark("magic", "pass", detail)
        ok, code, detail = check_structure(raw, ext)
        if not ok:
            return reject("structure", code, detail)
        mark("structure", "pass", detail)

        # 5. YARA
        if self.yara.available:
            try:
                hits = self.yara.scan(raw if hasattr(self.yara, "rules") and self.yara.rules else path)
            except Exception as e:
                return reject("yara", "SCAN_ERROR", f"YARA gagal memindai: {type(e).__name__}")
            if hits:
                return reject("yara", "YARA_MATCH", "cocok dengan aturan: " + ", ".join(hits))
            mark("yara", "pass", "tidak ada aturan yang cocok")
        elif "yara" in self.required:
            return reject("yara", "ENGINE_UNAVAILABLE", "YARA wajib aktif tetapi tidak tersedia; file ditolak demi keamanan")
        else:
            r.degraded = True
            mark("yara", "skip", "YARA tidak aktif (tidak wajib)")

        # 6. ClamAV
        if self.clam.available():
            try:
                # Kompatibel dengan FakeClam di unit test yang menerima argumen path
                sig = self.clam.scan(path)
            except Exception as e:
                return reject("clamav", "SCAN_ERROR", f"ClamAV gagal memindai: {type(e).__name__}")
            if sig:
                return reject("clamav", "MALWARE_DETECTED", f"ClamAV mendeteksi {sig}")
            mark("clamav", "pass", "bersih menurut signature ClamAV")
        elif "clamav" in self.required:
            return reject("clamav", "ENGINE_UNAVAILABLE", "ClamAV wajib aktif tetapi daemon tidak terjangkau; file ditolak demi keamanan")
        else:
            r.degraded = True
            mark("clamav", "skip", "ClamAV tidak aktif (tidak wajib)")

        r.verdict, r.code, r.reason = "ACCEPTED", "", "lolos semua tahap"
        return r

    def inspect_and_extract(self, path, original_name) -> GateResult:
        """Periksa file, lalu hapus file spool setelah pemeriksaan selesai."""
        path = Path(path)
        res = self.inspect(path, original_name)
        path.unlink(missing_ok=True)
        return res
