"""Log audit JSON Lines dengan rantai hash (tamper-evident).

Setiap baris memuat `prev` = SHA-256 dari baris sebelumnya. Mengubah atau
menghapus baris di tengah akan memutus rantai.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ZERO = "0" * 64


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._last = self._tail_hash()

    def _tail_hash(self):
        if not self.path.exists() or self.path.stat().st_size == 0:
            return ZERO
        with open(self.path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        return hashlib.sha256(lines[-1]).hexdigest() if lines else ZERO

    def append(self, record: dict) -> dict:
        with self._lock:
            rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record, "prev": self._last}
            line = json.dumps(rec, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            with open(self.path, "ab") as f:
                f.write(line + b"\n")
                f.flush()
                os.fsync(f.fileno())
            self._last = hashlib.sha256(line).hexdigest()
        return rec


def verify_chain(path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"ok": True, "records": 0, "first_bad_line": None}
    prev, n = ZERO, 0
    with open(path, "rb") as f:
        for n, raw in enumerate(f, start=1):
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                return {"ok": False, "records": n, "first_bad_line": n}
            if rec.get("prev") != prev:
                return {"ok": False, "records": n, "first_bad_line": n}
            prev = hashlib.sha256(raw).hexdigest()
    return {"ok": True, "records": n, "first_bad_line": None}


def tail(path, limit=50):
    """Catatan terbaru lebih dulu."""
    path = Path(path)
    if not path.exists():
        return []
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 2_000_000))
        lines = f.read().splitlines()
    out = []
    for raw in lines[-limit:]:
        try:
            out.append(json.loads(raw))
        except ValueError:
            continue
    out.reverse()
    return out
