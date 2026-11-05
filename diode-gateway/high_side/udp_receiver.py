"""Penerima Sisi Dalam (High-Side OT Enclave).
Hanya menerima: TIDAK ADA sendto/send di seluruh modul ini.

Pertahanan Berlapis:
 - Tanda tangan Ed25519 / HMAC per paket diperiksa PERTAMA sebelum apa pun di-parse.
 - Batas ukuran, jumlah transfer paralel, dan timeout (anti-DoS memori/disk).
 - Nama dari header hanya label tampilan: file disimpan sebagai <file_id><ekstensi>.
 - Anti-replay (jendela waktu + daftar file_id selesai yang bertahan lewat restart).
 - Dekoder Matriks Galois Field GF(2^8) Reed-Solomon RS(4, 2): mampu memulihkan
   kehilangan 1 maupun 2 paket sekaligus per grup tanpa jalur balik!
 - Verifikasi SHA-256 utuh, lalu validasi ulang tipe/struktur di sisi dalam.
 - OT Radar Telemetry Loader: memperbarui status parameter radar taktis jika file
   yang masuk adalah paket konfigurasi (.cfg) atau firmware (.bin) yang sah.
"""
import hashlib
import json
import os
import socket
import struct
import time
from collections import deque
from pathlib import Path

from common import config, protocol as P
from common.audit import AuditLog, tail
from common.filetype import check_magic, check_structure, sanitize_name


def _pwrite(fd, data, offset):
    if hasattr(os, "pwrite"):
        os.pwrite(fd, data, offset)
    else:
        os.lseek(fd, offset, os.SEEK_SET)
        os.write(fd, data)


def _pread(fd, n, offset):
    if hasattr(os, "pread"):
        return os.pread(fd, n, offset)
    else:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, n)


class Transfer:
    __slots__ = (
        "fid", "name", "ext", "size", "n", "cs", "k", "sha",
        "fd", "path", "have", "n_have", "parity_p0", "parity_p1",
        "created", "last", "recovered", "dups", "eof"
    )


class ReceiverCore:
    def __init__(self, key, vault_dir, staging_dir, audit, state_path=None, clock=time.time):
        self.key, self.clock, self.audit = key, clock, audit
        self.vault, self.staging = Path(vault_dir), Path(staging_dir)
        for d in (self.vault, self.staging):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        for stale in self.staging.glob("*.part"):
            stale.unlink()
        self.state_path = Path(state_path) if state_path else None
        self.ot_state_path = self.vault.parent / "ot_radar_state.json"
        self.epoch_path = self.vault.parent / "state_epoch.json"
        self.active, self.done = {}, {}
        now = clock()
        for rec in tail(audit.path, 1000):           # anti-replay bertahan lewat restart
            if rec.get("file_id"):
                self.done[rec["file_id"]] = now
        self.stats = dict.fromkeys(
            ("packets", "rejected_auth", "malformed", "duplicates",
             "late_or_orphan", "headers_rejected", "busy_drops"),
            0,
        )
        self.recent = deque(maxlen=12)
        self.dirty, self._flushed = True, 0.0
        self._init_ot_state()

    def _init_ot_state(self):
        if not self.ot_state_path.exists():
            default_ot = {
                "unit": "RADAR-ARHANUD-KARTIKA-01",
                "firmware_version": "v1.0.0-BASELINE",
                "sweep_freq_mhz": 2850,
                "interlock_status": "ACTIVE (SAFE)",
                "last_update_file": "-",
                "updated_at": "-",
            }
            try:
                self.ot_state_path.write_text(json.dumps(default_ot, ensure_ascii=False))
            except OSError:
                pass

    def _update_ot_radar(self, t, final_path: Path):
        """Jika file yang lolos adalah .cfg atau .bin, perbarui simulasi status Radar OT."""
        if t.ext not in (".cfg", ".bin"):
            return
        try:
            cur = json.loads(self.ot_state_path.read_text()) if self.ot_state_path.exists() else {}
        except Exception:
            cur = {}
        raw = final_path.read_bytes()
        if t.ext == ".bin" and len(raw) >= 12 and raw[:4] == b"KRTK":
            _, maj, min_v, _ = struct.unpack(">4sHHI", raw[:12])
            cur["firmware_version"] = f"v{maj}.{min_v}.0-KRTK-VERIFIED"
        elif t.ext == ".cfg":
            text = raw.decode("utf-8-sig", errors="ignore")
            for line in text.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = [x.strip() for x in line.split("=", 1)]
                    if k.upper() == "SWEEP_FREQ_MHZ" and v.isdigit():
                        cur["sweep_freq_mhz"] = int(v)
                    elif k.upper() == "FIRMWARE_PROFILE":
                        cur["firmware_version"] = v[:32]
        cur["unit"] = cur.get("unit", "RADAR-ARHANUD-KARTIKA-01")
        cur["interlock_status"] = "ACTIVE (VERIFIED CLEAN)"
        cur["last_update_file"] = t.name
        cur["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock()))
        tmp = self.ot_state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, ensure_ascii=False))
        os.replace(tmp, self.ot_state_path)

    # ---- penerimaan paket -------------------------------------------------
    def handle(self, datagram: bytes):
        self.stats["packets"] += 1
        self.dirty = True
        try:
            ptype, fid, body = P.unpack(datagram, self.key)
        except P.ProtocolError:
            self.stats["rejected_auth"] += 1
            return
        fh = fid.hex()
        if ptype == P.T_HEADER:
            return self._on_header(fh, body)
        t = self.active.get(fh)
        if t is None:
            self.stats["late_or_orphan"] += 1
            return
        t.last = self.clock()
        try:
            if ptype == P.T_DATA:
                self._on_data(t, body)
            elif ptype == P.T_PARITY:
                self._on_parity(t, body)
            else:
                t.eof += 1
                self._try_complete(t)
        except P.ProtocolError:
            self.stats["malformed"] += 1

    def _event(self, event, **kw):
        rec = self.audit.append({"event": event, **kw})
        self.recent.appendleft({"ts": rec["ts"], "event": event, "name": kw.get("name", ""), "code": kw.get("code", "")})
        self.dirty = True

    def _reject_header(self, fh, code, detail, name=""):
        self.stats["headers_rejected"] += 1
        self.done[fh] = self.clock()
        self._event("HEADER_REJECTED", file_id=fh, name=name, code=code, detail=detail)

    def _on_header(self, fh, body):
        if fh in self.active or fh in self.done:
            self.stats["duplicates"] += 1
            return
        try:
            h = P.parse_header(body)
        except P.ProtocolError:
            self.stats["malformed"] += 1
            return
        now = self.clock()
        if abs(now - h["ts"]) > config.REPLAY_WINDOW_S:
            return self._reject_header(fh, "REPLAY_OR_CLOCK_SKEW", "cap waktu di luar jendela anti-replay")
        name, ext, err = sanitize_name(h["name"])
        if err:
            return self._reject_header(fh, err, "nama/ekstensi tidak diizinkan")
        cs, k, size, n = h["chunk_size"], h["fec_group"], h["size"], h["n_chunks"]
        if not (0 < size <= config.MAX_FILE_BYTES):
            return self._reject_header(fh, "SIZE_LIMIT", f"ukuran {size} di luar batas", name)
        if not (256 <= cs <= 1200) or k > 16 or n != P.n_chunks(size, cs):
            return self._reject_header(fh, "HEADER_INVALID", "parameter chunk tidak konsisten", name)
        if len(self.active) >= config.MAX_CONCURRENT:
            self.stats["busy_drops"] += 1     # header diulang tiap pass; transfer bisa mulai nanti
            return
        t = Transfer()
        t.fid, t.name, t.ext, t.size, t.n, t.cs, t.k, t.sha = fh, name, ext, size, n, cs, k, h["sha256"].hex()
        t.path = self.staging / f"{fh}.part"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        t.fd = os.open(t.path, flags, 0o600)
        os.ftruncate(t.fd, size)
        t.have, t.n_have = bytearray(n), 0
        t.parity_p0, t.parity_p1 = {}, {}
        t.created = t.last = now
        t.recovered = t.dups = t.eof = 0
        self.active[fh] = t
        self._event("TRANSFER_STARTED", file_id=fh, name=name, size=size, sha256=t.sha)

    def _on_data(self, t, body):
        idx, payload = P.parse_chunk(body)
        if idx >= t.n or len(payload) != P.chunk_len(idx, t.size, t.cs):
            self.stats["malformed"] += 1
            return
        if t.have[idx]:
            t.dups += 1
            return
        _pwrite(t.fd, payload, idx * t.cs)
        t.have[idx] = 1
        t.n_have += 1
        if t.k:
            self._recover_group(t, idx // t.k)
        self._try_complete(t)

    def _on_parity(self, t, body):
        p_idx, payload = P.parse_chunk(body)
        if not t.k or len(payload) != t.cs:
            self.stats["malformed"] += 1
            return
        ng = P.n_groups(t.n, t.k)
        # Kompatibilitas ganda:
        # - Skema RS(4,2) menggunakan p_idx = g * 2 (P0 XOR) dan g * 2 + 1 (P1 GF256)
        # - Jika p_idx < 2 * ng, petakan ke grup g = p_idx // 2 dan slot = p_idx % 2
        if p_idx < 2 * ng:
            g, slot = p_idx // 2, p_idx % 2
        else:
            self.stats["malformed"] += 1
            return
        if slot == 0:
            t.parity_p0[g] = payload
        else:
            t.parity_p1[g] = payload
        self._recover_group(t, g)
        self._try_complete(t)

    def _recover_group(self, t, g):
        p0 = t.parity_p0.get(g)
        p1 = t.parity_p1.get(g)
        if p0 is None and p1 is None:
            return
        idxs = list(P.group_range(g, t.n, t.k))
        missing_global = [i for i in idxs if not t.have[i]]
        if not missing_global or len(missing_global) > 2:
            return
        have_local = {}
        for local_i, global_i in enumerate(idxs):
            if t.have[global_i]:
                raw = _pread(t.fd, P.chunk_len(global_i, t.size, t.cs), global_i * t.cs)
                have_local[local_i] = P.pad(raw, t.cs)
        recovered_map = P.rs_recover_group(len(idxs), t.cs, have_local, p0=p0, p1=p1)
        for local_i, rec_padded in recovered_map.items():
            global_i = idxs[local_i]
            if not t.have[global_i]:
                actual_len = P.chunk_len(global_i, t.size, t.cs)
                _pwrite(t.fd, rec_padded[:actual_len], global_i * t.cs)
                t.have[global_i] = 1
                t.n_have += 1
                t.recovered += 1

    def _try_complete(self, t):
        if t.n_have == t.n:
            self._finalize(t)

    # ---- penyelesaian -----------------------------------------------------
    def _drop(self, t, event, code, detail):
        if t.fd >= 0:
            os.close(t.fd)
            t.fd = -1
        t.path.unlink(missing_ok=True)
        self.active.pop(t.fid, None)
        self.done[t.fid] = self.clock()
        self._event(event, file_id=t.fid, name=t.name, size=t.size, code=code, detail=detail)

    def _finalize(self, t):
        try:
            os.fsync(t.fd)
            os.close(t.fd)
            t.fd = -1
            h = hashlib.sha256()
            with open(t.path, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h.update(blk)
            if h.hexdigest() != t.sha:
                return self._drop(
                    t,
                    "INTEGRITY_CHECK_FAILED",
                    "SHA256_MISMATCH",
                    "hash hasil rakitan tidak sama dengan hash di header",
                )
            ok, code, detail = check_magic(t.path, t.ext)
            if ok:
                ok, code, detail = check_structure(t.path, t.ext)
            if not ok:
                return self._drop(t, "HIGH_REVALIDATION_FAILED", code, detail)
            final = self.vault / f"{t.fid}{t.ext}"
            os.replace(t.path, final)
            os.chmod(final, 0o600)
            self._update_ot_radar(t, final)
            try:
                self.epoch_path.write_text(json.dumps({"last_epoch_s": int(self.clock()), "last_file_id": t.fid}))
            except OSError:
                pass
            meta = {
                "file_id": t.fid,
                "name": t.name,
                "size": t.size,
                "sha256": t.sha,
                "stored_as": final.name,
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())),
                "chunks": t.n,
                "recovered_by_fec": t.recovered,
                "duplicate_packets": t.dups,
            }
            tmp = self.vault / f".{t.fid}.json.tmp"
            tmp.write_text(json.dumps(meta, ensure_ascii=False))
            os.replace(tmp, self.vault / f"{t.fid}.json")
            self.active.pop(t.fid, None)
            self.done[t.fid] = self.clock()
            self._event(
                "VERIFIED_AND_SAVED",
                file_id=t.fid,
                name=t.name,
                size=t.size,
                sha256=t.sha,
                recovered_by_fec=t.recovered,
            )
        except Exception as e:
            if t.fd >= 0:
                os.close(t.fd)
                t.fd = -1
            self.active.pop(t.fid, None)
            self.done[t.fid] = self.clock()
            t.path.unlink(missing_ok=True)
            self._event("FINALIZE_ERROR", file_id=t.fid, name=t.name, code=type(e).__name__)

    def tick(self):
        now = self.clock()
        for t in list(self.active.values()):
            if now - t.created > config.TRANSFER_TIMEOUT_S or now - t.last > config.IDLE_TIMEOUT_S:
                self._drop(
                    t,
                    "TRANSFER_INCOMPLETE",
                    "TIMEOUT",
                    f"{t.n - t.n_have} dari {t.n} chunk tidak pernah diterima",
                )
        for fh, ts in list(self.done.items()):
            if now - ts > 2 * config.REPLAY_WINDOW_S:
                del self.done[fh]

    # ---- status untuk UI --------------------------------------------------
    def snapshot(self):
        ot = {}
        try:
            if self.ot_state_path.exists():
                ot = json.loads(self.ot_state_path.read_text())
        except Exception:
            pass
        return {
            "updated": self.clock(),
            "stats": dict(self.stats),
            "recent": list(self.recent),
            "ot_radar": ot,
            "active": [
                {
                    "file_id": t.fid,
                    "name": t.name,
                    "size": t.size,
                    "received": t.n_have,
                    "total": t.n,
                    "recovered": t.recovered,
                    "dups": t.dups,
                }
                for t in self.active.values()
            ],
        }

    def flush_state(self, force=False):
        if not self.state_path or not (self.dirty or force):
            return
        now = self.clock()
        if not force and now - self._flushed < 0.4:
            return
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.snapshot()))
        os.replace(tmp, self.state_path)
        self.dirty, self._flushed = False, now


def serve(core: ReceiverCore, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.bind((host, port))
    s.settimeout(0.5)
    print(f"[receiver] mendengar UDP {host}:{port} (hanya menerima, 0 byte balik)", flush=True)
    while True:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            data = None
        if data:
            core.handle(data)
        core.tick()
        core.flush_state()


def main():
    key = config.load_key("verify")
    audit = AuditLog(config.HIGH_DIR / "audit_high.jsonl")
    core = ReceiverCore(
        key,
        config.HIGH_DIR / "secure_vault",
        config.HIGH_DIR / "staging",
        audit,
        state_path=config.HIGH_DIR / "live.json",
    )
    core.flush_state(force=True)
    serve(core, config.RX_BIND, config.RX_PORT)


if __name__ == "__main__":
    main()
