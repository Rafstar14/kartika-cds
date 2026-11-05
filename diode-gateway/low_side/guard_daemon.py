"""Guard Daemon (Zona 2 - Security Gate & Unidirectional UDP Transmitter).
Memantau folder spool dari Zona 1 (Dropzone), menarik file 1x ke RAM (inspect_and_extract),
menghapus file spool dari disk untuk menutup celah TOCTOU, memindai 6 tahap di RAM,
menyimpan file yang ditolak ke quarantine (0400), atau menandatangani paket dengan
kunci privat Ed25519 dan mengirimkannya lewat UDP satu arah ke Zona 3 (High-Side OT).
"""
import json
import os
import time
import uuid
from pathlib import Path

from common import config
from common.audit import AuditLog
from low_side.gate_inspector import Gate
from low_side.udp_sender import send_file

RULES = Path(__file__).parent / "rules" / "gateway.yar"


def process_spool_once(spool_dir: Path, quarantine_dir: Path, gate: Gate, key: bytes, audit: AuditLog, send_fn=send_file):
    spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    processed = []
    for meta_file in sorted(spool_dir.glob("*.meta.json")):
        job_id = meta_file.name.replace(".meta.json", "")
        upload_file = spool_dir / f"{job_id}.upload"
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            orig_name = meta.get("filename", upload_file.name)
        except Exception:
            orig_name = upload_file.name
        meta_file.unlink(missing_ok=True)
        if not upload_file.exists():
            continue
        res = gate.inspect_and_extract(upload_file, orig_name)
        base = {"name": res.name, "sha256": res.sha256, "size": res.size, "code": res.code}
        if res.verdict == "ACCEPTED" and res.raw_bytes is not None:
            audit.append({"event": "GATE_ACCEPTED", "degraded": res.degraded, **base})
            tx = send_fn(res.raw_bytes, res.name, res.sha256, key=key, host=config.RX_HOST, port=config.RX_PORT)
            audit.append({"event": "SENT_NO_ACK", "file_id": tx["file_id"], "name": res.name, "sha256": res.sha256, "packets": tx["packets"]})
            processed.append((job_id, "ACCEPTED", tx["file_id"]))
        else:
            if res.raw_bytes is not None:
                dest = quarantine_dir / f"{job_id}.quarantined"
                dest.write_bytes(res.raw_bytes)
                os.chmod(dest, 0o400)
            (quarantine_dir / f"{job_id}.json").write_text(json.dumps({**base, "reason": res.reason}, ensure_ascii=False))
            audit.append({"event": "GATE_REJECTED", "reason": res.reason, **base})
            processed.append((job_id, "REJECTED", res.code))
    return processed


def main():
    spool = config.LOW_DIR / "spool_incoming"
    quarantine = config.LOW_DIR / "quarantine"
    audit = AuditLog(config.LOW_DIR / "audit_low.jsonl")
    gate = Gate(RULES)
    key = config.load_key("sign")
    print(f"[guard-daemon] memantau spool {spool} -> UDP {config.RX_HOST}:{config.RX_PORT}", flush=True)
    while True:
        process_spool_once(spool, quarantine, gate, key, audit)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
