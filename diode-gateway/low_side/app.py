"""UI dan orkestrasi sisi luar: unggah -> gate (in-memory) -> (karantina | kirim satu arah)."""
import json
import logging
import os
import queue
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

from common import config
from common.audit import AuditLog, tail, verify_chain
from common.web import harden
from low_side.gate_inspector import Gate, GateResult
from low_side.udp_sender import send_file

WEB = Path(__file__).parent / "web"
RULES = Path(__file__).parent / "rules" / "gateway.yar"


def create_app(gate=None, key=None, send=send_file, start_worker=True):
    app = Flask(__name__, static_folder=str(config.BASE / "common" / "static"), static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_FILE_BYTES + 64 * 1024
    harden(app)

    drop, quarantine = config.LOW_DIR / "dropzone", config.LOW_DIR / "quarantine"
    for d in (drop, quarantine):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    for stale in drop.glob("*.upload"):          # sisa dari proses sebelumnya tidak pernah dikirim
        stale.unlink()
    audit_path = config.LOW_DIR / "audit_low.jsonl"
    audit = AuditLog(audit_path)
    gate = gate or Gate(RULES)
    key = key or config.load_key("sign")
    jobs, lock, q = OrderedDict(), threading.Lock(), queue.Queue()

    def worker():
        while True:
            job_id, path, name, sha = q.get()
            t = jobs[job_id]["transfer"]
            t["state"] = "sending"
            try:
                def prog(i, total):
                    t["sent"], t["total"] = i, total
                res = send(path, name, sha, key=key, host=config.RX_HOST, port=config.RX_PORT, progress=prog)
                t.update(state="sent", file_id=res["file_id"], sent=res["packets"], total=res["packets"])
                audit.append({"event": "SENT_NO_ACK", "file_id": res["file_id"], "name": name, "sha256": sha, "packets": res["packets"]})
            except Exception as e:
                t.update(state="failed", error=f"{type(e).__name__}: {str(e)[:120]}")
                audit.append({"event": "SEND_FAILED", "name": name, "sha256": sha, "code": type(e).__name__})
            finally:
                Path(path).unlink(missing_ok=True)

    if start_worker:
        threading.Thread(target=worker, daemon=True).start()

    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/app.js")
    def appjs():
        return send_from_directory(WEB, "app.js")

    @app.errorhandler(413)
    def too_big(_):
        return jsonify(error=f"File terlalu besar. Maksimum {config.MAX_FILE_BYTES // 1048576} MB."), 413

    @app.get("/api/status")
    def status():
        return jsonify(gate.status())

    @app.get("/api/jobs")
    def list_jobs():
        with lock:
            return jsonify(list(reversed(list(jobs.values())))[:12])

    @app.get("/api/audit")
    def audit_view():
        return jsonify(records=tail(audit_path, 40), chain=verify_chain(audit_path))

    @app.post("/api/upload")
    def upload():
        if request.headers.get("X-Diode-Request") != "1":      # blokir form lintas-situs (CSRF)
            abort(403)
        f = request.files.get("file")
        if f is None or not f.filename:
            return jsonify(error="Pilih satu file untuk diperiksa."), 400
        job_id = uuid.uuid4().hex[:12]
        tmp = drop / f"{job_id}.upload"                           # nama di disk = id acak, bukan nama dari pengguna
        f.save(tmp)
        os.chmod(tmp, 0o600)
        try:
            res = gate.inspect(tmp, f.filename)
        except Exception as e:                                    # fail-closed
            res = GateResult(code="GATE_ERROR", reason=f"gate error: {type(e).__name__}", name="")
        job = {**res.to_dict(), "id": job_id, "created": time.time(), "transfer": {"state": "none"}}
        base = {"name": res.name, "sha256": res.sha256, "size": res.size, "code": res.code}
        if res.verdict == "ACCEPTED":
            job["transfer"] = {"state": "queued", "sent": 0, "total": 0}
            audit.append({"event": "GATE_ACCEPTED", "degraded": res.degraded, **base})
        else:
            dest = quarantine / f"{job_id}.quarantined"
            os.replace(tmp, dest)
            os.chmod(dest, 0o400)
            (quarantine / f"{job_id}.json").write_text(json.dumps({**base, "reason": res.reason}, ensure_ascii=False))
            audit.append({"event": "GATE_REJECTED", "reason": res.reason, **base})
        with lock:
            jobs[job_id] = job
            while len(jobs) > 50:
                jobs.popitem(last=False)
        if res.verdict == "ACCEPTED":
            q.put((job_id, str(tmp), res.name, res.sha256))
        return jsonify(job=job)

    return app


def main():
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = create_app()
    host, port = os.environ.get("LOW_UI_HOST", "127.0.0.1"), int(os.environ.get("LOW_UI_PORT", "5000"))
    print(f"[low-ui] http://{host}:{port}  (server pengembangan Flask; untuk demo, bukan produksi)", flush=True)
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
