"""UI Sisi Dalam (High-Side OT Enclave).
Hanya-baca: membaca file status/log/telemetri OT lokal, tidak ada endpoint POST/PUT/DELETE,
dan tidak membuka koneksi apa pun ke sisi luar.
"""
import json
import logging
import os
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

from common import config
from common.audit import tail, verify_chain
from common.web import harden

WEB = Path(__file__).parent / "web"


def create_app():
    app = Flask(__name__, static_folder=str(config.BASE / "common" / "static"), static_url_path="/static")
    harden(app)
    vault = config.HIGH_DIR / "secure_vault"
    live_path = config.HIGH_DIR / "live.json"
    ot_path = config.HIGH_DIR / "ot_radar_state.json"
    audit_path = config.HIGH_DIR / "audit_high.jsonl"

    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/app.js")
    def appjs():
        return send_from_directory(WEB, "app.js")

    @app.get("/api/live")
    def live():
        try:
            return jsonify(json.loads(live_path.read_text()))
        except (OSError, ValueError):
            return jsonify(updated=0, stats={}, active=[], recent=[], ot_radar={})

    @app.get("/api/ot")
    def ot_status():
        try:
            return jsonify(json.loads(ot_path.read_text()))
        except (OSError, ValueError):
            return jsonify(
                unit="RADAR-ARHANUD-KARTIKA-01",
                firmware_version="v1.0.0-BASELINE",
                sweep_freq_mhz=2850,
                interlock_status="ACTIVE (SAFE)",
                last_update_file="-",
                updated_at="-",
            )

    @app.get("/api/vault")
    def vault_list():
        items = []
        for p in vault.glob("*.json"):
            try:
                items.append(json.loads(p.read_text()))
            except (OSError, ValueError):
                continue
        items.sort(key=lambda m: m.get("received_at", ""), reverse=True)
        return jsonify(items[:100])

    @app.get("/api/audit")
    def audit_view():
        return jsonify(records=tail(audit_path, 40), chain=verify_chain(audit_path))

    return app


def main():
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    host, port = os.environ.get("HIGH_UI_HOST", "127.0.0.1"), int(os.environ.get("HIGH_UI_PORT", "5001"))
    print(f"[high-ui] http://{host}:{port}", flush=True)
    create_app().run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    main()
