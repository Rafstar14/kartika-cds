import io
import time
from pathlib import Path
from common import config
from high_side.app import create_app as create_high
from low_side.app import create_app as create_low
from low_side.gate_inspector import Gate
from tests.helpers import KEY, make_pdf
from tests.test_gate import FakeClam, RULES

H = {"X-Diode-Request": "1"}


def low_client(tmp_path, monkeypatch, sent):
    monkeypatch.setattr(config, "LOW_DIR", tmp_path / "low")

    def fake_send(path, name, sha, **kw):
        sent.append((name, sha, Path(path).exists()))
        return {"file_id": "ab" * 16, "packets": 9, "bytes": 1}

    gate = Gate(RULES, clam=FakeClam(), required={"clamav"})
    return create_low(gate=gate, key=KEY, send=fake_send).test_client()


def post(c, name, data, headers=H):
    return c.post("/api/upload", data={"file": (io.BytesIO(data), name)}, headers=headers, content_type="multipart/form-data")


def test_csrf_header_required(tmp_path, monkeypatch):
    c = low_client(tmp_path, monkeypatch, [])
    assert post(c, "a.txt", b"halo", headers={}).status_code == 403


def test_rejected_file_is_quarantined_and_never_sent(tmp_path, monkeypatch):
    sent = []
    c = low_client(tmp_path, monkeypatch, sent)
    j = post(c, "laporan.pdf", b"MZ" + bytes(100)).get_json()["job"]
    time.sleep(0.2)
    assert j["verdict"] == "REJECTED" and j["code"] == "FORMAT_SPOOFING_DETECTED" and not sent


def test_accepted_file_is_sent_and_dropzone_cleared(tmp_path, monkeypatch):
    sent = []
    c = low_client(tmp_path, monkeypatch, sent)
    j = post(c, "../../x.pdf", make_pdf()).get_json()["job"]
    assert j["verdict"] == "ACCEPTED" and j["name"] == "x.pdf"
    for _ in range(40):
        jobs = c.get("/api/jobs").get_json()
        if jobs[0]["transfer"]["state"] == "sent":
            break
        time.sleep(0.05)
    assert jobs[0]["transfer"]["state"] == "sent" and sent[0][0] == "x.pdf"


def test_high_ui_is_read_only(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "HIGH_DIR", tmp_path / "high")
    c = create_high().test_client()
    assert c.get("/api/live").get_json()["active"] == []
    assert c.get("/api/vault").get_json() == []
    for m in (c.post, c.put, c.delete):
        assert m("/api/vault").status_code in (404, 405)
