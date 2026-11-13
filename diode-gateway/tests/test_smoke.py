import hashlib

import pytest

from scripts import demo_smoke_test as smoke
from scripts import make_demo_files


def test_missing_sample_is_failure_not_detection(monkeypatch, capsys):
    monkeypatch.setattr(smoke, "SCENARIOS", (("data_terinfeksi.txt", "REJECTED", ("YARA_MATCH",), "EICAR"),))
    monkeypatch.setattr(smoke, "get_json", lambda url: {"ready": True, "required": []})

    def missing(*args):
        raise FileNotFoundError("file tidak ada")

    monkeypatch.setattr(smoke, "upload", missing)
    assert smoke.main([]) == 1
    out = capsys.readouterr().out
    assert "[GAGAL]" in out
    assert "[LULUS]" not in out


def test_rejected_sample_requires_expected_reason(monkeypatch):
    monkeypatch.setattr(smoke, "upload", lambda *args: ({"verdict": "REJECTED", "code": "ENGINE_UNAVAILABLE"}, ""))
    scenario = ("pdf_aktif.pdf", "REJECTED", ("YARA_MATCH",), "PDF aktif")
    with pytest.raises(ValueError, match="ENGINE_UNAVAILABLE"):
        smoke.run_scenario("http://low", "http://high", scenario)


def test_receipt_requires_matching_transfer_id_and_hash(monkeypatch):
    expected_sha = hashlib.sha256(b"sampel").hexdigest()
    responses = {
        "http://low/api/jobs": [{"id": "new-job", "transfer": {"state": "sent", "file_id": "new-file"}}],
        "http://high/api/vault": [
            {"file_id": "old-file", "sha256": expected_sha},
            {"file_id": "new-file", "sha256": "salah"},
        ],
    }
    monkeypatch.setattr(smoke, "get_json", lambda url: responses[url])
    with pytest.raises(ValueError, match="hash brankas"):
        smoke.wait_for_receipt("http://low", "http://high", "new-job", expected_sha)

    responses["http://high/api/vault"][1]["sha256"] = expected_sha
    assert smoke.wait_for_receipt("http://low", "http://high", "new-job", expected_sha) == "new-file"


def test_transfer_failure_is_not_a_receipt(monkeypatch):
    monkeypatch.setattr(smoke, "get_json", lambda url: [
        {"id": "job", "transfer": {"state": "failed", "error": "koneksi gagal"}}
    ])
    with pytest.raises(ValueError, match="koneksi gagal"):
        smoke.wait_for_receipt("http://low", "http://high", "job", "hash")


def test_sample_generator_continues_after_write_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(make_demo_files, "OUT", tmp_path)
    written = []

    def fake_write(path, data):
        if path.name == "data_terinfeksi.txt":
            raise PermissionError("file diblokir")
        written.append(path.name)

    monkeypatch.setattr(type(tmp_path), "write_bytes", fake_write)
    assert make_demo_files.main() == 1
    assert "pdf_aktif.pdf" in written
    assert "[GAGAL] data_terinfeksi.txt" in capsys.readouterr().out
