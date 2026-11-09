import pytest
from pathlib import Path
from low_side.gate_inspector import Gate
from tests.helpers import make_pdf, make_png, make_firmware

RULES = Path(__file__).resolve().parent.parent / "low_side" / "rules" / "gateway.yar"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeClam:
    def __init__(self, up=True, sig=None):
        self.up, self.sig = up, sig

    def available(self):
        return self.up

    def scan(self, path):
        return self.sig


def gate(clam=None, required=("yara", "clamav")):
    return Gate(RULES, clam=clam or FakeClam(), required=set(required))


def run(g, tmp_path, name, data):
    p = tmp_path / "x.upload"
    p.write_bytes(data)
    return g.inspect(p, name)


def test_valid_files_and_ot_packages_pass(tmp_path):
    g = gate(required=set())
    samples = (
        ("laporan.pdf", make_pdf()),
        ("gambar.png", make_png()),
        ("catatan.txt", b"halo dunia\n"),
        ("radar.cfg", b"SWEEP_FREQ_MHZ=2900\n"),
        ("fw.bin", make_firmware()),
    )
    for name, data in samples:
        r = run(g, tmp_path, name, data)
        assert r.verdict == "ACCEPTED", (name, r.code, r.reason)


@pytest.mark.parametrize("data", [b"\x7fELF" + bytes(200), b"MZ" + bytes(200), b"#!/bin/sh\necho hi\n"])
def test_executable_renamed_pdf_is_spoofing(tmp_path, data):
    r = run(gate(required=set()), tmp_path, "laporan_palsu.pdf", data)
    assert (r.verdict, r.code) == ("REJECTED", "FORMAT_SPOOFING_DETECTED")


def test_corrupted_firmware_crc_rejected(tmp_path):
    bad_fw = bytearray(make_firmware())
    bad_fw[-1] ^= 0xFF
    r = run(gate(required=set()), tmp_path, "fw.bin", bytes(bad_fw))
    assert (r.verdict, r.code) == ("REJECTED", "STRUCTURE_INVALID")


def test_symlink_in_dropzone_rejected(tmp_path):
    target = tmp_path / "real.txt"
    target.write_bytes(b"halo")
    link = tmp_path / "link.upload"
    try:
        link.symlink_to(target)
    except OSError:
        import pytest
        pytest.skip("Symlink creation requires elevated privileges on Windows")
    r = gate(required=set()).inspect(link, "real.txt")
    assert (r.verdict, r.code) == ("REJECTED", "UNSAFE_INODE")


def test_extension_not_allowed_and_traversal_name(tmp_path):
    g = gate(required=set())
    assert run(g, tmp_path, "script.ps1", b"x").code == "EXT_NOT_ALLOWED"
    assert run(g, tmp_path, "evil.exe", b"MZ").code == "EXT_NOT_ALLOWED"
    r = run(g, tmp_path, "../../etc/passwd.txt", b"aman")
    assert r.verdict == "ACCEPTED" and r.name == "passwd.txt"


def test_png_with_trailing_payload_is_polyglot(tmp_path):
    r = run(gate(required=set()), tmp_path, "a.png", make_png(extra=b"MZ" + bytes(50)))
    assert r.code == "STRUCTURE_INVALID" and "IEND" in r.reason


def test_pdf_with_javascript_hits_yara(tmp_path):
    g = gate()
    if not g.yara.available:
        pytest.skip("yara-python tidak terpasang di environment ini")
    r = run(g, tmp_path, "a.pdf", make_pdf(b"<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n"))
    assert r.code == "YARA_MATCH" and "Pdf_Active_Content" in r.reason


def test_ot_radar_sabotage_hits_yara(tmp_path):
    g = gate()
    if not g.yara.available:
        pytest.skip("yara-python tidak terpasang di environment ini")
    r = run(g, tmp_path, "radar.cfg", b"SWEEP_FREQ_MHZ=2800\nDISABLE_RADAR_INTERLOCK=1\n")
    assert r.code == "YARA_MATCH" and "OT_Radar_Sabotage_Patterns" in r.reason


def test_clamav_detection(tmp_path):
    r = run(gate(clam=FakeClam(sig="Win.Test.Foo"), required=("clamav",)), tmp_path, "a.txt", b"bersih")
    assert r.code == "MALWARE_DETECTED" and "Win.Test.Foo" in r.reason


def test_fail_closed_when_required_engine_down(tmp_path):
    r = run(gate(clam=FakeClam(up=False), required=("clamav",)), tmp_path, "a.txt", b"halo")
    assert (r.verdict, r.code) == ("REJECTED", "ENGINE_UNAVAILABLE")
