"""Uji contoh unggahan dan penerimaan pada gateway yang sudah dijalankan.

Perintah ini mengirim file ke gateway dan menambah isi karantina serta brankas.
Jalankan hanya pada data demo. Kegagalan membaca file bukan bukti deteksi malware.
"""
import argparse
import hashlib
import time
from pathlib import Path

import requests


BASE = Path(__file__).resolve().parent.parent
DEMO_FILES = BASE / "demo_files"
HEADERS = {"X-Diode-Request": "1"}
HTTP_TIMEOUT = 5
TRANSFER_TIMEOUT = 30

SCENARIOS = (
    ("dokumen_operasi.pdf", "ACCEPTED", (), "Dokumen sah"),
    ("firmware_radar_v24.bin", "ACCEPTED", (), "Firmware KRTK sah"),
    ("radar_update_sah.cfg", "ACCEPTED", (), "Konfigurasi radar sah"),
    ("laporan_palsu.pdf", "REJECTED", ("FORMAT_SPOOFING_DETECTED",), "Penyamaran format"),
    ("pdf_aktif.pdf", "REJECTED", ("YARA_MATCH",), "Konten PDF aktif"),
    ("sabotase_radar.cfg", "REJECTED", ("YARA_MATCH",), "Pola sabotase radar"),
    ("gambar_polyglot.png", "REJECTED", ("STRUCTURE_INVALID",), "Polyglot PNG"),
    ("data_terinfeksi.txt", "REJECTED", ("YARA_MATCH", "MALWARE_DETECTED"), "Sampel EICAR"),
)


def get_json(url):
    response = requests.get(url, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json()


def upload(low_url, filename):
    content = (DEMO_FILES / filename).read_bytes()
    response = requests.post(
        f"{low_url}/api/upload",
        files={"file": (filename, content)},
        headers=HEADERS,
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()["job"], hashlib.sha256(content).hexdigest()


def wait_for_receipt(low_url, high_url, job_id, expected_sha, timeout=TRANSFER_TIMEOUT):
    """Cocokkan ID transfer baru dan hash, bukan hanya nama atau isi brankas lama."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = get_json(f"{low_url}/api/jobs")
        job = next((item for item in jobs if item.get("id") == job_id), None)
        if job is None:
            raise ValueError("pekerjaan tidak ditemukan di sisi luar")
        transfer = job.get("transfer", {})
        if transfer.get("state") == "failed":
            raise ValueError(f"pengiriman gagal: {transfer.get('error', 'alasan tidak tersedia')}")
        file_id = transfer.get("file_id")
        if file_id:
            vault = get_json(f"{high_url}/api/vault")
            received = next((item for item in vault if item.get("file_id") == file_id), None)
            if received:
                if received.get("sha256") != expected_sha:
                    raise ValueError("hash brankas tidak sama dengan file yang diunggah")
                return file_id
        time.sleep(0.25)
    raise TimeoutError("penerimaan di brankas belum terbukti dalam batas waktu")


def run_scenario(low_url, high_url, scenario):
    filename, expected, codes, _ = scenario
    job, source_sha = upload(low_url, filename)
    verdict = job.get("verdict")
    code = job.get("code", "")
    if verdict != expected:
        raise ValueError(f"harapan {expected}, hasil {verdict} (kode {code or '-'})")
    if codes and code not in codes:
        raise ValueError(f"ditolak dengan kode {code or '-'}, bukan {', '.join(codes)}")
    if verdict == "ACCEPTED":
        if job.get("sha256") != source_sha:
            raise ValueError("hash pemeriksaan tidak sama dengan file yang diunggah")
        file_id = wait_for_receipt(low_url, high_url, job["id"], source_sha)
        return f"diterima di brankas, ID {file_id}, SHA-256 cocok"
    return f"ditolak oleh gate ({code})"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--low-url", default="http://127.0.0.1:5000")
    parser.add_argument("--high-url", default="http://127.0.0.1:5001")
    args = parser.parse_args(argv)
    low_url, high_url = args.low_url.rstrip("/"), args.high_url.rstrip("/")

    print("KARTIKA-CDS: UJI DEMO LOKAL")
    try:
        status = get_json(f"{low_url}/api/status")
        get_json(f"{high_url}/api/live")
    except (requests.RequestException, ValueError) as exc:
        print(f"[GAGAL] Endpoint tidak dapat diperiksa: {exc}")
        return 1

    print(f"Engine aktif: YARA={status.get('yara')}, ClamAV={status.get('clamav')}; "
          f"wajib={', '.join(status.get('required', [])) or '-'}")
    if not status.get("ready"):
        print("[PERINGATAN] Engine yang diwajibkan belum siap.")

    passed = 0
    for scenario in SCENARIOS:
        filename, _, _, label = scenario
        try:
            detail = run_scenario(low_url, high_url, scenario)
        except (OSError, requests.RequestException, ValueError, KeyError, TypeError) as exc:
            print(f"[GAGAL] {label} ({filename}): {exc}")
            if filename == "data_terinfeksi.txt" and isinstance(exc, OSError) and not isinstance(exc, requests.RequestException):
                print("        File tidak terbaca; periksa karantina antivirus atau buat ulang sampel.")
        else:
            passed += 1
            print(f"[LULUS] {label} ({filename}): {detail}")

    print(f"Hasil: {passed}/{len(SCENARIOS)} skenario lulus.")
    print("Uji lokal ini tidak membuktikan isolasi fisik atau kesiapan operasional.")
    return 0 if passed == len(SCENARIOS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
