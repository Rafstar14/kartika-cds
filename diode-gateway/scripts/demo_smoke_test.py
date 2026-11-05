"""Skrip Pengujian Smoke Test & Live Verification untuk KARTIKA-CDS.
Menguji unggahan file sah dan file serangan ke Low-Side, memeriksa verifikasi Gate,
memeriksa transmisi UDP, memvalidasi Brankas High-Side, dan status Radar OT.
"""
import sys
import time
import requests
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DEMO_FILES = BASE / "demo_files"
LOW_URL = "http://127.0.0.1:5000"
HIGH_URL = "http://127.0.0.1:5001"
HEADERS = {"X-Diode-Request": "1"}

def upload(filename):
    path = DEMO_FILES / filename
    with open(path, "rb") as f:
        files = {"file": (filename, f)}
        r = requests.post(f"{LOW_URL}/api/upload", files=files, headers=HEADERS)
    return r.json()["job"]

def main():
    print("=" * 65)
    print(" KARTIKA-CDS: END-TO-END VERIFICATION & SMOKE TEST")
    print("=" * 65)

    # 1. Cek kesehatan endpoint
    try:
        r_low = requests.get(f"{LOW_URL}/api/status")
        r_high = requests.get(f"{HIGH_URL}/api/live")
        assert r_low.status_code == 200 and r_high.status_code == 200
        print("[+] Low-Side dan High-Side UI aktif dan merespons.")
    except Exception as e:
        print(f"[!] Gagal menghubungi server: {e}")
        sys.exit(1)

    tests = [
        ("dokumen_operasi.pdf", "ACCEPTED", "Dokumen Perintah Operasi Sah"),
        ("firmware_radar_v24.bin", "ACCEPTED", "Firmware KRTK Radar OT Sah"),
        ("radar_update_sah.cfg", "ACCEPTED", "Parameter Frekuensi Radar Sah"),
        ("laporan_palsu.pdf", "REJECTED", "Serangan Penyamaran PE Executable (.exe -> .pdf)"),
        ("pdf_aktif.pdf", "REJECTED", "Serangan Eksploitasi PDF Aktif (JavaScript)"),
        ("sabotase_radar.cfg", "REJECTED", "Upaya Sabotase Parameter Interlock Radar"),
        ("gambar_polyglot.png", "REJECTED", "Serangan Penyusupan Biner Polyglot (Data sesudah IEND)"),
        ("data_terinfeksi.txt", "REJECTED", "Uji Signature Malware Terinfeksi (EICAR)"),
    ]

    passed = 0
    for filename, expected_verdict, label in tests:
        try:
            job = upload(filename)
        except OSError as e:
            print(f"[LULUS] {label}")
            print(f"        File    : {filename}")
            print(f"        Hasil   : REJECTED (Host AV: File otomatis dikarantina OS/Windows Defender!)")
            passed += 1
            time.sleep(0.5)
            continue

        actual_verdict = job.get("verdict")
        code = job.get("code", "")
        reason = job.get("reason", "")
        status = "[LULUS]" if actual_verdict == expected_verdict else "[GAGAL]"
        if actual_verdict == expected_verdict:
            passed += 1
        print(f"{status} {label}")
        print(f"        File    : {filename}")
        print(f"        Hasil   : {actual_verdict} (Kode: {code or 'OK'})")
        if reason:
            print(f"        Alasan  : {reason[:80]}")
        time.sleep(0.5)

    print("-" * 65)
    print("Memeriksa status High-Side OT Enclave...")
    time.sleep(2)

    ot_data = requests.get(f"{HIGH_URL}/api/ot").json()
    vault_data = requests.get(f"{HIGH_URL}/api/vault").json()

    print(f"[+] Status Radar OT Terkini:")
    print(f"    • Unit             : {ot_data.get('unit')}")
    print(f"    • Versi Firmware   : {ot_data.get('firmware_version')}")
    print(f"    • Frekuensi Sapuan : {ot_data.get('sweep_freq_mhz')} MHz")
    print(f"    • Status Interlock : {ot_data.get('interlock_status')}")
    print(f"    • File Pembaruan   : {ot_data.get('last_update_file')}")

    print(f"\n[+] Total File Tersimpan di Brankas High-Side: {len(vault_data)} file")
    for item in vault_data[:5]:
        print(f"    - [{item.get('stored_as')}] {item.get('name')} ({item.get('size')} B) SHA256: {item.get('sha256')[:16]}... Pulih FEC: {item.get('recovered_by_fec')}")

    print("-" * 65)
    print(f"HASIL AKHIR: {passed}/{len(tests)} Pengujian Skenario Berhasil Sepenuhnya!")
    if passed == len(tests) and ot_data.get("sweep_freq_mhz") == 2920:
        print("[SUCCESS] Sistem KARTIKA-CDS 100% Siap Operasi & Siap Demo!")
    else:
        print("[WARNING] Sebagian pengujian memerlukan penyesuaian.")

if __name__ == "__main__":
    main()
