"""KARTIKA-CDS: Development & Demo Server Launcher (Cross-Platform / Windows & Linux)
Menjalankan seluruh layanan KARTIKA-CDS secara otomatis:
  - High-Side UDP Receiver (UDP 9999)
  - High-Side Read-Only OT Dashboard (HTTP 5001)
  - Low-Side Ingest & RAM Security Gate Dashboard (HTTP 5000)
  - Split-View Out-of-Band Observer (HTTP 8000)
"""
import os
import sys
import time
import subprocess
import signal
from pathlib import Path

BASE = Path(__file__).resolve().parent
PYTHON = sys.executable

def main():
    os.chdir(BASE)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["DIODE_RX_HOST"] = "127.0.0.1"
    os.environ["DIODE_RX_BIND"] = "127.0.0.1"
    os.environ["LOW_UI_HOST"] = "127.0.0.1"
    os.environ["LOW_UI_PORT"] = "5000"
    os.environ["HIGH_UI_HOST"] = "127.0.0.1"
    os.environ["HIGH_UI_PORT"] = "5001"

    # Periksa ClamAV atau fallback ke YARA
    if "DIODE_REQUIRE_ENGINES" not in os.environ:
        try:
            sys.path.insert(0, str(BASE))
            from low_side.gate_inspector import ClamEngine
            if ClamEngine().available():
                os.environ["DIODE_REQUIRE_ENGINES"] = "yara,clamav"
            else:
                os.environ["DIODE_REQUIRE_ENGINES"] = "yara"
                print("[*] clamd tidak terdeteksi. Berjalan dalam mode proteksi YARA.")
        except Exception:
            os.environ["DIODE_REQUIRE_ENGINES"] = "yara"

    # Buat direktori data jika belum ada
    for d in ("run", "data/low/dropzone", "data/low/quarantine", "data/high/secure_vault", "data/high/staging", "keys"):
        (BASE / d).mkdir(parents=True, exist_ok=True)

    processes = []

    def cleanup(signum=None, frame=None):
        print("\n[*] Menghentikan seluruh komponen KARTIKA-CDS...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        for p in processes:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print("[+] Semua layanan dihentikan.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print("=" * 70)
    print(" KARTIKA-CDS: Unidirectional Security Gateway (Unified Hardened)")
    print("=" * 70)

    # 1. Receiver UDP High-Side
    p_rx = subprocess.Popen([PYTHON, "-m", "high_side.udp_receiver"], cwd=BASE)
    processes.append(p_rx)
    time.sleep(0.5)

    # 2. Web UI High-Side (:5001)
    p_high = subprocess.Popen([PYTHON, "-m", "high_side.app"], cwd=BASE)
    processes.append(p_high)

    # 3. Web UI Low-Side (:5000)
    p_low = subprocess.Popen([PYTHON, "-m", "low_side.app"], cwd=BASE)
    processes.append(p_low)
    time.sleep(0.5)

    # 4. Web UI Split-View Observer (:8000)
    p_demo = subprocess.Popen([PYTHON, "-m", "http.server", "8000", "--bind", "127.0.0.1", "--directory", "demo"], cwd=BASE)
    processes.append(p_demo)

    print("\n[*] Proses demo dijalankan. Periksa status layanan pada alamat berikut:")
    print("    • Sisi Luar (Low-Side Dropzone & Gate) : http://127.0.0.1:5000")
    print("    • Sisi Dalam (High-Side OT Radar Enclave): http://127.0.0.1:5001")
    print("    • Split-View Juri (Observer)            : http://127.0.0.1:8000/split.html")
    print("    • UDP Gateway                           : 127.0.0.1:9999 (tanpa ACK; mode localhost)")
    print("\n[*] Sampel file demo siap digunakan di folder: diode-gateway/demo_files/")
    print("[*] Tekan Ctrl+C untuk menghentikan seluruh layanan.\n")

    try:
        while True:
            for p in processes:
                if p.poll() is not None:
                    print(f"[!] Proses {p.args} terhenti dengan kode {p.returncode}")
                    cleanup()
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
