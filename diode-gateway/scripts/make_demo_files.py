"""Membuat file uji lengkap untuk demo juri di folder demo_files/.
Mencakup file dokumen/citra, paket konfigurasi Radar OT (.cfg), paket Firmware KRTK (.bin),
serta berbagai sampel serangan (spoofing, polyglot, EICAR, PDF aktif, sabotase OT YARA).
"""
import random
import struct
import sys
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "demo_files"


def png(w=64, h=64, extra=b""):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"".join(bytes((x * 4 % 256, y * 4 % 256, 160)) for x in range(w)) for y in range(h))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
        + extra
    )


def pdf(extra_obj=b"", pages_text=60):
    rnd = random.Random(7)
    words = "operasi logistik pengamanan jaringan laporan harian satuan evaluasi koordinasi".split()
    text = b"\n".join(b"% " + " ".join(rnd.choice(words) for _ in range(12)).encode() for _ in range(pages_text * 6))
    return (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
        + extra_obj
        + text
        + b"\ntrailer\n<< /Root 1 0 R /Size 4 >>\nstartxref\n0\n%%EOF\n"
    )


def krtk_firmware(major=2, minor=4, payload=b"KARTIKA-RADAR-DSP-FIRMWARE-IMAGE-V2.4-VERIFIED" * 80):
    hdr = struct.pack(">4sHHI", b"KRTK", major, minor, len(payload))
    body = hdr + payload
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack(">I", crc)


def main():
    OUT.mkdir(exist_ok=True)
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
    files = {
        "dokumen_operasi.pdf": pdf(),
        "gambar_normal.png": png(),
        "radar_update_sah.cfg": (
            b"# KONFIGURASI PARAMETER RADAR ARHANUD KARTIKA\n"
            b"SWEEP_FREQ_MHZ=2920\n"
            b"FIRMWARE_PROFILE=v2.4.0-TACTICAL\n"
            b"GAIN_DB=42\n"
        ),
        "firmware_radar_v24.bin": krtk_firmware(2, 4),
        "laporan_palsu.pdf": b"MZ" + bytes(300),                      # bukan PDF: berawalan MZ (PE EXE)
        "data_terinfeksi.txt": eicar,                                 # terdeteksi YARA & ClamAV
        "skrip_mencurigakan.txt": (
            b"# FILE UJI DETEKSI\n"
            b"powershell -enc AAAA\n"
            b"cmd.exe /c echo uji\n"
        ),
        "sabotase_radar.cfg": (
            b"# UJI DETEKSI YARA SABOTASE OT\n"
            b"SWEEP_FREQ_MHZ=2900\n"
            b"DISABLE_RADAR_INTERLOCK=1\n"
            b"MODBUS_FORCE_COIL_RESET=TRUE\n"
        ),
        "pdf_aktif.pdf": pdf(
            b"4 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
        ),
        "gambar_polyglot.png": png(extra=b"MZ" + bytes(120)),          # data disisipkan setelah IEND
        "skrip_uji.ps1": b"Write-Host 'uji ekstensi'\n",
    }
    for name, data in files.items():
        (OUT / name).write_bytes(data)
        print(f"{name:26} {len(data):>7} byte")
    print(f"\nTersimpan di {OUT}")


if __name__ == "__main__":
    sys.exit(main())
