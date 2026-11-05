# KARTIKA-CDS: Unidirectional Security Gateway (Data Diode + Malware Inspection + OT Enclave)

Sistem transfer file dan patch OT/Radar satu arah dari jaringan luar (*low-side*) ke jaringan dalam terisolasi (*high-side OT enclave*).
File diperiksa secara *in-memory* (anti-TOCTOU) di sisi luar, ditandatangani secara kriptografis (Ed25519 / HMAC), dikodekan dengan **Reed-Solomon $GF(2^8)$ Erasure Coding `RS(4,2)`**, dikirim lewat UDP satu arah tanpa jalur balik, lalu diverifikasi ulang dan dimuat ke simulasi Radar OT di sisi dalam.

> **Istilah di proposal:** sebut sistem ini *Unidirectional Cross-Domain Security Gateway* atau *Software-Enforced Data Diode*.
> Lihat **`MASTER_PLAN.md`** untuk rincian lengkap arsitektur 3-Zona, ancaman yang dimitigasi, dan matriks keamanan.

## 1. Arsitektur & Keunggulan Utama

```
 [Operator Browser di Host (127.0.0.1:8000/split.html)] -- Membaca dua UI terpisah
        |                                                       |
 +------+---------------+   UDP 9999 Satu Arah (0 ACK)   +------+---------------+
 | diode-low / guard    | -----------------------------> | diode-high (OT Zone) |
 | 10.10.10.2           |   Ed25519 Sign + RS(4,2) FEC   | 10.10.10.3           |
 | Dropzone > RAM Gate  |                                | Receiver+Vault+Radar |
 +------+---------------+                                +------+---------------+
        |  veth (vl-br)                            veth (vh-br) |
        +---------------- br-diode (Host, 10.10.10.1) ----------+
               nftables (family bridge) + Static ARP + IPv6 Off DI HOST
```

### Perbaikan Menyeluruh (Gabungan KARTIKA-CDS + `diode-gateway`)
1. **Isolasi UI Sepenuhnya**: Dua server terpisah (`low_side/app.py` dan `high_side/app.py`). Tampilan berdampingan dibangun di browser operator (`demo/split.html`). UI sisi dalam 100% *read-only*.
2. **Kriptografi Asimetris Ed25519 & Dukungan 3-Zona**: Mendukung penandatanganan paket dengan **Ed25519** (`keys/guard_ed25519.priv` di sisi pengirim, `keys/guard_ed25519.pub` di sisi penerima) sehingga kompromi pada sisi penerima tidak dapat memalsukan paket. Tetap kompatibel dengan kunci simetris HMAC-SHA256 (`diode.key`).
3. **In-Memory Single-Read Inspection (Anti-TOCTOU & Anti-Symlink)**: File diunggah dengan nama acak, diperiksa `lstat` (menolak symlink/FIFO/hardlink), dibaca **1x ke RAM**, lalu langsung dihapus dari disk sebelum keenam tahap gate (Nama/Ukuran, SHA-256, Magic Bytes, Struktur/Polyglot, YARA, ClamAV `INSTREAM`) berjalan.
4. **True $GF(2^8)$ Reed-Solomon Erasure Coding `RS(4, 2)`**: Setiap 4 *chunk* data dilengkapi 2 *chunk* paritas independen (`P0` XOR dan `P1` Vandermonde $GF(256)$). Mampu memulihkan hingga **2 paket hilang dalam satu grup yang sama** pada 1 pass tanpa pengiriman ulang.
5. **Konteks Pertahanan TNI AD (OT Radar Config & Firmware Loader)**: Mendukung file `.pdf`, `.png`, `.jpg`, `.txt`, `.cfg` (Konfigurasi Parameter Radar), dan `.bin` (Image Firmware bertanda tangan `KRTK` + CRC32). File `.cfg` dan `.bin` yang lolos memperbarui telemetri Radar OT (`ot_radar_state.json`) di sisi dalam.
6. **Penegakan Diode Layer 2 di Host Bridge**: `nftables` pada level bridge host memblokir seluruh frame keluar dari `vh-br`, ARP statis permanen, IPv6 dimatikan, dan diuji otomatis oleh `scripts/verify_oneway.sh` (7 pemeriksaan).
7. **Tamper-Evident Audit Hash Chain**: Setiap catatan di `audit_low.jsonl` dan `audit_high.jsonl` mengikat hash SHA-256 baris sebelumnya (`prev`).

## 2. Cara Menjalankan

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash scripts/gen_key.sh
python3 scripts/make_demo_files.py
python3 -m pytest
```

* **Mode Pengembangan (Localhost):** `bash scripts/run_dev.sh`
* **Mode Diode Penuh (Namespaces + Bridge Firewall):**
  ```bash
  sudo bash scripts/setup_netns.sh
  sudo bash scripts/verify_oneway.sh
  sudo bash scripts/run_netns.sh start
  python3 -m http.server 8000 --bind 127.0.0.1 --directory demo
  ```
