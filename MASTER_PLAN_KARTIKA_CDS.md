# MASTER PLAN: KARTIKA-CDS (Unified Hardened Edition)
**Unidirectional Cross-Domain Security Gateway & Malware Inspection Diode**
*(Integrasi Arsitektur 3-Zona Hardened KARTIKA-CDS + Rekayasa Perangkat Lunak & Otomasi `diode-gateway`)*

---

## 1. Ringkasan Eksekutif & Tujuan Sistem
Sistem ini dirancang untuk skenario **Kartika Cyber Hackathon (TNI AD)**: pengiriman dokumen perintah operasi (`.pdf`), citra taktis (`.png`, `.jpg`), log/konfigurasi parameter radar (`.cfg`, `.txt`), dan pembaruan firmware perangkat OT/SCADA (`.bin`) dari jaringan luar yang tidak tepercaya (*Low-Side*) menuju jaringan dalam terisolasi (*High-Side OT Enclave*) secara **satu arah tanpa jalur balik (0-byte back-channel)**.

---

## 2. Matriks Penutupan Celah Keamanan (Visible & Unseen Vulnerabilities)

| No | Celah Keamanan / Kritik | Solusi Implementasi pada KARTIKA-CDS Unified |
| :--- | :--- | :--- |
| **1** | **Dashboard menembus Diode** (Server luar membaca log sisi dalam) | Dua aplikasi web terpisah sepenuhnya (`low_side/app.py` di `:5000` dan `high_side/app.py` di `:5001`). Tampilan berdampingan disajikan murni di browser operator melalui `demo/split.html`. Server High-Side bersifat *100% Read-Only*. |
| **2** | **Path Traversal (`../../`)** pada nama file di Header UDP | Receiver mengabaikan nama file asli saat menyimpan ke disk. File disimpan sebagai `<file_id_hex><ext>` dengan izin `0400` (*read-only*). Nama asli disanitasi ketat (`sanitize_name`) hanya untuk label di metadata & log audit. |
| **3** | **Jalur UDP tanpa autentikasi & risiko kompromi Web UI** | **Kriptografi Asimetris Ed25519 per paket** (mode default) + **Isolasi 3-Zona (`diode-dropzone`, `diode-guard`, `diode-high`)**. Web UI di Zona 1 tidak memegang kunci privat dan tidak punya rute ke High-Side. Hanya `guard_daemon` di Zona 2 yang memegang `guard_ed25519.priv`, sedangkan `udp_receiver` di Zona 3 hanya memegang `guard_ed25519.pub`. |
| **4** | **`iptables` di dalam node dalam & kebocoran ARP Layer 2** | Penegakan satu arah dipasang di **Host Bridge (`br-diode`)** menggunakan `nftables` (`family bridge`) dengan policy `drop`. Node dalam tidak dapat menghapus aturan host. ARP dikunci statis (`nud permanent`), `arp off` di antarmuka penerima, dan IPv6 dimatikan (`disable_ipv6=1`). |
| **5** | **Celah TOCTOU (*Time-of-Check to Time-of-Use*) & Symlink Attack** | Saat `Gate.inspect_and_extract()` memeriksa file, sistem mengecek `os.lstat` (menolak symlink, FIFO, atau hardlink), membaca seluruh byte file **satu kali saja ke buffer RAM (`bytes`)**, lalu segera menghapus file spool dari disk (`unlink`). Seluruh 6 tahap pemeriksaan (Nama/Ukuran, SHA-256, Magic Bytes, Struktur/Polyglot, YARA, ClamAV `INSTREAM`) dan pengiriman UDP bekerja murni dari buffer RAM tersebut. |
| **6** | **Klaim "FEC" palsu (hanya replikasi)** | Mengimplementasikan **True Galois Field $GF(2^8)$ Reed-Solomon / Vandermonde Erasure Coding `RS(4, 2)`**. Setiap grup 4 *data chunks* dilengkapi 2 *parity chunks* (`P0` XOR & `P1` Vandermonde $GF(256)$). Mampu memulihkan kehilangan **hingga 2 paket per grup (33% erasure)** hanya dalam 1 pass tanpa ACK, ditambah *multi-pass interleaving*. |
| **7** | **Replay Attack & Firmware Downgrade** | Header menyertakan `ts` (jendela waktu anti-replay) dan **Monotonic `epoch_ms`** yang disimpan permanen di `state_epoch.json` serta pemulihan daftar `file_id` dari `audit_high.jsonl`. |
| **8** | **Polyglot File & Active PDF Exploit** | Pemeriksaan struktur mendalam (`common/filetype.py`) memvalidasi CRC tiap chunk PNG, mendeteksi byte sisipan setelah `IEND`/`%%EOF`/`FFD9`, memvalidasi header firmware `KRTK` beserta CRC32-nya, serta aturan YARA mendeteksi `/JavaScript`, `/Launch`, PowerShell, dan sabotase OT/Modbus. |
| **9** | **Manipulasi Log Audit (*Log Tampering*)** | `common/audit.py` menggunakan struktur **Tamper-Evident Hash Chain** (`prev` = SHA-256 baris sebelumnya) yang diverifikasi secara real-time di UI kedua sisi. |

---

## 3. Topologi 3-Zona & Alur Kerja

```text
[ Browser Operator di Host (127.0.0.1:8000/split.html) ]
       | (Baca UI Luar :5000)                           | (Baca UI Dalam :5001)
       v                                                v
+----------------------+   Spool Antrean   +--------------------------+
| ZONA 1: Dropzone UI  | ----------------> | ZONA 2: Security Guard   |
| - low_side/app.py    | (Tarik 1x ke RAM  | - gate_inspector.py (RAM)|
| - Tanpa Kunci Privat |  & hapus spool)   | - udp_sender.py          |
| - Tanpa Rute ke High |                   | - Kunci Ed25519 Private  |
+----------------------+                   +------------+-------------+
                                                        |
                                           UDP 9999 Satu Arah (Ed25519 + RS(4,2) FEC)
                                                        |
       =================================================+========================
       HOST BRIDGE (br-diode) - nftables family bridge (DROP semua arah balik L2)
       - Static ARP, IPv6 OFF, Forwarding OFF, Terverifikasi oleh verify_oneway.sh
       =================================================+========================
                                                        |
                                                        v
                                           +--------------------------+
                                           | ZONA 3: High-Side OT     |
                                           | - udp_receiver.py        |
                                           | - Kunci Ed25519 Public   |
                                           | - Revalidasi Struktur    |
                                           | - OT Radar State Loader  |
                                           | - high_side/app.py (:5001)|
                                           +--------------------------+
```

---

## 4. Tahapan Eksekusi & Pengujian Lengkap

1. **Persiapan Lingkungan & Kunci Kriptografi:**
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   bash scripts/gen_key.sh
   python3 scripts/make_demo_files.py
   ```
2. **Menjalankan Suite Pengujian Otomatis (`pytest`):**
   ```bash
   python3 -m pytest
   ```
3. **Menjalankan Simulasi Ketahanan Packet Loss Tanpa Jaringan:**
   ```bash
   python3 scripts/loss_simulation.py
   ```
4. **Menjalankan Mode Produksi / Demo Juri (Network Namespaces + nftables Bridge):**
   ```bash
   sudo bash scripts/setup_netns.sh
   sudo bash scripts/verify_oneway.sh      # Membuktikan 7/7 tes isolasi satu arah LULUS
   sudo bash scripts/run_netns.sh start
   python3 -m http.server 8000 --bind 127.0.0.1 --directory demo
   ```
5. **Simulasi Gangguan Jaringan Ekstrem (15% Packet Loss Tanpa ACK):**
   ```bash
   sudo bash scripts/loss_demo.sh on 15
   # Unggah file melalui UI http://10.10.10.2:5000 dan amati pemulihan FEC RS(4,2) di http://10.10.10.3:5001
   sudo bash scripts/loss_demo.sh off
   ```
