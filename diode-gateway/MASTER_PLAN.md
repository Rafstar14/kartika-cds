# MASTER PLAN: KARTIKA-CDS (Unified Hardened Edition)
**Unidirectional Cross-Domain Security Gateway & Malware Inspection Diode**
*(Integrasi Arsitektur 3-Zona Hardened KARTIKA-CDS + Rekayasa Perangkat Lunak & Otomasi `diode-gateway`)*

> **Status dokumen:** rencana arsitektur, bukan bukti seluruh kontrol sudah tercapai. Implementasi demo saat ini memakai localhost, menyimpan unggahan sementara di disk, dan menampilkan radar simulasi. Topologi Linux harus diuji pada lingkungan target; tidak ada jaminan isolasi fisik atau kesiapan operasional. Rincian kondisi saat ini ada di README utama.

---

## 1. Ringkasan Eksekutif & Tujuan Sistem
Sistem ini dirancang untuk skenario **Kartika Cyber Hackathon (TNI AD)**: pemeriksaan dan pengiriman dokumen, citra, konfigurasi, dan contoh firmware dari sisi luar ke sisi dalam. Pengirim UDP tidak menunggu ACK; pemisahan jaringan harus dibuktikan terpisah dari demo localhost.

---

## 2. Matriks Penutupan Celah Keamanan (Visible & Unseen Vulnerabilities)

| No | Celah Keamanan / Kritik | Rencana dan status pada prototipe |
| :--- | :--- | :--- |
| **1** | **Dashboard menembus Diode** (Server luar membaca log sisi dalam) | Dua aplikasi web terpisah sepenuhnya (`low_side/app.py` di `:5000` dan `high_side/app.py` di `:5001`). Tampilan berdampingan disajikan murni di browser operator melalui `demo/split.html`. Server High-Side bersifat *100% Read-Only*. |
| **2** | **Path Traversal (`../../`)** pada nama file di Header UDP | Receiver menyimpan file sebagai `<file_id_hex><ext>` dan menyanitasi nama untuk metadata; izin file yang disimpan adalah `0600` jika didukung sistem. |
| **3** | **Jalur UDP tanpa autentikasi & risiko kompromi Web UI** | Paket diautentikasi memakai Ed25519 atau HMAC. Pemisahan dropzone dan guard menjadi proses dengan batas kunci yang berbeda adalah sasaran desain; launcher demo menjalankan gate dan pengirim bersama aplikasi sisi luar. Isi paket tidak dienkripsi. |
| **4** | **`iptables` di dalam node dalam & kebocoran ARP Layer 2** | Skrip menyediakan topologi bridge dan aturan `nftables` untuk membatasi lalu lintas. Jalankan `verify_oneway.sh` pada host uji untuk memperoleh hasil pada lingkungan tersebut. |
| **5** | **Celah TOCTOU (*Time-of-Check to Time-of-Use*) & Symlink Attack** | Gate memeriksa tipe file dan membaca spool ke RAM untuk sebagian pemeriksaan. ClamAV dan pengirim membaca ulang spool; pengirim memeriksa ulang SHA-256 sebelum transmisi. File yang ditolak dikarantina, file yang diterima dihapus setelah upaya kirim. Ini bukan jaminan penghapusan sebelum pemeriksaan atau pemeriksaan seluruhnya di RAM. |
| **6** | **Klaim "FEC" palsu (hanya replikasi)** | Mengimplementasikan **True Galois Field $GF(2^8)$ Reed-Solomon / Vandermonde Erasure Coding `RS(4, 2)`**. Setiap grup 4 *data chunks* dilengkapi 2 *parity chunks* (`P0` XOR & `P1` Vandermonde $GF(256)$). Mampu memulihkan kehilangan **hingga 2 paket per grup (33% erasure)** hanya dalam 1 pass tanpa ACK, ditambah *multi-pass interleaving*. |
| **7** | **Replay Attack & Firmware Downgrade** | Header memiliki pemeriksaan jendela waktu, dan sebagian `file_id` yang selesai dipulihkan dari audit saat startup. File `state_epoch.json` dicatat, tetapi epoch monoton untuk mencegah downgrade belum ditegakkan. |
| **8** | **Polyglot File & Active PDF Exploit** | Pemeriksaan struktur mendalam (`common/filetype.py`) memvalidasi CRC tiap chunk PNG, mendeteksi byte sisipan setelah `IEND`/`%%EOF`/`FFD9`, memvalidasi header firmware `KRTK` beserta CRC32-nya, serta aturan YARA mendeteksi `/JavaScript`, `/Launch`, PowerShell, dan sabotase OT/Modbus. |
| **9** | **Manipulasi Log Audit (*Log Tampering*)** | `common/audit.py` menggunakan struktur **Tamper-Evident Hash Chain** (`prev` = SHA-256 baris sebelumnya) yang diverifikasi secara real-time di UI kedua sisi. |

---

## 3. Topologi 3-Zona yang Direncanakan

Diagram ini menggambarkan sasaran arsitektur, bukan pemisahan proses atau kunci yang dibuktikan oleh launcher demo. Pada demo, gate dan pengirim berjalan dalam aplikasi sisi luar, dan spool tidak dihapus sebelum pemeriksaan.

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
       - Static ARP, IPv6 OFF, Forwarding OFF, perlu diuji dengan verify_oneway.sh
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
4. **Menguji Topologi Linux (Network Namespaces + nftables Bridge):**
   ```bash
   sudo bash scripts/setup_netns.sh
   sudo bash scripts/verify_oneway.sh      # Periksa hasil pada host uji
   sudo bash scripts/run_netns.sh start
   python3 -m http.server 8000 --bind 127.0.0.1 --directory demo
   ```
5. **Simulasi Gangguan Jaringan Ekstrem (15% Packet Loss Tanpa ACK):**
   ```bash
   sudo bash scripts/loss_demo.sh on 15
   # Unggah file melalui UI http://10.10.10.2:5000 dan amati pemulihan FEC RS(4,2) di http://10.10.10.3:5001
   sudo bash scripts/loss_demo.sh off
   ```
