<div align="center">

# 🛡️ KARTIKA-CDS

### Unidirectional Cross-Domain Security Gateway & Malware Inspection Diode

**Dirancang untuk Kartika Cyber Hackathon — TNI Angkatan Darat**

*Transfer file satu arah tanpa jalur balik (0-byte back-channel) dari jaringan tidak tepercaya menuju jaringan Radar OT terisolasi, dengan pemeriksaan keamanan 6 tahap secara in-memory.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask)](#)
[![Ed25519](https://img.shields.io/badge/Crypto-Ed25519-green)](#)
[![Reed Solomon](https://img.shields.io/badge/FEC-Reed--Solomon%20RS(4%2C2)-blue)](#)
[![Tests](https://img.shields.io/badge/Tests-30%20Passed-brightgreen)](#pengujian)

</div>

---

## 📋 Daftar Isi

- [Tentang Proyek](#tentang-proyek)
- [Arsitektur Sistem](#arsitektur-sistem)
- [Fitur Keamanan](#fitur-keamanan)
- [Prasyarat](#prasyarat)
- [Instalasi & Setup](#instalasi--setup)
- [Menjalankan Sistem](#menjalankan-sistem)
- [Pengujian & Demo](#pengujian--demo)
- [Struktur Direktori](#struktur-direktori)
- [Tampilan Antarmuka](#tampilan-antarmuka)
- [Dokumentasi Teknis](#dokumentasi-teknis)
- [Lisensi](#lisensi)

---

## Tentang Proyek

**KARTIKA-CDS (Cross-Domain Security)** adalah sistem gerbang keamanan satu arah (*data diode*) yang dirancang untuk skenario pertahanan siber TNI AD. Sistem ini memungkinkan pengiriman:

| Jenis File | Ekstensi | Keterangan |
|---|---|---|
| Dokumen perintah operasi | `.pdf` | Perintah dan laporan taktis |
| Citra taktis | `.png`, `.jpg` | Peta situasi dan foto intelijen |
| Konfigurasi parameter radar | `.cfg`, `.txt` | Frekuensi sapuan, interlock, dan parameter operasional |
| Firmware perangkat OT/SCADA | `.bin` | Pembaruan biner bertanda tangan `KRTK` dengan CRC32 |

dari **jaringan luar yang tidak tepercaya (Low-Side)** menuju **jaringan dalam terisolasi (High-Side OT Radar Enclave)** secara satu arah, **tanpa jalur balik sama sekali (0-byte back-channel)**.

---

## Arsitektur Sistem

```
 [ Browser Operator di Host (127.0.0.1:8000/split.html) ]
         |                                                |
   Baca UI Sisi Luar (:5000)                    Baca UI Sisi Dalam (:5001)
         v                                                v
+-------------------------+                   +--------------------------+
| ZONA 1: Dropzone UI    |   Spool 1x ke    | ZONA 2: Security Guard   |
| - low_side/app.py      |   buffer RAM      | - gate_inspector.py      |
| - Tanpa kunci privat   | ←── lalu hapus ──→| - udp_sender.py          |
| - Tanpa rute ke High   |   dari disk       | - Kunci Ed25519 Private  |
+-------------------------+                   +------------+-------------+
                                                           |
                                      UDP 9999 Satu Arah (Ed25519 + RS(4,2) FEC)
                                                           |
     ═══════════════════════════════════════════════════════+═══════
     HOST BRIDGE (br-diode) - nftables family bridge DROP semua arah balik L2
     Static ARP │ IPv6 OFF │ Forwarding OFF │ Diverifikasi verify_oneway.sh
     ═══════════════════════════════════════════════════════+═══════
                                                           |
                                                           v
                                              +--------------------------+
                                              | ZONA 3: High-Side OT    |
                                              | - udp_receiver.py (RX)  |
                                              | - Kunci Ed25519 Public  |
                                              | - Brankas secure_vault/ |
                                              | - Simulator Radar OT    |
                                              +--------------------------+
```

---

## Fitur Keamanan

### Pipeline Pemeriksaan 6 Tahap (Berjalan Murni di RAM)

| # | Tahap | Fungsi |
|---|---|---|
| 1 | **Nama & Ukuran** | Validasi ekstensi file yang diizinkan, batas maksimum 10 MB, sanitasi nama file terhadap path traversal (`../../`) |
| 2 | **SHA-256** | Penghitungan hash integritas untuk pencatatan audit dan deteksi duplikasi |
| 3 | **Tanda Tangan File (Magic Bytes)** | Deteksi format spoofing: file `.exe` yang disamarkan sebagai `.pdf` akan tertolak |
| 4 | **Pemeriksaan Struktur & Anti-Polyglot** | Validasi CRC tiap chunk PNG, deteksi sisipan data setelah `IEND`/`%%EOF`/`FFD9`, validasi header firmware `KRTK` + CRC32 |
| 5 | **Aturan YARA** | Deteksi `/JavaScript`, `/Launch` dalam PDF, pola PowerShell, dan sabotase parameter OT/Modbus |
| 6 | **ClamAV (INSTREAM)** | Pemindaian malware murni dari buffer RAM tanpa menyentuh disk |

### Fitur Keamanan Tambahan

- **Ed25519 Kriptografi Asimetris**: Setiap paket UDP ditandatangani secara kriptografis
- **Reed-Solomon RS(4,2) Forward Error Correction**: Mampu memulihkan kehilangan hingga 2 paket per grup (33% erasure) tanpa memerlukan ACK
- **Anti-Replay & Anti-Downgrade**: Monotonic epoch timestamp dan jendela waktu anti-replay
- **Tamper-Evident Hash Chain Audit Log**: Setiap catatan audit mengikat hash SHA-256 baris sebelumnya
- **Anti-TOCTOU**: File dibaca 1x ke RAM lalu segera dihapus dari disk sebelum pemeriksaan

---

## Prasyarat

| Komponen | Versi Minimum | Keterangan |
|---|---|---|
| **Python** | 3.10+ | Tersedia di [python.org](https://www.python.org/downloads/) |
| **pip** | Terbaru | Biasanya sudah termasuk dengan Python |
| **Git** | Terbaru | Untuk meng-clone repository ini |

### Opsional (untuk fitur penuh)

| Komponen | Keterangan |
|---|---|
| **ClamAV + clamd** | Untuk tahap pemindaian malware (tahap ke-6). Tanpa ClamAV, sistem tetap berjalan dalam mode YARA-only |
| **libmagic** | Untuk pemeriksaan magic bytes tingkat lanjut. Tanpa ini, sistem menggunakan deteksi bawaan |

---

## Instalasi & Setup

### 1. Clone Repository

```bash
git clone https://github.com/Rafstar14/kartika-cds.git
cd kartika-cds/diode-gateway
```

### 2. Buat Virtual Environment & Install Dependensi

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Catatan Windows:** Jika mendapat error `Execution Policy`, jalankan terlebih dahulu:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 3. Generate Kunci Kriptografi

**Cross-platform (disarankan):**
```bash
python scripts/gen_key.py
```

**Linux / macOS (alternatif):**
```bash
bash scripts/gen_key.sh
```

### 4. Generate File Demo untuk Pengujian

```bash
python scripts/make_demo_files.py
```

File demo akan tersimpan di folder `demo_files/` berisi:
- File sah: `dokumen_operasi.pdf`, `radar_update_sah.cfg`, `firmware_radar_v24.bin`, `gambar_normal.png`
- File serangan: `laporan_palsu.pdf` (exe tersembunyi), `pdf_aktif.pdf` (JavaScript), `sabotase_radar.cfg`, `gambar_polyglot.png`

---

## Menjalankan Sistem

### ⚡ Cara Tercepat: Perintah Instan `kartika`

Setelah instalasi selesai, cukup ketik **satu perintah** di terminal dari folder mana saja:

**Windows (Command Prompt / PowerShell):**
```cmd
kartika
```

**Linux / macOS:**
```bash
./kartika
```

**Atau jika sudah install via pip:**
```bash
kartika
```

Menu interaktif berikut akan langsung muncul di terminal:

```
======================================================================
Choose Interface (v2.0-Hardened)
🚀 Server: http://127.0.0.1:8000 (Stopped)
======================================================================

 > Web UI (Open in Browser)
   Terminal UI (Interactive CLI)
   Run Live Smoke Test
   FEC Loss Simulation
   Check Gateway Status
   Stop Gateway Services
   Exit
```

Navigasikan pilihan menggunakan **tombol panah atas/bawah** pada keyboard, lalu tekan **Enter** untuk memilih:

| Pilihan Menu | Fungsi |
|---|---|
| **Web UI (Open in Browser)** | Menyalakan gateway di latar belakang & otomatis membuka split-view di browser |
| **Terminal UI (Interactive CLI)** | Pemantauan status radar OT, brankas file, dan port secara real-time di terminal |
| **Run Live Smoke Test** | Pengujian otomatis 8 skenario serangan & file sah TNI AD |
| **FEC Loss Simulation** | Simulasi ketahanan paket loss dengan Reed-Solomon RS(4,2) |
| **Check Gateway Status** | Pemeriksaan kesehatan port (5000, 5001, 8000, 9999) & kunci kriptografi |
| **Stop Gateway Services** | Menghentikan semua proses server di latar belakang |
| **Exit** | Keluar dari launcher |

Setelah memilih **Web UI**, browser Anda akan otomatis terbuka ke:

| Layanan | URL | Fungsi |
|---|---|---|
| **Split-View Observer** | http://127.0.0.1:8000/split.html | Tampilan berdampingan kedua sisi untuk demo / presentasi juri |
| **Sisi Luar (Low-Side)** | http://127.0.0.1:5000 | Dashboard upload, dropzone, dan pemeriksaan 6 tahap |
| **Sisi Dalam (High-Side)** | http://127.0.0.1:5001 | Brankas file terverifikasi, telemetri radar OT, dan audit log |
| **UDP Simplex Gateway** | 127.0.0.1:9999 | Transfer data satu arah (0-byte back-channel) |

### Mode Diode Penuh (Linux dengan Network Namespaces)

Untuk menjalankan dengan isolasi jaringan fisik sesungguhnya menggunakan Linux network namespaces dan nftables bridge firewall:

```bash
sudo bash scripts/setup_netns.sh       # Buat topologi jaringan 3-zona
sudo bash scripts/verify_oneway.sh     # Verifikasi isolasi satu arah (7 pengujian)
sudo bash scripts/run_netns.sh start   # Jalankan semua layanan di namespace masing-masing
python3 -m http.server 8000 --bind 127.0.0.1 --directory demo  # Split-view observer
```

---

## Pengujian & Demo

### Menjalankan Unit Test (30 Test Cases)

```bash
python -m pytest
```

Pengujian mencakup:
- CSRF header enforcement
- File rejection & quarantine flow
- Format spoofing detection (PE as PDF)
- Firmware CRC validation
- Symlink & path traversal blocking
- Polyglot file detection
- YARA rule matching (active PDF, OT sabotage)
- ClamAV detection
- Fail-closed gate behavior
- Ed25519 & HMAC crypto roundtrip
- Reed-Solomon RS(4,2) erasure recovery
- Tamper-evident audit chain
- High-side read-only enforcement

### Menjalankan Demo End-to-End (8 Skenario Serangan)

```bash
python scripts/demo_smoke_test.py
```

Skrip ini menjalankan 8 skenario pengujian otomatis:

| # | Skenario | File | Hasil yang Diharapkan |
|---|---|---|---|
| 1 | Dokumen perintah operasi sah | `dokumen_operasi.pdf` | ACCEPTED |
| 2 | Firmware radar OT sah | `firmware_radar_v24.bin` | ACCEPTED |
| 3 | Parameter frekuensi radar sah | `radar_update_sah.cfg` | ACCEPTED |
| 4 | Penyamaran executable | `laporan_palsu.pdf` | REJECTED: FORMAT_SPOOFING |
| 5 | Eksploitasi PDF aktif (JavaScript) | `pdf_aktif.pdf` | REJECTED: YARA_MATCH |
| 6 | Sabotase parameter radar | `sabotase_radar.cfg` | REJECTED: YARA_MATCH |
| 7 | Penyusupan polyglot PNG | `gambar_polyglot.png` | REJECTED: STRUCTURE_INVALID |
| 8 | Signature malware (EICAR) | `data_terinfeksi.txt` | REJECTED: AV Detection |

---

## Struktur Direktori

```
kartika-cds/
├── MASTER_PLAN_KARTIKA_CDS.md        # Rencana arsitektur induk (Bahasa Indonesia)
├── PRD_KARTIKA_CDS_Unified_Hardened_Edition.md  # Product Requirements Document
│
└── diode-gateway/                     # Implementasi inti
    ├── run_dev.py                     # Server launcher (cross-platform)
    ├── cli.py                         # Command-line interface
    ├── requirements.txt               # Dependensi Python
    ├── pytest.ini                     # Konfigurasi pytest
    │
    ├── common/                        # Modul bersama kedua sisi
    │   ├── config.py                  # Konfigurasi & konstanta sistem
    │   ├── protocol.py                # Protokol UDP, Ed25519/HMAC, Reed-Solomon RS(4,2)
    │   ├── filetype.py                # Deteksi tipe file, anti-polyglot, validasi firmware
    │   ├── audit.py                   # Tamper-evident hash chain logging
    │   ├── web.py                     # HTTP security hardening (CSP, CORS, etc.)
    │   └── static/
    │       └── diode.css              # Tactical Emerald Military Command Center UI
    │
    ├── low_side/                      # Zona 1-2: Sisi Luar (Dropzone + Security Gate)
    │   ├── app.py                     # Flask web server sisi luar (:5000)
    │   ├── gate_inspector.py          # Pipeline pemeriksaan 6 tahap (in-memory)
    │   ├── guard_daemon.py            # Guard daemon proses inspeksi & penandatanganan
    │   ├── udp_sender.py              # Pengirim UDP satu arah + Reed-Solomon encoder
    │   ├── rules/
    │   │   └── gateway.yar            # YARA rules (active PDF, OT sabotage, shellcode)
    │   └── web/
    │       ├── index.html             # Dashboard Tactical Low-Side
    │       └── app.js                 # Client-side logic
    │
    ├── high_side/                     # Zona 3: Sisi Dalam (OT Radar Enclave)
    │   ├── app.py                     # Flask web server sisi dalam (:5001, READ-ONLY)
    │   ├── udp_receiver.py            # Penerima UDP + Reed-Solomon decoder + verifikasi Ed25519
    │   └── web/
    │       ├── index.html             # Dashboard Tactical High-Side OT
    │       └── app.js                 # Client-side logic
    │
    ├── demo/                          # Split-view observer untuk presentasi
    │   ├── split.html                 # Dual-panel command center view
    │   └── split.js                   # Konfigurasi URL panel
    │
    ├── scripts/                       # Skrip utilitas & otomasi
    │   ├── gen_key.py                 # Generator kunci (cross-platform, Python)
    │   ├── gen_key.sh                 # Generator kunci (Linux/macOS, Bash)
    │   ├── make_demo_files.py         # Pembuat file demo & sampel serangan
    │   ├── demo_smoke_test.py         # End-to-end smoke test (8 skenario)
    │   ├── run_dev.ps1                # Runner Windows PowerShell
    │   ├── run_dev.sh                 # Runner Linux/macOS
    │   ├── loss_simulation.py         # Simulasi packet loss untuk uji FEC
    │   ├── setup_netns.sh             # Setup Linux network namespaces
    │   ├── run_netns.sh               # Runner mode isolasi penuh
    │   ├── verify_oneway.sh           # Verifikasi 7 titik isolasi satu arah
    │   └── teardown_netns.sh          # Bersihkan network namespaces
    │
    └── tests/                         # Unit test suite (30 test cases)
        ├── test_app.py                # Pengujian web endpoint & CSRF
        ├── test_gate.py               # Pengujian pipeline inspeksi
        ├── test_protocol.py           # Pengujian kriptografi & Reed-Solomon
        ├── test_transfer.py           # Pengujian transfer end-to-end
        └── helpers.py                 # Utilitas pengujian
```

---

## Tampilan Antarmuka

Antarmuka didesain dengan tema **Tactical Cyber / Military Tech Command Center** menggunakan palet warna *dark-mode emerald neon* khas militer:

**Fitur tampilan:**
- Sidebar navigasi dengan indikator status sistem real-time
- Hero card dengan animasi sapuan radar
- Dashboard metrik: firmware, frekuensi sapuan, dan status interlock hardware diode
- Visualisasi 6-tahap pemeriksaan keamanan secara real-time
- Dropzone interaktif dengan stepper progress (Upload → Scan → Analisis → Validasi → Enkripsi → Transfer)
- Tabel log terbaru dengan badge status LOLOS / DITOLAK
- Split-view untuk presentasi (sisi luar dan sisi dalam berdampingan)

---

## Dokumentasi Teknis

- [Master Plan Arsitektur (Bahasa Indonesia)](MASTER_PLAN_KARTIKA_CDS.md)
- [Product Requirements Document](PRD_KARTIKA_CDS_Unified_Hardened_Edition.md)

---

## Lisensi

Proyek ini dikembangkan untuk perlombaan **Kartika Cyber Hackathon**.

---

<div align="center">
  <strong>KARTIKA-CDS</strong> · Inspect. Verify. Protect.<br>
  <em>Unidirectional Cross-Domain Security Gateway</em>
</div>
