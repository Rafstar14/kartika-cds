<div align="center">

# 🛡️ KARTIKA-CDS

### Unidirectional Cross-Domain Security Gateway & Malware Inspection Diode

**Dirancang untuk Kartika Cyber Hackathon — TNI Angkatan Darat**

*Prototipe pemeriksaan dan transfer berkas dengan pengirim UDP tanpa ACK, untuk skenario jaringan radar OT. Demo bawaan berjalan di localhost*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask)](#)
[![Ed25519](https://img.shields.io/badge/Crypto-Ed25519-green)](#)
[![Reed Solomon](https://img.shields.io/badge/FEC-Reed--Solomon%20RS(4%2C2)-blue)](#)
[![Tests](https://img.shields.io/badge/Tests-pytest-blue)](#pengujian--demo)

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

**KARTIKA-CDS (Cross-Domain Security)** adalah prototipe gerbang pemeriksaan berkas dan transfer UDP yang dirancang untuk skenario pertahanan siber. Jenis berkas yang didukung:

| Jenis File | Ekstensi | Keterangan |
|---|---|---|
| Dokumen perintah operasi | `.pdf` | Perintah dan laporan taktis |
| Citra taktis | `.png`, `.jpg` | Peta situasi dan foto intelijen |
| Konfigurasi parameter radar | `.cfg`, `.txt` | Frekuensi sapuan, interlock, dan parameter operasional |
| Firmware perangkat OT/SCADA | `.bin` | Contoh format biner dengan penanda `KRTK` dan CRC32, bukan tanda tangan kriptografis firmware |

Pengirim tidak menunggu ACK dari penerima. Mode demo menggunakan localhost sehingga tidak membuktikan pemisahan jaringan atau tidak adanya jalur balik pada tingkat sistem. Status radar merupakan simulasi yang disimpan dalam JSON, bukan perangkat radar yang terhubung.

> **Batas keamanan:** ini prototipe, belum tersertifikasi atau dibuktikan siap operasi. Tanda tangan Ed25519 atau HMAC mengautentikasi paket dan mendeteksi perubahan; isi berkas tidak dienkripsi. Pemeriksaan berbasis aturan dan signature tidak menjamin semua malware terdeteksi.

---

## Arsitektur Sistem

```
 Browser operator (localhost:8000/split.html)
       |                                     |
       v                                     v
 Sisi luar (:5000)                    Sisi dalam (:5001, baca saja)
 Unggah ke spool disk                 Brankas dan status radar simulasi
       |                                     ^
 Gate: nama, hash, format,                   |
 struktur, YARA, ClamAV*                     |
       |                                     |
       +------ UDP tanpa ACK, RS(4,2) -------+
               autentikasi Ed25519/HMAC
```

\* Engine yang tidak diwajibkan dapat dilewati. Skrip Linux menyediakan topologi *network namespaces* dan aturan `nftables` untuk pengujian terpisah; hasilnya bergantung pada lingkungan dan harus diverifikasi dengan `scripts/verify_oneway.sh`.

---

## Fitur Keamanan

### Pipeline Pemeriksaan 6 Tahap

| # | Tahap | Fungsi |
|---|---|---|
| 1 | **Nama & Ukuran** | Validasi ekstensi file yang diizinkan, batas maksimum 10 MB, sanitasi nama file terhadap path traversal (`../../`) |
| 2 | **SHA-256** | Penghitungan hash untuk pencatatan audit dan pemeriksaan integritas saat transfer |
| 3 | **Tanda Tangan File (Magic Bytes)** | Deteksi format spoofing: file `.exe` yang disamarkan sebagai `.pdf` akan tertolak |
| 4 | **Pemeriksaan Struktur & Anti-Polyglot** | Validasi CRC tiap chunk PNG, deteksi sisipan data setelah `IEND`/`%%EOF`/`FFD9`, validasi header firmware `KRTK` + CRC32 |
| 5 | **Aturan YARA** | Deteksi `/JavaScript`, `/Launch` dalam PDF, pola PowerShell, dan sabotase parameter OT/Modbus |
| 6 | **ClamAV (INSTREAM)** | Jika tersedia, file spool dibaca kembali lalu dikirim ke daemon `clamd`; dapat diwajibkan melalui konfigurasi |

Unggahan disimpan sementara di disk. Gate membaca file ke memori untuk pemeriksaan hash, format, struktur, dan YARA; ClamAV membaca ulang file spool. File ditolak dipindah ke karantina. File diterima dibaca ulang oleh pengirim, hash-nya dibandingkan lagi sebelum dikirim, dan file sementara dihapus setelah upaya pengiriman selesai. Hal ini bukan inspeksi yang seluruhnya berlangsung di RAM.

### Fitur Keamanan Tambahan

- **Autentikasi paket**: Ed25519 bila pasangan kunci tersedia, atau HMAC-SHA256 sebagai fallback. Keduanya bukan enkripsi.
- **Reed-Solomon RS(4,2) Forward Error Correction**: Mampu memulihkan kehilangan hingga 2 paket per grup (33% erasure) tanpa memerlukan ACK
- **Pembatasan replay**: Penerima memeriksa jendela waktu dan `file_id` yang telah selesai. Perlindungan anti-downgrade firmware belum diimplementasikan.
- **Tamper-Evident Hash Chain Audit Log**: Setiap catatan audit mengikat hash SHA-256 baris sebelumnya
- **Pemeriksaan ulang hash sebelum kirim**: Pengirim membandingkan hash file spool dengan hasil gate dan membatalkan pengiriman jika berbeda.

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
| **ClamAV + clamd** | Untuk tahap pemindaian malware. `run_dev.py` menggunakan mode YARA-only jika clamd tidak tersedia; bila ClamAV diwajibkan, file ditolak ketika daemon tidak tersedia. |
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

Skrip juga membuat sampel uji EICAR yang dapat dikarantina antivirus pada komputer. Jika sampel tidak dapat dibuat atau dibaca, smoke test akan melaporkannya sebagai gagal, bukan sebagai bukti bahwa gate mendeteksinya.

---

## Menjalankan Sistem

### Menjalankan demo lokal

Dari folder `diode-gateway` dengan virtual environment aktif:

```bash
python cli.py
```

Alternatif tanpa menu: `python run_dev.py`. Untuk menyediakan perintah `kartika` di virtual environment, jalankan `pip install -e .` dari folder `diode-gateway`, kemudian jalankan `kartika` saat environment tersebut aktif.

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
| **Sisi Dalam (High-Side)** | http://127.0.0.1:5001 | Brankas file terverifikasi, status radar simulasi, dan audit log |
| **UDP Gateway** | 127.0.0.1:9999 | Pengiriman UDP tanpa ACK pada komputer yang sama |

### Mode Linux dengan Network Namespaces

Untuk menguji topologi virtual dengan Linux network namespaces dan nftables bridge firewall:

```bash
sudo bash scripts/setup_netns.sh       # Buat topologi jaringan 3-zona
sudo bash scripts/verify_oneway.sh     # Verifikasi isolasi satu arah (7 pengujian)
sudo bash scripts/run_netns.sh start   # Jalankan semua layanan di namespace masing-masing
python3 -m http.server 8000 --bind 127.0.0.1 --directory demo  # Split-view observer
```

Ini adalah isolasi berbasis perangkat lunak, bukan diode fisik. Jalankan verifikasi di lingkungan target dan catat hasilnya; keberadaan skrip bukan bukti semua jalur balik telah tertutup. Skrip mengubah konfigurasi jaringan host dan membutuhkan hak administrator.

---

## Pengujian & Demo

### Menjalankan Unit Test

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
- ClamAV detection dengan engine tiruan dalam tes, bukan daemon ClamAV nyata
- Fail-closed gate behavior
- Ed25519 & HMAC crypto roundtrip
- Reed-Solomon RS(4,2) erasure recovery
- Tamper-evident audit chain
- High-side read-only enforcement

### Menjalankan Smoke Test (8 Skenario)

Jalankan gateway lokal dan buat file demo terlebih dahulu. Smoke test mengunggah file dan menambahkan data ke karantina serta brankas, sehingga gunakan hanya lingkungan demo.

```bash
python scripts/demo_smoke_test.py
```

Skrip memeriksa keputusan gate dan kode alasan. Untuk file yang diterima, skrip juga menunggu ID transfer yang sama di brankas dan mencocokkan SHA-256. File yang tidak dapat dibaca, respons tidak sesuai, dan penerimaan yang tidak terbukti dihitung gagal; proses mengembalikan kode keluar bukan nol. Deteksi EICAR dapat terjadi pada YARA atau ClamAV, tergantung engine yang aktif dan urutan pemeriksaan.

| # | Skenario | File | Hasil yang Diharapkan |
|---|---|---|---|
| 1 | Dokumen perintah operasi sah | `dokumen_operasi.pdf` | ACCEPTED |
| 2 | Firmware radar OT sah | `firmware_radar_v24.bin` | ACCEPTED |
| 3 | Parameter frekuensi radar sah | `radar_update_sah.cfg` | ACCEPTED |
| 4 | Penyamaran executable | `laporan_palsu.pdf` | REJECTED: FORMAT_SPOOFING_DETECTED |
| 5 | Eksploitasi PDF aktif (JavaScript) | `pdf_aktif.pdf` | REJECTED: YARA_MATCH |
| 6 | Sabotase parameter radar | `sabotase_radar.cfg` | REJECTED: YARA_MATCH |
| 7 | Penyusupan polyglot PNG | `gambar_polyglot.png` | REJECTED: STRUCTURE_INVALID |
| 8 | Signature uji EICAR | `data_terinfeksi.txt` | REJECTED: YARA_MATCH atau MALWARE_DETECTED |

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
    │   ├── gate_inspector.py          # Pipeline pemeriksaan 6 tahap
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
    │   ├── run_netns.sh               # Runner topologi Linux virtual
    │   ├── verify_oneway.sh           # Verifikasi 7 titik isolasi satu arah
    │   └── teardown_netns.sh          # Bersihkan network namespaces
    │
    └── tests/                         # Suite pengujian otomatis
        ├── test_app.py                # Pengujian web endpoint & CSRF
        ├── test_gate.py               # Pengujian pipeline inspeksi
        ├── test_protocol.py           # Pengujian kriptografi & Reed-Solomon
        ├── test_transfer.py           # Pengujian transfer end-to-end
        ├── test_smoke.py              # Validasi pelaporan smoke test
        └── helpers.py                 # Utilitas pengujian
```

---

## Tampilan Antarmuka

Antarmuka menyediakan panel sisi luar dan sisi dalam dengan tampilan berdampingan untuk demo lokal.

**Fitur tampilan:**
- Sidebar navigasi dengan indikator status sistem real-time
- Hero card dengan animasi sapuan radar
- Dashboard status firmware, frekuensi, dan interlock simulasi
- Visualisasi pemeriksaan dan hasil unggahan
- Tabel log terbaru dengan badge status LOLOS / DITOLAK
- Split-view untuk presentasi (sisi luar dan sisi dalam berdampingan)

---

## Dokumentasi Teknis

- [Master Plan Arsitektur (Bahasa Indonesia)](MASTER_PLAN_KARTIKA_CDS.md)
- [Product Requirements Document](PRD_KARTIKA_CDS_Unified_Hardened_Edition.md)

Dokumen master plan dan PRD merupakan sasaran desain, bukan bukti bahwa semua rencana telah diimplementasikan atau diuji. Gunakan penjelasan status dan batas prototipe dalam README ini saat mendeskripsikan sistem.

---

## Lisensi

Proyek ini dikembangkan untuk perlombaan **Kartika Cyber Hackathon**.

---

<div align="center">
  <strong>KARTIKA-CDS</strong> · Inspect. Verify. Protect.<br>
  <em>Unidirectional Cross-Domain Security Gateway</em>
</div>
