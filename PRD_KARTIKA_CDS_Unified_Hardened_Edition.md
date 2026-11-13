# PRODUCT REQUIREMENTS DOCUMENT (PRD)

> **Status dokumen:** PRD ini memuat sasaran dan kriteria desain, bukan bukti bahwa semua persyaratan telah terpenuhi. Demo saat ini menggunakan localhost, spool di disk, autentikasi paket tanpa enkripsi, dan radar simulasi. Isolasi Linux, ClamAV nyata, serta kesiapan operasional memerlukan pengujian pada lingkungan target. Lihat README utama untuk kondisi implementasi.

| Metadata Dokumen | Detail Spesifikasi |
| :--- | :--- |
| **Nama Produk** | **KARTIKA-CDS** (*Cross-Domain Solution, Air-Gap Data Diode & Malware Inspection Gateway*) |
| **Edisi Arsitektur** | Unified Hardened Edition (Integrasi Arsitektur 3-Zona + Otomasi `diode-gateway`) |
| **Target Kompetisi** | Kartika Cyber Hackathon — TNI Angkatan Darat (TNI AD) |
| **Domain Masalah** | Keamanan Siber Integrasi IT/OT & Pertahanan Infrastruktur Kritis Militer |
| **Status Dokumen** | Rencana kebutuhan prototipe; sebagian persyaratan masih perlu dipenuhi atau diverifikasi |
| **Tanggal Rilis** | 30 Oktober 2026 |

---

## 1. Ringkasan Eksekutif & Visi Produk

### 1.1 Latar Belakang Masalah
Instalasi militer strategis dan infrastruktur operasional (OT/ICS) milik TNI AD—seperti unit Radar Pertahanan Udara (Arhanud), pusat komando C4ISR, dan sistem kendali logistik—wajib diisolasi dari jaringan luar (*air-gapped*) untuk mencegah spionase siber (ekfiltrasi data rahasia) dan sabotase jarak jauh. Namun, sistem terisolasi tersebut tetap membutuhkan pembaruan rutin dari jaringan luar (*Low-Side*), seperti:
* Pembaruan konfigurasi parameter frekuensi sapuan radar (`.cfg`).
* Pembaruan *image firmware* modul pemrosesan sinyal digital (`.bin`).
* Pengiriman dokumen perintah operasi dan peta taktis (`.pdf`, `.png`, `.jpg`, `.txt`).

Penggunaan media penyimpanan fisik (USB flashdisk) secara manual membuka celah infeksi *malware* bergaya *Stuxnet*, sedangkan pembukaan jalur jaringan dua arah standar (TCP/IP + Firewall biasa) membuka risiko jalur balik (*back-channel*) menuju server *Command & Control* (C2) penyerang jika salah satu sisi terkompromi.

### 1.2 Solusi yang Dihadirkan (Visi Produk)
**KARTIKA-CDS** adalah prototipe pemeriksaan berkas dan transfer UDP tanpa ACK. Gate menerapkan pemeriksaan bertahap sesuai engine yang diwajibkan, lalu penerima mengautentikasi paket dan memeriksa ulang berkas. Reed-Solomon $RS(4, 2)$ dapat memulihkan kehilangan tertentu. Sistem tidak menjamin seluruh malware terdeteksi atau seluruh jalur kebocoran tertutup; demo localhost bukan bukti isolasi fisik.

---

## 2. Profil Pengguna & Pemangku Kepentingan (*User Personas*)

| Peran Pengguna | Tanggung Jawab Operasional | Kebutuhan Utama terhadap Sistem |
| :--- | :--- | :--- |
| **1. Operator Staf Sisi Luar (*Low-Side Operator*)** | Mengunggah file perintah operasi, konfigurasi radar, atau patch firmware dari jaringan staf/publik. | Antarmuka web yang jelas, umpan balik instan mengapa sebuah file diterima atau ditolak di tiap tahap pemeriksaan, serta jaminan proses unggah tidak rumit. |
| **2. Perwira Pengawas Enklave OT (*High-Side OT Custodian*)** | Memantau penerimaan file bersih dan status kesiapan perangkat Radar/SCADA di dalam jaringan rahasia terisolasi. | Dashboard *read-only* yang menampilkan integritas file (SHA-256), statistik pemulihan paket FEC, nama penyimpanan aman berbasis UUID, dan status pembaruan Radar OT secara langsung. |
| **3. Auditor Keamanan Siber / Juri Penilai (*Security Auditor*)** | Menguji ketahanan sistem terhadap *bypass*, *spoofing*, *polyglot*, *replay attack*, *packet loss*, dan upaya pembocoran data dari dalam ke luar. | Bukti terukur dan otomatis (`verify_oneway.sh`, `pytest`, rantai hash log audit *tamper-evident*) bahwa sistem bekerja sesuai klaim tanpa kontradiksi arsitektur. |

---

## 3. Ruang Lingkup Sistem (*Scope*)

### 3.1 Fitur di Dalam Ruang Lingkup (*In-Scope*)
1. Pipeline inspeksi 6 tahap: sanitasi nama/ukuran, SHA-256, magic bytes, struktur, YARA, dan ClamAV (`INSTREAM`) ketika tersedia atau diwajibkan. Unggahan tersimpan di spool disk dan beberapa komponen membacanya kembali.
2. Protokol pengiriman UDP satu arah (*Simplex*) dengan tanda tangan kriptografi **Ed25519 (64-byte)** atau **HMAC-SHA256 (32-byte)** pada setiap datagram.
3. Pengkodean dan pendekodean *Forward Error Correction* (FEC) sejati menggunakan **Reed-Solomon $RS(4, 2)$ di atas $GF(2^8)$** ditambah *multi-pass interleaving*.
4. Isolasi topologi jaringan menggunakan Linux Network Namespaces (`diode-low`, `diode-high`) dan jembatan virtual (`br-diode`) dengan aturan pemutus jalur balik `nftables` *family bridge* di Host OS, ARP statis permanen, dan penonaktifan IPv6.
5. Dua aplikasi Web UI independen (`low_side` di port `5000` dan `high_side` di port `5001`) serta pembungkus visual presentasi juri (`demo/split.html`) yang bekerja sebagai *Out-of-Band Observer* di browser Host.
6. Simulasi pembaruan parameter operasional **Radar Arhanud TNI AD** (`ot_radar_state.json`) saat file konfigurasi `.cfg` atau firmware `.bin` (`KRTK`) yang valid tiba di sisi dalam.
7. Pencatatan log audit berformat JSON Lines (`.jsonl`) dengan pengikatan rantai hash (*Tamper-Evident Hash Chain*).

### 3.2 Fitur di Luar Ruang Lingkup (*Out-of-Scope*)
1. Pembuatan perangkat keras optik fisik (LED/Fotodioda SFP fisik)—disimulasikan secara ketat pada tingkat *Kernel Bridge Layer 2* di Host OS.
2. Dekripsi lalu lintas terenkripsi kata sandi (semua arsip terkompresi/terenkripsi seperti `.zip`, `.rar`, `.7z` langsung ditolak secara *default* oleh kebijakan *anti-zip bomb*).

---

## 4. Kebutuhan Fungsional (*Functional Requirements*)

### 4.1 Modul Drop-Zone & Ingesti Sisi Luar (`low_side/app.py` & `gate_inspector.py`)

| ID | Kebutuhan Fungsional | Kriteria Penerimaan (*Acceptance Criteria*) | Prioritas |
| :--- | :--- | :--- | :--- |
| **FR-01** | **Perlindungan CSRF & Penyimpanan Spool Acak** | Endpoint `POST /api/upload` wajib menolak permintaan tanpa header `X-Diode-Request: 1` (HTTP 403). File yang diunggah disimpan sementara menggunakan ID acak `<job_id>.upload` dengan izin `0600`, tidak pernah menggunakan nama file asli dari pengguna. | **P0 (Kritis)** |
| **FR-02** | **Pemeriksaan Anti-Symlink & Penanganan Spool** | Gate memeriksa `os.lstat()` dan menolak *symlink*, FIFO, perangkat, atau *hardlink*. Gate membaca spool ke RAM untuk hash, format, struktur, dan YARA; ClamAV serta pengirim membaca ulang spool. Pengirim membandingkan hash sebelum transfer. Pemeriksaan satu kali dan penghapusan sebelum pemeriksaan belum tercapai. | **P0 (Kritis)** |
| **FR-03** | **Sanitasi Nama & Pembatasan Ukuran File (Tahap 1)** | Nama file dinormalisasi dengan NFKC, karakter berbahaya dihapus, dan ekstensi diperiksa terhadap daftar putih (`.pdf`, `.png`, `.jpg`, `.txt`, `.cfg`, `.bin`). File berukuran $0\text{ byte}$ (`EMPTY_FILE`) atau $> 10\text{ MB}$ (`SIZE_LIMIT`) langsung ditolak. | **P0 (Kritis)** |
| **FR-04** | **Kalkulasi Integritas Awal SHA-256 (Tahap 2)** | Sistem menghitung nilai hash SHA-256 dari buffer RAM dan menyertakannya pada catatan pekerjaan, log audit, serta header protokol UDP. | **P0 (Kritis)** |
| **FR-05** | **Deteksi Magic Bytes & Anti-Spoofing (Tahap 3)** | Sistem memeriksa byte awal buffer terhadap tanda tangan biner terlarang (`MZ` PE Windows, `\x7fELF` Linux, `#!` shebang, Mach-O, serta arsip `PK\x03\x04` ZIP/RAR/7z/GZIP). Jika ditemukan ketidaksesuaian dengan ekstensi, file ditolak dengan kode `FORMAT_SPOOFING_DETECTED`. | **P0 (Kritis)** |
| **FR-06** | **Validasi Struktur Mendalam & Anti-Polyglot (Tahap 4)** | Sistem memvalidasi keutuhan struktur internal sesuai tipe file (`STRUCTURE_INVALID` jika gagal):<br>• **PNG:** Memverifikasi CRC32 setiap chunk dari `IHDR` hingga `IEND` dan menolak jika ada byte ekstra setelah `IEND`.<br>• **JPG:** Memastikan diakhiri dengan penanda EOI `\xff\xd9`.<br>• **PDF:** Memastikan keberadaan `%%EOF` di bagian akhir tanpa byte susulan.<br>• **TXT/CFG:** Memastikan teks UTF-8 murni tanpa byte `NUL` (`\x00`).<br>• **BIN (Firmware OT):** Memastikan header `KRTK`, kecocokan panjang payload, dan kecocokan nilai CRC32 internal 4-byte terakhir. | **P0 (Kritis)** |
| **FR-07** | **Pemindaian Aturan YARA Taktis (Tahap 5)** | Sistem memindai buffer dengan aturan `low_side/rules/gateway.yar` untuk mendeteksi string uji EICAR, skrip aktif di dalam PDF (`/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`), perintah berbahaya (`powershell -enc`, `/dev/tcp/`), serta pola sabotase OT/Radar (`DISABLE_RADAR_INTERLOCK`, `MODBUS_FORCE_COIL_RESET`). | **P0 (Kritis)** |
| **FR-08** | **Pemindaian Antivirus ClamAV Stream (Tahap 6)** | Jika tersedia, sistem membaca ulang spool lalu mengirim byte ke daemon `clamd` menggunakan `INSTREAM`. Jika signature terdeteksi, file ditolak dengan kode `MALWARE_DETECTED`; engine yang tidak wajib dapat dilewati. | **P0 (Kritis)** |
| **FR-09** | **Kebijakan Fail-Closed & Karantina Bukti** | Jika mesin pemindai yang diwajibkan (`DIODE_REQUIRE_ENGINES`) mati atau gagal dihubungi, sistem wajib menolak file (`ENGINE_UNAVAILABLE`). Setiap file yang ditolak dipindahkan ke folder `quarantine/<job_id>.quarantined` dengan izin `0400` beserta file metadata alasan penolakannya. | **P0 (Kritis)** |

---

### 4.2 Modul Protokol Transmisi Satu Arah & FEC (`common/protocol.py` & `low_side/udp_sender.py`)

| ID | Kebutuhan Fungsional | Kriteria Penerimaan (*Acceptance Criteria*) | Prioritas |
| :--- | :--- | :--- | :--- |
| **FR-10** | **Autentikasi Kriptografi Per Paket (Ed25519 / HMAC)** | Setiap datagram UDP (`HEADER`, `DATA`, `PARITY`, `EOF`) wajib ditandatangani dengan kunci privat **Ed25519** (menghasilkan tanda tangan 64-byte dengan flag versi `0x81`) atau kunci simetris **HMAC-SHA256** (32-byte). Sisi penerima yang hanya memegang kunci publik Ed25519 secara matematis tidak dapat membuat paket palsu. | **P0 (Kritis)** |
| **FR-11** | **Pengkodean Erasure Coding Reed-Solomon $RS(4, 2)$ di $GF(2^8)$** | Setiap grup yang terdiri dari $K=4$ potongan data masing-masing $1024\text{ byte}$ dikodekan menjadi 2 potongan paritas independen:<br>• $P_0$: Paritas XOR ($\bigoplus_{i=0}^{3} D_i$).<br>• $P_1$: Paritas Vandermonde di Galois Field $GF(2^8)$ dengan polinomial primitif $\text{0x11d}$ dan koefisien $(1, 2, 4, 8)$. | **P0 (Kritis)** |
| **FR-12** | **Pengiriman Multi-Pass Interleaved Tanpa Jalur Balik** | Pengirim mentransmisikan paket menggunakan `socket.SOCK_DGRAM` (`sendto` saja, tanpa pernah memanggil `recv`). Paket `HEADER` dikirim 3 kali di awal, diikuti $N$ *pass* pengiriman (di mana *pass* bernomor ganjil dikirim dengan urutan grup terbalik untuk memecah *burst packet loss*), dan diakhiri 2 paket `EOF` per *pass*. | **P0 (Kritis)** |

---

### 4.3 Modul Penerima Sisi Dalam, Brankas, & Simulasi OT (`high_side/udp_receiver.py` & `app.py`)

| ID | Kebutuhan Fungsional | Kriteria Penerimaan (*Acceptance Criteria*) | Prioritas |
| :--- | :--- | :--- | :--- |
| **FR-13** | **Operasi Pasif Murni ($0\text{ Byte}$ Keluar)** | Kode sumber `high_side/udp_receiver.py` dilarang keras memiliki pemanggilan `.send()`, `.sendto()`, atau `.sendall()`. Diverifikasi secara otomatis melalui inspeksi AST/kode sumber pada suite pengujian. | **P0 (Kritis)** |
| **FR-14** | **Verifikasi Tanda Tangan Instan & Anti-Replay** | Setiap datagram yang masuk diverifikasi tanda tangan kriptografinya terlebih dahulu sebelum dialokasikan ke struktur sesi. Paket `HEADER` yang memiliki cap waktu di luar jendela `REPLAY_WINDOW_S` ($300\text{ detik}$) atau `file_id` yang sudah pernah diproses langsung ditolak. Daftar `file_id` yang selesai dipulihkan dari `audit_high.jsonl` saat *startup* agar tahan terhadap *restart*. | **P0 (Kritis)** |
| **FR-15** | **Dekoder Matriks $GF(2^8)$ untuk Pemulihan 1 & 2 Paket Hilang** | Apabila dalam satu grup berukuran 4 chunk terdapat 1 atau 2 chunk data yang hilang, Receiver menggunakan kombinasi $P_0$ dan/atau $P_1$ melalui eliminasi linear $2 \times 2$ di $GF(2^8)$ untuk merekonstruksi chunk yang hilang secara utuh tanpa meminta pengiriman ulang. | **P0 (Kritis)** |
| **FR-16** | **Verifikasi SHA-256 Utuh & Revalidasi Sisi Dalam** | Setelah seluruh potongan lengkap, Receiver menghitung ulang SHA-256 file hasil rakitan dan mencocokkannya dengan nilai SHA-256 di `HEADER`. Selanjutnya, Receiver menjalankan kembali `check_magic()` dan `check_structure()` di sisi dalam sebagai pertahanan lapis kedua jika sisi luar pernah disusupi. | **P0 (Kritis)** |
| **FR-17** | **Penyimpanan Berbasis UUID (Anti-Path Traversal)** | File yang lolos verifikasi disimpan di `secure_vault/<file_id_hex><ext>` dengan izin `0600`/`0400`. Nama asli file hanya disimpan sebagai atribut teks ter-sanitasi di dalam file metadata `<file_id_hex>.json`. | **P0 (Kritis)** |
| **FR-18** | **Pembaruan Status Perangkat Radar OT TNI AD** | Apabila file yang masuk dan terverifikasi adalah konfigurasi `.cfg` atau firmware `.bin` (`KRTK`), Receiver secara otomatis mengekstrak parameter versi firmware dan frekuensi sapuan (`SWEEP_FREQ_MHZ`), lalu memperbarui `ot_radar_state.json` yang ditampilkan pada dashboard Sisi Dalam. | **P1 (Tinggi)** |
| **FR-19** | **Dashboard Sisi Dalam 100% Read-Only** | Aplikasi `high_side/app.py` hanya melayani metode `GET` (`/api/live`, `/api/ot`, `/api/vault`, `/api/audit`). Semua permintaan `POST`, `PUT`, atau `DELETE` harus menghasilkan kode HTTP `404` atau `405`. | **P0 (Kritis)** |

---

## 5. Kebutuhan Non-Fungsional & Keamanan (*Non-Functional & Security Requirements*)

| Kategori | Spesifikasi Teknis & Standar Keamanan |
| :--- | :--- |
| **1. Penegakan Isolasi Jaringan (Layer 2 Host Enforcement)** | • Aturan blokir jalur balik wajib berada di **Host Bridge (`br-diode`)** menggunakan `nftables` (`table bridge diode`), bukan di dalam namespace penerima.<br>• Semua frame dari antarmuka `vh-br` menuju `vl-br` di-`drop` pada *Layer 2*.<br>• Tabel ARP dikunci secara statis (`nud permanent`), IPv6 dimatikan (`disable_ipv6=1`), dan IPv4 *forwarding* di jembatan dimatikan (`forwarding=0`). |
| **2. Ketahanan terhadap Kehilangan Paket (*Packet Loss Resilience*)** | • Kode dan tes memeriksa pemulihan hingga **2 chunk data per grup** jika paket paritas yang diperlukan tersedia.<br>• `scripts/loss_simulation.py` melakukan simulasi tertentu; hasil simulasi tidak menjamin tingkat keberhasilan di jaringan nyata. |
| **3. Pembatasan Sumber Daya (Anti-DoS)** | • Ukuran datagram UDP dibatasi maksimal $1450\text{ byte}$ (bebas fragmentasi MTU).<br>• Maksimal sesi perakitan paralel di Receiver dibatasi `MAX_CONCURRENT = 4` sesi, dengan batas waktu aktif `TRANSFER_TIMEOUT_S = 180` detik dan batas diam `IDLE_TIMEOUT_S = 20` detik. |
| **4. Integritas Log Audit (*Tamper-Evident Logging*)** | • Seluruh peristiwa di sisi luar (`audit_low.jsonl`) dan sisi dalam (`audit_high.jsonl`) menyertakan field `prev` berisi hash SHA-256 dari baris sebelumnya.<br>• Modifikasi 1 karakter pun pada riwayat log akan langsung terdeteksi oleh fungsi `verify_chain()` dan memunculkan peringatan merah di UI. |
| **5. Pengerasan Web & Isolasi Bytecode** | • Header HTTP dilengkapi `Content-Security-Policy` ketat (`default-src 'none'; script-src 'self'`), `X-Content-Type-Options: nosniff`, dan `Cache-Control: no-store`.<br>• Seluruh skrip dijalankan dengan `PYTHONDONTWRITEBYTECODE=1` untuk mencegah serangan *cross-zone `__pycache__` poisoning*. |

---

## 6. Spesifikasi Format Data & Protokol Biner

### 6.1 Tata Letak Datagram UDP (`common/protocol.py`)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic = "DIOD"                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|   Version   |  Packet_Type  |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                        File_ID (16 Byte)                      +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                     Body (Panjang Variabel)                   |
+                                                               +
|  - HEADER : size(8B), n_chunks(4B), cs(2B), ts(8B), k(2B),    |
|             sha256(32B), name_len(2B), name_utf8              |
|  - DATA   : chunk_idx(4B), payload_len(2B), payload(<=1024B)  |
|  - PARITY : parity_idx(4B), payload_len(2B), payload(1024B)   |
|  - EOF    : (Kosong / 0 Byte)                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Auth Tag / Signature: Ed25519 (64 Byte) atau HMAC (32 Byte) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*Catatan:* Bit tertinggi `F` (`0x80`) pada byte `Version` bernilai `1` (`0x81`) jika paket ditandatangani dengan **Ed25519**, dan `0` (`0x01`) jika menggunakan **HMAC-SHA256**.

### 6.2 Format Biner Paket Firmware Radar OT (`.bin` — `KRTK`)
```text
+---------------+---------------+---------------+---------------+
| Magic "KRTK"  | Major Ver (2B)| Minor Ver (2B)| PayloadLen(4B)|
| (4 Byte)      | uint16 BE     | uint16 BE     | uint32 BE     |
+---------------+---------------+---------------+---------------+
|                 Firmware Payload (PayloadLen Byte)            |
+---------------------------------------------------------------+
|          CRC32 Checksum dari Header + Payload (4 Byte)        |
+---------------------------------------------------------------+
```

---

## 7. Matriks Pengujian & Kriteria Penerimaan Akhir (*Verification & Validation*)

Sistem dinyatakan siap didemonstrasikan di hadapan dewan juri apabila lulus seluruh pengujian otomatis dan skenario langsung berikut:

### 7.1 Suite Pengujian Unit & Integrasi Otomatis (`pytest`)
* **`tests/test_protocol.py`:** Memvalidasi putaran penuh (*round-trip*) paket HMAC & Ed25519, memastikan kunci publik tidak dapat menandatangani paket, menolak manipulasi 1-bit pada datagram, dan membuktikan pemulihan matematis $RS(4, 2)$ untuk seluruh kombinasi $\binom{4}{2} = 6$ pasang *chunk* yang hilang.
* **`tests/test_gate.py`:** Memvalidasi penerimaan format contoh, sejumlah penolakan format dan struktur, pencocokan aturan YARA, serta perilaku fail-closed. Tes deteksi ClamAV memakai engine tiruan, bukan daemon ClamAV nyata.
* **`tests/test_transfer.py`:** Memvalidasi pengiriman *end-to-end* dengan Ed25519 dan pembaruan status Radar OT, pemulihan kehilangan 2 paket per grup pada 1 *pass*, pembuangan paket palsu, pencegahan *path traversal* (`../../../../tmp/pwn.png`), revalidasi struktur di sisi dalam, deteksi manipulasi rantai hash log audit, serta kepastian bahwa modul Receiver tidak memiliki fungsi kirim.
* **`tests/test_app.py`:** Memvalidasi penegakan header CSRF `X-Diode-Request`, karantina file yang ditolak tanpa pernah dikirim ke antrean UDP, pengiriman file yang diterima, dan sifat *read-only* pada seluruh endpoint Web UI Sisi Dalam.

### 7.2 Skrip Pembuktian Isolasi Satu Arah (`sudo bash scripts/verify_oneway.sh`)
Wajib menghasilkan status **`[LULUS]`** pada ketujuh pengujian jaringan nyata di bawah ini:
1. Luar $\rightarrow$ Dalam pada `UDP 9999` : **`RECEIVED`** (Jalur resmi diizinkan).
2. Luar $\rightarrow$ Dalam pada `UDP 9998` : **`NONE`** (Port UDP lain diblokir).
3. Luar $\rightarrow$ Dalam pada `TCP 5001` : **`BLOCKED`** (Akses TCP lintas zona diblokir).
4. Dalam $\rightarrow$ Luar pada `UDP 5555` : **`NONE`** (Upaya kirim balik UDP gagal total).
5. Dalam $\rightarrow$ Luar pada `TCP 5000` : **`BLOCKED`** (Upaya koneksi balik TCP gagal total).
6. Dalam $\rightarrow$ Luar via `ICMP Ping` : **`NOREPLY`** (Ping balik diblokir).
7. Dalam $\rightarrow$ Luar via `ARP Request` : **`NOREPLY`** (Frame ARP Layer 2 dari dalam diblokir).

---

## 8. Daftar Periksa Skenario Demonstrasi Langsung (*Live Demo Runbook*)

Gunakan file yang dihasilkan oleh `python3 scripts/make_demo_files.py` di dalam folder `demo_files/` secara berurutan saat presentasi:

| No | File Uji Demo | Skenario yang Didemonstrasikan | Hasil yang Diharapkan di Layar Split-View |
| :--- | :--- | :--- | :--- |
| **1** | `dokumen_operasi.pdf` & `gambar_normal.png` | Pengiriman dokumen perintah operasi & citra taktis standar. | **Lolos 6 Tahap Gate** $\rightarrow$ Terkirim via UDP $\rightarrow$ Masuk ke Brankas Sisi Dalam dengan SHA-256 identik. |
| **2** | `radar_update_sah.cfg` & `firmware_radar_v24.bin` | Pembaruan parameter frekuensi & firmware Radar Arhanud TNI AD. | **Lolos 6 Tahap Gate** $\rightarrow$ Diterima di Sisi Dalam $\rightarrow$ **Panel Status Radar OT langsung berubah ke `v2.4.0-KRTK-VERIFIED` dan `2920 MHz`**. |
| **3** | `laporan_palsu.pdf` | Serangan penyamaran program `.exe` (`MZ`) menjadi dokumen `.pdf`. | **Ditolak di Tahap 3 (Tanda Tangan File):** Terdeteksi sebagai `executable Windows (PE/DOS)`. Dikarantina di sisi luar, $0\text{ paket}$ dikirim. |
| **4** | `gambar_polyglot.png` | Serangan penyelundupan payload biner di belakang chunk `IEND` gambar PNG. | **Ditolak di Tahap 4 (Struktur File):** Terdeteksi ada data tambahan setelah `IEND`. |
| **5** | `pdf_aktif.pdf` & `sabotase_radar.cfg` | Eksploitasi JavaScript di dalam PDF & upaya mematikan *safety interlock* Radar OT. | **Ditolak di Tahap 5 (Aturan YARA):** Ditangkap oleh `Pdf_Active_Content` dan `OT_Radar_Sabotage_Patterns`. |
| **6** | `data_terinfeksi.txt` | Serangan file terinfeksi signature malware standar (EICAR). | **Ditolak di Tahap 5/6 (YARA & ClamAV):** Dikarantina secara instan di sisi luar. |
| **7** | **Uji Gangguan Ekstrem (`loss_demo.sh on 15`)** | Pengiriman file di tengah gangguan kehilangan paket jaringan sebesar 15% tanpa jalur balik (0 ACK). | Penghitung **`Pulih FEC`** di Sisi Dalam bertambah secara otomatis berkat matriks Reed-Solomon $RS(4, 2)$, dan file tetap tersimpan 100% utuh dengan SHA-256 cocok. |
