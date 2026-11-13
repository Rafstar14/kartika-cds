# KARTIKA-CDS: Prototipe Security Gateway

KARTIKA-CDS memeriksa berkas pada sisi luar, mengirim berkas yang diterima melalui UDP tanpa ACK, lalu memverifikasi dan menyimpannya pada sisi dalam. Paket diautentikasi dengan Ed25519 atau HMAC-SHA256 dan dilengkapi Reed-Solomon RS(4,2). Isi berkas tidak dienkripsi.

Mode demo berjalan di localhost. Status radar adalah simulasi dalam `ot_radar_state.json`, bukan telemetri dari perangkat nyata. Skrip Linux menyediakan topologi virtual `network namespaces` dan firewall `nftables` untuk pengujian terpisah; ini bukan diode fisik, dan hasil verifikasinya bergantung pada lingkungan yang diuji. Prototipe belum dinyatakan siap untuk operasi.

## Alur berkas

1. Unggahan disimpan sementara di disk dengan nama acak.
2. Gate memeriksa nama, ukuran, hash, format, struktur, YARA, dan ClamAV sesuai engine yang tersedia dan diwajibkan. Sebagian pemeriksaan memakai buffer RAM; ClamAV membaca ulang file spool.
3. Berkas yang ditolak dipindahkan ke karantina. Berkas yang diterima dibaca kembali oleh pengirim dan hash-nya dibandingkan dengan hasil gate sebelum dikirim; spool dihapus setelah upaya pengiriman selesai.
4. Penerima memverifikasi paket, merakit dan memeriksa ulang berkas, kemudian menyimpannya di brankas. Berkas `.cfg` dan `.bin` tertentu memperbarui status radar simulasi.

Pemeriksaan berbasis aturan dan signature tidak menjamin seluruh malware terdeteksi. Bila engine yang dikonfigurasi sebagai wajib tidak tersedia, gate menolak berkas. Launcher lokal dapat menggunakan mode YARA-only bila `clamd` tidak tersedia.

## Instalasi dan demo lokal

Dengan Python 3.10 atau lebih baru, dari direktori ini:

```bash
python -m venv .venv
# Aktifkan .venv sesuai sistem operasi Anda.
python -m pip install -r requirements.txt
python scripts/gen_key.py
python scripts/make_demo_files.py
python -m pytest
python cli.py
```

Di Windows PowerShell, aktifkan environment menggunakan `.\.venv\Scripts\Activate.ps1`; di Linux/macOS gunakan `source .venv/bin/activate`. `python run_dev.py` menjalankan layanan lokal tanpa menu.

Skrip pembuat sampel menghasilkan file uji EICAR yang mungkin dikarantina oleh antivirus. `python scripts/demo_smoke_test.py` mengunggah sampel dan mengubah data demo di karantina serta brankas. Jika file tidak dapat dibaca, hasilnya dihitung gagal; file yang diterima harus ditemukan di brankas dengan ID transfer dan hash yang cocok.

## Pengujian topologi Linux

Setelah membaca skrip dan memastikan mesin uji sesuai, jalankan:

```bash
sudo bash scripts/setup_netns.sh
sudo bash scripts/verify_oneway.sh
sudo bash scripts/run_netns.sh start
```

Perintah memerlukan hak administrator dan mengubah konfigurasi jaringan host. Catat hasil verifikasi pada lingkungan yang benar-benar digunakan; skrip yang tersedia saja tidak membuktikan isolasi pada semua sistem.

Dokumentasi utama dan penjelasan batas prototipe tersedia di [README proyek](../README.md). Dokumen PRD dan master plan memuat sasaran desain, bukan sertifikasi atau bukti seluruh fitur sudah terpenuhi.
