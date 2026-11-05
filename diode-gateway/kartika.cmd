@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

echo =================================================================
echo  KARTIKA-CDS: Meluncurkan Gerbang Keamanan Satu Arah...
echo =================================================================

:: Otomatis buka browser setelah delay 2 detik di background
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8000/split.html"

:: Jalankan server utama
python "%SCRIPT_DIR%\run_dev.py" %*
