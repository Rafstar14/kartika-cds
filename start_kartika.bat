@echo off
title KARTIKA-CDS Tactical Launcher
cd /d "%~dp0\diode-gateway"
echo ===================================================
echo   Menjalankan KARTIKA-CDS (Tactical Cyber Diode)
echo ===================================================
echo - Low-Side Web UI  : http://127.0.0.1:5000
echo - High-Side OT UI  : http://127.0.0.1:5001
echo - Split Command UI : http://127.0.0.1:8000/split.html
echo ===================================================

:: Cek Python (venv bawaan atau python sistem)
set "PY_CMD="
if exist "..\venv\Scripts\python.exe" (
    set "PY_CMD=..\venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "PY_CMD=python"
    ) else (
        where py >nul 2>&1
        if %errorlevel% equ 0 (
            set "PY_CMD=py"
        )
    )
)

if "%PY_CMD%"=="" (
    echo [ERROR] Python tidak ditemukan di komputer ini!
    echo Silakan install Python 3.10+ terlebih dahulu dari python.org
    pause
    exit /b 1
)

:: Buka browser otomatis ke Split Command Observer
start http://127.0.0.1:8000/split.html

%PY_CMD% run_dev.py
pause
