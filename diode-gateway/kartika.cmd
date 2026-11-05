@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

:: Jalankan Interactive CLI Launcher
python "%SCRIPT_DIR%\cli.py" %*
