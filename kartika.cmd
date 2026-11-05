@echo off
setlocal
set "SCRIPT_DIR=%~dp0diode-gateway"
if not exist "%SCRIPT_DIR%\cli.py" (
    set "SCRIPT_DIR=%~dp0"
)

:: Jalankan Interactive CLI Launcher
python "%SCRIPT_DIR%\cli.py" %*
