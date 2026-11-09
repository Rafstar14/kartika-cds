@echo off
title KARTIKA-CDS Terminator
echo Menghentikan seluruh proses KARTIKA-CDS...

powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*kartika*' -or $_.CommandLine -like '*diode-gateway*' -or ($_.Name -match 'python' -and (Get-NetTCPConnection -LocalPort 5000, 5001, 8000 -OwningProcess $_.ProcessId -ErrorAction SilentlyContinue)) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host 'Komponen dihentikan: PID' $_.ProcessId }"

echo.
echo Seluruh layanan KARTIKA-CDS telah berhasil dimatikan.
timeout /t 3 >nul
exit
