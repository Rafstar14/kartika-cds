<#
.SYNOPSIS
  Menjalankan KARTIKA-CDS dalam mode lokal di Windows PowerShell.
#>
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir
Set-Location $BaseDir

& "C:\Users\Hype\AppData\Local\Python\bin\python.exe" run_dev.py
