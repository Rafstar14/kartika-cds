<#
.SYNOPSIS
  Menjalankan KARTIKA-CDS dalam mode lokal di Windows PowerShell.
#>
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BaseDir = Split-Path -Parent $ScriptDir
Set-Location $BaseDir

python run_dev.py
