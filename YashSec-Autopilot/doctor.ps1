$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) { Write-Host "Run .\setup.ps1 first."; exit 1 }
& .\.venv\Scripts\python.exe -m app.cli doctor
