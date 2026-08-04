$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) { Write-Host "Run .\setup.ps1 first."; exit 1 }
Write-Host "Installing optional Python-based scanners: Semgrep and Schemathesis" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pip install --upgrade semgrep schemathesis
Write-Host "Done. Run .\doctor.ps1 to verify." -ForegroundColor Green
