$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
& "$PSScriptRoot\build-desktop.ps1"

$Iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if (-not $Iscc) {
  $Candidates = @(
    "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
  )
  $IsccPath = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $IsccPath) { throw "Inno Setup 6 not found. Install it, then rerun this script." }
} else { $IsccPath = $Iscc.Source }
& $IsccPath "installer\YashSec-Autopilot.iss"
if (-not (Test-Path "dist\installer\YashSec-Autopilot-Setup-x64.exe")) { throw "Installer was not created." }
Write-Host "Installer ready: dist\installer\YashSec-Autopilot-Setup-x64.exe" -ForegroundColor Green
