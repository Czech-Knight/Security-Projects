$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

& "$PSScriptRoot\build-backend.ps1"
$BackendDestination = "desktop\src-tauri\resources\YashSecBackend.exe"
New-Item -ItemType Directory -Force (Split-Path $BackendDestination) | Out-Null
Copy-Item "dist\backend\YashSecBackend.exe" $BackendDestination -Force

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Rust/Cargo is required. Install the Rust MSVC toolchain." }
Set-Location "desktop\src-tauri"
cargo build --release
Set-Location $Root
$DesktopExe = "desktop\src-tauri\target\release\yashsec-autopilot.exe"
if (-not (Test-Path $DesktopExe)) { throw "Desktop executable was not created." }
New-Item -ItemType Directory -Force "dist\desktop" | Out-Null
Copy-Item $DesktopExe "dist\desktop\YashSec Autopilot.exe" -Force
Copy-Item "dist\backend\YashSecBackend.exe" "dist\desktop\YashSecBackend.exe" -Force
Copy-Item "LICENSE" "dist\desktop\LICENSE.txt" -Force
Write-Host "Portable desktop build ready: dist\desktop" -ForegroundColor Green
