$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path ".venv-build")) { py -3.11 -m venv .venv-build }
& ".\.venv-build\Scripts\python.exe" -m pip install --upgrade pip wheel
& ".\.venv-build\Scripts\python.exe" -m pip install -r requirements-build.txt
& ".\.venv-build\Scripts\python.exe" -m pytest -q
Remove-Item -Recurse -Force "build\backend", "dist\backend" -ErrorAction SilentlyContinue
& ".\.venv-build\Scripts\pyinstaller.exe" --clean --noconfirm --distpath "dist\backend" --workpath "build\backend" "packaging\yashsec-backend.spec"
if (-not (Test-Path "dist\backend\YashSecBackend.exe")) { throw "Backend executable was not created." }
Write-Host "Backend ready: dist\backend\YashSecBackend.exe" -ForegroundColor Green
