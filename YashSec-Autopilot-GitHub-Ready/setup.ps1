$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "`nYashSec Autopilot - Windows source setup" -ForegroundColor Cyan

$pythonCmd = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = @("py", "-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = @("python")
} else {
    Write-Host "Python 3.11+ is missing." -ForegroundColor Red
    Write-Host "Install Python for Windows and enable Add Python to PATH."
    exit 1
}

if ($pythonCmd.Count -eq 2) {
    & $pythonCmd[0] $pythonCmd[1] -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
} else {
    & $pythonCmd[0] -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
}
if ($LASTEXITCODE -ne 0) { throw "Python 3.11 or newer is required." }

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating Python virtual environment..."
    if ($pythonCmd.Count -eq 2) { & $pythonCmd[0] $pythonCmd[1] -m venv .venv } else { & $pythonCmd[0] -m venv .venv }
}

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
Write-Host "Installing core dependencies..."
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ".env created from the safe example. Review it before enabling any remote integration." -ForegroundColor Green
} else {
    Write-Host ".env already exists; preserving it." -ForegroundColor DarkGray
}

& $venvPython -m app.cli init
Write-Host "`nCore setup complete." -ForegroundColor Green
Write-Host "Run .\start.ps1 and create the first Owner account in the first-run wizard."
Write-Host "Optional scanners and local AI are documented in docs\EXTERNAL_TOOLS_INSTALLATION_AND_INTEGRATION_GUIDE.md."
