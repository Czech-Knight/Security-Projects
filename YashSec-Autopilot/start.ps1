$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Run .\setup.ps1 first." -ForegroundColor Yellow
    exit 1
}

$port = 8787
if (Test-Path ".env") {
    $line = Get-Content ".env" | Where-Object { $_ -match '^YASHSEC_PORT=' } | Select-Object -First 1
    if ($line) {
        $candidate = ($line -split '=', 2)[1].Trim()
        if ($candidate -match '^\d+$') { $port = [int]$candidate }
    }
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$url = "http://127.0.0.1:$port"
Start-Job -ScriptBlock { param($target); Start-Sleep -Seconds 2; Start-Process $target } -ArgumentList $url | Out-Null
Write-Host "YashSec Autopilot is starting at $url" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop it.`n" -ForegroundColor DarkGray
& $python -m app.server --host 127.0.0.1 --port $port --log-level info
