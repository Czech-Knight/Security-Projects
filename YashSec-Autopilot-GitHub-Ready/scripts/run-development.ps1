$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
$env:YASHSEC_HOST = "127.0.0.1"
$env:YASHSEC_PORT = "8787"
$env:YASHSEC_DOCS_ENABLED = "true"
& ".\.venv\Scripts\python.exe" -m app.server --host 127.0.0.1 --port 8787 --log-level info
