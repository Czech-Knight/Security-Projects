param(
  [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

Write-Host "Checking health endpoint..."
Invoke-RestMethod -Uri "$BaseUrl/health" | Out-Null

Write-Host "Checking projects endpoint..."
Invoke-RestMethod -Uri "$BaseUrl/api/projects" | Out-Null

Write-Host "Checking dashboard endpoint..."
Invoke-RestMethod -Uri "$BaseUrl/api/dashboard" | Out-Null

Write-Host "Smoke test completed successfully."
