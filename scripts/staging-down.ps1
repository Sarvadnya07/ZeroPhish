# ==============================================================================
# ZeroPhish — Staging Deployment Shutdown Script
# ==============================================================================
[CmdletBinding()]
param ()

$ErrorActionPreference = "SilentlyContinue"

Write-Host "Stopping ZeroPhish Staging Stack..." -ForegroundColor Yellow

if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker compose -f docker-compose.staging.yml down
}

# Stop any lingering uvicorn processes on port 8000
Get-Process | Where-Object { $_.ProcessName -eq "python" -and $_.CommandLine -like "*8000*" } | Stop-Process -Force

Write-Host "Staging shutdown complete." -ForegroundColor Green
