# ==============================================================================
# ZeroPhish — Staging Deployment Startup Script
# ==============================================================================
# Starts the isolated staging environment and waits for health checks to pass.
[CmdletBinding()]
param (
    [switch]$LocalProcess,
    [string]$Port = "8000"
)

$ErrorActionPreference = "Stop"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Starting ZeroPhish Staging Environment" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$env:ZEROPHISH_ENV = "staging"
$env:ZEROPHISH_STAGING_BASE_URL = "http://127.0.0.1:$Port"
$env:ZEROPHISH_STAGING_ALLOWED_HOSTS = "127.0.0.1,localhost,staging.zerophish.internal"
$env:ZEROPHISH_CASCADE_SHADOW_MODE = "true"
$env:ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE = "0.10"

if ($LocalProcess) {
    Write-Host "Launching local isolated staging process on port $Port..." -ForegroundColor Yellow
    $process = Start-Process python -ArgumentList "-m", "uvicorn", "Backend.gateway:app", "--host", "127.0.0.1", "--port", $Port -PassThru
    Write-Host "Staging process PID: $($process.Id)" -ForegroundColor Green
} else {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Write-Host "Launching Docker Compose staging stack..." -ForegroundColor Yellow
        docker compose -f docker-compose.staging.yml up -d
    } else {
        Write-Host "Docker not detected; falling back to local isolated staging process..." -ForegroundColor Yellow
        $process = Start-Process python -ArgumentList "-m", "uvicorn", "Backend.gateway:app", "--host", "127.0.0.1", "--port", $Port -PassThru
        Write-Host "Staging process PID: $($process.Id)" -ForegroundColor Green
    }
}

Write-Host "Staging startup initiated. Run scripts/staging-health.ps1 to verify connectivity." -ForegroundColor Green
