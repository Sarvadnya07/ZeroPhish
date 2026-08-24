# ==============================================================================
# ZeroPhish — Staging Health & Connectivity Verification Script
# ==============================================================================
[CmdletBinding()]
param (
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Continue"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Verifying ZeroPhish Staging Health ($BaseUrl)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$env:ZEROPHISH_ENV = "staging"
$env:ZEROPHISH_STAGING_BASE_URL = $BaseUrl
$env:ZEROPHISH_STAGING_ALLOWED_HOSTS = "127.0.0.1,localhost,staging.zerophish.internal"

# 1. Config Check (Zero network calls)
Write-Host "`n1. Checking Staging Configuration..." -ForegroundColor Yellow
python -u -m Backend.ml.data.pipeline external-staging-config-check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Staging configuration invalid." -ForegroundColor Red
    exit 1
}

# 2. Single Bounded Connectivity Check
Write-Host "`n2. Executing Single Bounded External Connectivity Check..." -ForegroundColor Yellow
python -u -m Backend.ml.data.pipeline external-staging-check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Staging service is unreachable." -ForegroundColor Red
    exit 1
}

Write-Host "`n[PASS] Staging health check passed successfully." -ForegroundColor Green
