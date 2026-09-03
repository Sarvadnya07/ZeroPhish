<#
.SYNOPSIS
    Verifies the ZeroPhish staging environment health and connectivity.

.DESCRIPTION
    This script performs two checks:
    1. Validates the staging configuration (fail‑closed without network calls)
    2. Executes a single bounded connectivity request to the staging service
       to confirm it is reachable and healthy.

    It uses the Python CLI commands defined in the ml.data.pipeline module.

.PARAMETER BaseUrl
    Base URL of the staging service. Default: http://127.0.0.1:8000.

.PARAMETER NoConfigCheck
    Skip the configuration validation step.

.PARAMETER NoConnectivityCheck
    Skip the connectivity check (only config check).

.PARAMETER Timeout
    Timeout for the connectivity check in seconds. Default: 10.

.EXAMPLE
    .\staging-health.ps1
    .\staging-health.ps1 -BaseUrl http://localhost:8001
    .\staging-health.ps1 -NoConnectivityCheck
#>

[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [switch]$NoConfigCheck,
    [switch]$NoConnectivityCheck,
    [int]$Timeout = 10
)

$ErrorActionPreference = "Continue"

# ---------- Helper Functions ----------
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# ---------- Main Script ----------
Write-Info "Verifying ZeroPhish Staging Health ($BaseUrl)"
Write-Info "================================================="

# 1. Set environment variables (for the Python CLI)
$env:ZEROPHISH_ENV = "staging"
$env:ZEROPHISH_STAGING_BASE_URL = $BaseUrl
$env:ZEROPHISH_STAGING_ALLOWED_HOSTS = "127.0.0.1,localhost,staging.zerophish.internal"

# 2. Configuration check (zero network calls)
if (-not $NoConfigCheck) {
    Write-Info "1. Checking staging configuration..."
    $configCheck = python -u -m Backend.ml.data.pipeline external-staging-config-check 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorMsg "Staging configuration invalid."
        Write-Host $configCheck -ForegroundColor Red
        exit 1
    }
    Write-Success "Staging configuration valid."
} else {
    Write-Info "Skipping configuration check."
}

# 3. Connectivity check (single bounded request)
if (-not $NoConnectivityCheck) {
    Write-Info "2. Executing single bounded connectivity check..."
    $connectCheck = python -u -m Backend.ml.data.pipeline external-staging-check --timeout $Timeout 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-ErrorMsg "Staging service is unreachable or returned an error."
        Write-Host $connectCheck -ForegroundColor Red
        exit 1
    }
    Write-Success "Staging service is reachable and healthy."
} else {
    Write-Info "Skipping connectivity check."
}

Write-Info "`n[PASS] Staging health check passed successfully."
exit 0