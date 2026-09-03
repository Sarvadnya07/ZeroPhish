<#
.SYNOPSIS
    Starts the ZeroPhish Isolated Staging Environment for shadow evaluation.

.DESCRIPTION
    This script launches the staging environment (either as a local process or via Docker Compose).
    It sets the required environment variables, optionally waits for health checks to pass,
    and provides options for background execution and process management.

.PARAMETER Port
    Port on which the staging gateway should listen (default: 8000).

.PARAMETER LocalProcess
    Force the use of a local Python process instead of Docker Compose.

.PARAMETER DockerCompose
    Force the use of Docker Compose (fails if Docker is not available).

.PARAMETER Background
    Run the staging process in the background (as a PowerShell job, local process only).

.PARAMETER NoWait
    Do not wait for the health check to pass before returning.

.PARAMETER Timeout
    Maximum time to wait for health checks (default: 60 seconds).

.EXAMPLE
    .\start_staging.ps1
    .\start_staging.ps1 -Port 8001 -LocalProcess -Background
    .\start_staging.ps1 -DockerCompose
#>

param(
    [int]$Port = 8000,
    [switch]$LocalProcess,
    [switch]$DockerCompose,
    [switch]$Background,
    [switch]$NoWait,
    [int]$Timeout = 60
)

$ErrorActionPreference = "Stop"

# ---------- Helper Functions ----------
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# ---------- Main Script ----------
Write-Info "🛡️  ZeroPhish Staging Environment Startup"
Write-Info "==========================================="

# 1. Set environment variables
$env:ZEROPHISH_ENV = "staging"
$env:ZEROPHISH_STAGING_BASE_URL = "http://127.0.0.1:$Port"
$env:ZEROPHISH_STAGING_ALLOWED_HOSTS = "127.0.0.1,localhost,staging.zerophish.internal"
$env:ZEROPHISH_CASCADE_SHADOW_MODE = "true"
$env:ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE = "0.10"
Write-Info "Environment variables configured:"
Write-Info "  ZEROPHISH_ENV = $env:ZEROPHISH_ENV"
Write-Info "  ZEROPHISH_STAGING_BASE_URL = $env:ZEROPHISH_STAGING_BASE_URL"
Write-Info "  ZEROPHISH_CASCADE_SHADOW_MODE = $env:ZEROPHISH_CASCADE_SHADOW_MODE"
Write-Info "  ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE = $env:ZEROPHISH_CASCADE_SHADOW_SAMPLE_RATE"

# 2. Check port availability
$portInUse = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Warning "Port $Port is already in use."
    if (-not $DockerCompose) {
        Write-Warning "If you want to use a different port, specify -Port <port>."
    }
    # Continue anyway (staging may be already running)
}

# 3. Determine launch method
$useDocker = $DockerCompose -or (-not $LocalProcess -and (Get-Command docker -ErrorAction SilentlyContinue))
$useLocal = $LocalProcess -or (-not $useDocker)

if ($useDocker -and $DockerCompose -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-ErrorMsg "Docker not detected, but -DockerCompose was specified. Aborting."
    exit 1
}

# 4. Launch staging
if ($useDocker) {
    Write-Info "Launching Docker Compose staging stack..."
    docker compose -f docker-compose.staging.yml up -d
    if (-not $?) {
        Write-ErrorMsg "Docker Compose failed to start."
        exit 1
    }
    Write-Success "Docker Compose stack started."
} elseif ($useLocal) {
    Write-Info "Launching local isolated staging process on port $Port..."

    # Construct command
    $pythonCmd = "python"
    $scriptPath = "Backend/gateway.py"
    if (-not (Test-Path $scriptPath)) {
        Write-ErrorMsg "Gateway script not found at $scriptPath. Please ensure you are in the repository root."
        exit 1
    }

    $arguments = @("-m", "uvicorn", "Backend.gateway:app", "--host", "127.0.0.1", "--port", $Port)
    if ($Background) {
        # Run as a PowerShell job
        $job = Start-Job -ScriptBlock {
            param($ScriptPath, $ArgsList)
            Set-Location (Split-Path $ScriptPath -Parent)
            & python -m uvicorn Backend.gateway:app @ArgsList
        } -ArgumentList $scriptPath, $arguments
        Write-Success "Staging process started in background (Job ID: $($job.Id))."
        # Store job ID for later management
        $env:STAGING_JOB_ID = $job.Id
    } else {
        # Run in foreground (blocking)
        Write-Info "Staging will run in the foreground. Press Ctrl+C to stop."
        Start-Process -NoNewWindow -FilePath "python" -ArgumentList $arguments -Wait
        # If we reach here, the process exited; we should exit as well.
        exit 0
    }
}

# 5. Wait for health checks (if not background and not NoWait)
if (-not $NoWait -and -not $Background) {
    Write-Info "Waiting for staging to become healthy (timeout: ${Timeout}s)..."
    $healthUrl = "http://127.0.0.1:$Port/health"
    $startTime = Get-Date
    $healthy = $false

    do {
        try {
            $response = Invoke-RestMethod -Uri $healthUrl -Method Get -ErrorAction SilentlyContinue
            if ($response -and $response.status -eq "healthy") {
                $healthy = $true
                break
            }
        } catch {
            # Ignore errors
        }
        Start-Sleep -Seconds 2
        $elapsed = (Get-Date) - $startTime
    } while ($elapsed.TotalSeconds -lt $Timeout)

    if ($healthy) {
        Write-Success "Staging is healthy and ready."
    } else {
        Write-Warning "Health check did not pass within ${Timeout}s. Please check the staging logs."
        Write-Info "You can inspect logs using: docker compose logs (if using Docker) or check the process output."
    }
} else {
    if ($Background) {
        Write-Info "Staging is running in the background. Use scripts/staging-health.ps1 to verify connectivity."
    } else {
        Write-Info "Staging startup initiated. Run scripts/staging-health.ps1 to verify connectivity."
    }
}

# 6. Display useful info
Write-Info ""
Write-Info "📡 Staging Endpoints:"
Write-Info "   - Health: http://127.0.0.1:$Port/health"
Write-Info "   - Gateway: http://127.0.0.1:$Port/gateway/scan"
Write-Info "   - Shadow control: via environment variables"

if ($useDocker) {
    Write-Info ""
    Write-Info "Docker commands:"
    Write-Info "   docker compose -f docker-compose.staging.yml logs      # view logs"
    Write-Info "   docker compose -f docker-compose.staging.yml down      # stop"
}