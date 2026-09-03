<#
.SYNOPSIS
    Stops the ZeroPhish staging environment (Docker Compose or local process).

.DESCRIPTION
    This script stops the staging stack by:
    - Running `docker compose down` if a Docker Compose stack is detected.
    - Terminating any process listening on the staging port (by PID).
    - Optionally stopping any background PowerShell jobs that were started with `-Background`.

    It will ask for confirmation before killing processes unless `-Force` is used.

.PARAMETER Port
    Port on which the staging gateway was running. Default: 8000.

.PARAMETER Force
    Skip confirmation prompts and force termination.

.PARAMETER KillJobs
    Also stop any running PowerShell jobs that match the staging description.

.EXAMPLE
    .\staging-down.ps1
    .\staging-down.ps1 -Port 8001 -Force
#>

[CmdletBinding()]
param(
    [int]$Port = 8000,
    [switch]$Force,
    [switch]$KillJobs
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

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# ---------- Main Script ----------
Write-Info "Stopping ZeroPhish Staging Stack (Port: $Port)"
Write-Info "================================================="

$anythingStopped = $false

# 1. Stop Docker Compose if available
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $composeFile = "docker-compose.staging.yml"
    if (Test-Path $composeFile) {
        Write-Info "Docker Compose file found. Stopping containers..."
        docker compose -f $composeFile down
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose stack stopped."
            $anythingStopped = $true
        } else {
            Write-Warning "Docker Compose down command returned non-zero exit code."
        }
    } else {
        Write-Warning "docker-compose.staging.yml not found; skipping Docker stop."
    }
} else {
    Write-Info "Docker not detected; skipping Docker stop."
}

# 2. Kill any process listening on the specified port
Write-Info "Checking for processes listening on port $Port..."
$connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($connections) {
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    if ($pids) {
        Write-Info "Found process(es) with PID(s): $($pids -join ', ')"
        if (-not $Force) {
            $confirm = Read-Host "Terminate these processes? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Info "Skipping process termination."
                exit 0
            }
        }
        foreach ($pid in $pids) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                    Write-Success "Terminated process $pid ($($proc.ProcessName))."
                    $anythingStopped = $true
                }
            } catch {
                Write-Warning "Could not terminate process $pid: $_"
            }
        }
    }
} else {
    Write-Info "No process found listening on port $Port."
}

# 3. Optionally kill background jobs
if ($KillJobs) {
    $jobs = Get-Job | Where-Object { $_.Name -like "*staging*" -or $_.Command -like "*gateway*" }
    if ($jobs) {
        Write-Info "Found $($jobs.Count) background job(s) matching staging/gateway."
        if (-not $Force) {
            $confirm = Read-Host "Stop these jobs? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Info "Skipping job termination."
            } else {
                foreach ($job in $jobs) {
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                    Remove-Job -Job $job -ErrorAction SilentlyContinue
                    Write-Success "Stopped and removed job $($job.Id)."
                    $anythingStopped = $true
                }
            }
        } else {
            foreach ($job in $jobs) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -ErrorAction SilentlyContinue
                Write-Success "Stopped and removed job $($job.Id) (forced)."
                $anythingStopped = $true
            }
        }
    } else {
        Write-Info "No matching background jobs found."
    }
}

if ($anythingStopped) {
    Write-Success "Staging shutdown complete."
} else {
    Write-Info "No staging components were found to stop."
}
exit 0