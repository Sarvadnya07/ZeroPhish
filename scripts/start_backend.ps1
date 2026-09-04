<#
.SYNOPSIS
    Starts the ZeroPhish FastAPI Backend Server (Tier 2) with environment validation and dependency checks.

.DESCRIPTION
    This script activates the Python virtual environment, installs required packages,
    validates the .env files (both root and tier_2/), and launches the backend server.
    It also checks for port conflicts and optionally runs the server in the background.

.PARAMETER Port
    Port on which the backend should listen (overrides .env). Default: 8000.

.PARAMETER EnvFile
    Path to the main .env file. Default: .\.env.

.PARAMETER Tier2EnvFile
    Path to the tier_2 .env file. Default: .\tier_2\.env.

.PARAMETER Background
    Run the backend in the background (as a PowerShell job).

.PARAMETER NoInstall
    Skip dependency installation (pip install).

.EXAMPLE
    .\start_backend.ps1
    .\start_backend.ps1 -Port 8002 -Background
#>

param(
    [int]$Port,
    [string]$EnvFile = ".\.env",
    [string]$Tier2EnvFile = ".\tier_2\.env",
    [switch]$Background,
    [switch]$NoInstall
)

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
Write-Info "🛡️  ZeroPhish Backend Startup"
Write-Info "=============================="

# 1. Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Success "Python found: $pythonVersion"
} catch {
    Write-ErrorMsg "Python is not installed or not in PATH. Please install Python 3.11+."
    exit 1
}

# 2. Virtual environment
$venvPath = "venv"
if (Test-Path "$venvPath\Scripts\Activate.ps1") {
    Write-Success "Virtual environment found: $venvPath"
} else {
    Write-Warning "Virtual environment not found. Creating one..."
    python -m venv $venvPath
    if (-not $?) {
        Write-ErrorMsg "Failed to create virtual environment."
        exit 1
    }
    Write-Success "Virtual environment created."
}

# Activate venv
& "$venvPath\Scripts\Activate.ps1"
if (-not $?) {
    Write-ErrorMsg "Failed to activate virtual environment."
    exit 1
}
Write-Success "Virtual environment activated."

# 3. Install dependencies (unless skipped)
if (-not $NoInstall) {
    Write-Info "Checking/installing dependencies..."
    $requirements = "requirements.txt"
    if (Test-Path $requirements) {
        pip install -r $requirements
        if (-not $?) {
            Write-ErrorMsg "Failed to install dependencies."
            exit 1
        }
        Write-Success "Dependencies installed."
    } else {
        Write-Warning "requirements.txt not found; skipping install."
    }
}

# 4. Environment file (root)
if (Test-Path $EnvFile) {
    Write-Success "Root environment file found: $EnvFile"
    # Load environment variables from .env
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -match '^"(.+)"$' -or $value -match "^'(.+)'$") {
                $value = $matches[1]
            }
            Set-Item -Path "env:$key" -Value $value
        }
    }
    Write-Success "Root environment variables loaded."
} else {
    Write-Warning "Root .env file not found at $EnvFile. Creating default..."
    @"
# ZeroPhish Backend Configuration
GEMINI_API_KEY=your_actual_gemini_api_key_here
"@ | Out-File -FilePath $EnvFile -Encoding UTF8
    Write-Success "Default root .env created. Please edit it if needed."
}

# 5. Environment file (tier_2)
if (Test-Path $Tier2EnvFile) {
    Write-Success "Tier-2 environment file found: $Tier2EnvFile"
    # Load tier_2 environment variables (if any)
    Get-Content $Tier2EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -match '^"(.+)"$' -or $value -match "^'(.+)'$") {
                $value = $matches[1]
            }
            Set-Item -Path "env:$key" -Value $value
        }
    }
    Write-Success "Tier-2 environment variables loaded."
} else {
    Write-Warning "Tier-2 .env file not found at $Tier2EnvFile. Creating default..."
    @"
# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379
# For Redis Cloud:
# REDIS_URL=redis://username:password@host:port
"@ | Out-File -FilePath $Tier2EnvFile -Encoding UTF8
    Write-Success "Default tier_2/.env created. Please edit it if needed."
}

# 6. Override port if specified (if backend uses PORT env var, set it)
if ($Port) {
    Set-Item -Path "env:PORT" -Value $Port
    Write-Info "Port overridden to $Port"
}

# 7. Check port availability (if we can determine the port)
$backendPort = [int](Get-Item -Path "env:PORT" -ErrorAction SilentlyContinue).Value
if (-not $backendPort) { $backendPort = 8000 }  # default

$portInUse = Get-NetTCPConnection -LocalPort $backendPort -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Warning "Port $backendPort is already in use by another process."
    Write-Warning "You may need to stop that process or use a different port."
    $choice = Read-Host "Continue anyway? (y/N)"
    if ($choice -ne 'y' -and $choice -ne 'Y') {
        Write-Info "Exiting."
        exit 1
    }
}

# 8. Display summary
Write-Info "Backend Configuration:"
Write-Info "  Port: $backendPort"
Write-Info "  Root Env: $EnvFile"
Write-Info "  Tier-2 Env: $Tier2EnvFile"
Write-Info "  Background: $Background"

# 9. Start the backend (Forward to canonical gateway)
$gatewayScript = "$PSScriptRoot\start_gateway.ps1"
if (Test-Path $gatewayScript) {
    Write-Info "⚡ Notice: tier_2/main.py is deprecated. Delegating to canonical start_gateway.ps1..."
    & $gatewayScript @PSBoundParameters
    exit $LASTEXITCODE
}

$backendScript = "Backend/gateway.py"
if (-not (Test-Path $backendScript)) {
    Write-ErrorMsg "Backend gateway script not found at $backendScript"
    exit 1
}

Write-Info "🚀 Starting ZeroPhish Unified Gateway..."
Set-Location "Backend"
python gateway.py