<#
.SYNOPSIS
    Starts the ZeroPhish Unified API Gateway with environment validation and dependency checks.

.DESCRIPTION
    This script activates the Python virtual environment, installs required packages,
    validates the .env file, and launches the gateway. It also checks for port conflicts
    and optionally runs the gateway in the background.

.PARAMETER Port
    Port on which the gateway should listen (overrides .env). Default: 8001.

.PARAMETER EnvFile
    Path to the .env file. Default: .\.env.

.PARAMETER Background
    Run the gateway in the background (as a PowerShell job).

.PARAMETER NoInstall
    Skip dependency installation (pip install).

.EXAMPLE
    .\start_gateway.ps1
    .\start_gateway.ps1 -Port 8002 -Background
#>

param(
    [int]$Port,
    [string]$EnvFile = ".\.env",
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
Write-Info "🛡️  ZeroPhish API Gateway Startup"
Write-Info "================================"

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

# 4. Environment file
if (Test-Path $EnvFile) {
    Write-Success "Environment file found: $EnvFile"
    # Load environment variables from .env (PowerShell way)
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove quotes if any
            if ($value -match '^"(.+)"$' -or $value -match "^'(.+)'$") {
                $value = $matches[1]
            }
            Set-Item -Path "env:$key" -Value $value
        }
    }
    Write-Success "Environment variables loaded."
} else {
    Write-Warning ".env file not found at $EnvFile. Creating default..."
    @"
# Gateway Configuration
GATEWAY_PORT=8001
TIER3_TIMEOUT=5

# Gemini API Key (Optional)
GEMINI_API_KEY=your_actual_gemini_api_key_here
"@ | Out-File -FilePath $EnvFile -Encoding UTF8
    Write-Success "Default .env created. Please edit it if needed."
}

# 5. Override port if specified
if ($Port) {
    Set-Item -Path "env:GATEWAY_PORT" -Value $Port
    Write-Info "Port overridden to $Port"
}

# 6. Check port availability (if we can)
$gatewayPort = [int](Get-Item -Path "env:GATEWAY_PORT" -ErrorAction SilentlyContinue).Value
if (-not $gatewayPort) { $gatewayPort = 8001 }

$portInUse = Get-NetTCPConnection -LocalPort $gatewayPort -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Warning "Port $gatewayPort is already in use by another process."
    Write-Warning "You may need to stop that process or use a different port."
    # Optionally ask to continue
    $choice = Read-Host "Continue anyway? (y/N)"
    if ($choice -ne 'y' -and $choice -ne 'Y') {
        Write-Info "Exiting."
        exit 1
    }
}

# 7. Display summary
Write-Info "Gateway Configuration:"
Write-Info "  Port: $gatewayPort"
Write-Info "  Env File: $EnvFile"
Write-Info "  Background: $Background"

# 8. Start the gateway
$gatewayScript = "Backend/gateway.py"
if (-not (Test-Path $gatewayScript)) {
    Write-ErrorMsg "Gateway script not found at $gatewayScript"
    exit 1
}

Write-Info "🚀 Starting ZeroPhish API Gateway..."
Write-Info "📡 Endpoints:"
Write-Info "   - POST /gateway/scan"
Write-Info "   - GET  /gateway/status/{scan_id}"
Write-Info "   - GET  /gateway/result/{scan_id}"
Write-Info "   - GET  /gateway/health"
Write-Info "   - API Docs: http://localhost:$gatewayPort/docs"
Write-Info ""
Write-Info "Press Ctrl+C to stop the gateway"

if ($Background) {
    # Run as a background job
    $job = Start-Job -ScriptBlock {
        param($ScriptPath, $Port)
        Set-Location (Split-Path $ScriptPath -Parent)
        python (Split-Path $ScriptPath -Leaf)
    } -ArgumentList $gatewayScript, $gatewayPort
    Write-Success "Gateway started in background (Job ID: $($job.Id))."
    Write-Info "To stop it, run: Stop-Job -Id $($job.Id)"
} else {
    # Run in foreground
    Set-Location (Split-Path $gatewayScript -Parent)
    python (Split-Path $gatewayScript -Leaf)
}