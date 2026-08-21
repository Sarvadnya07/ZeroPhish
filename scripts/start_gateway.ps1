# ZeroPhish Gateway Startup Script
# This script starts the unified API Gateway

Write-Host "🛡️  ZeroPhish API Gateway Startup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "✅ Activating virtual environment..." -ForegroundColor Green
    & "venv\Scripts\Activate.ps1"
}
else {
    Write-Host "⚠️  Virtual environment not found. Creating one..." -ForegroundColor Yellow
    python -m venv venv
    & "venv\Scripts\Activate.ps1"
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
}

Write-Host ""
Write-Host "🔍 Checking environment configuration..." -ForegroundColor Cyan

# Check if .env exists
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  .env file not found. Creating default..." -ForegroundColor Yellow
    @"
# Gateway Configuration
GATEWAY_PORT=8001
TIER3_TIMEOUT=5

# Gemini API Key (Optional)
GEMINI_API_KEY=your_actual_gemini_api_key_here
"@ | Out-File -FilePath ".env" -Encoding UTF8
}

Write-Host ""
Write-Host "🚀 Starting ZeroPhish API Gateway..." -ForegroundColor Green
Write-Host ""
Write-Host "📊 Gateway Features:" -ForegroundColor Cyan
Write-Host "   - Tier 1: Client-side pre-validation" -ForegroundColor White
Write-Host "   - Tier 2: Metadata + Pattern analysis" -ForegroundColor White
Write-Host "   - Tier 3: AI semantic analysis (async)" -ForegroundColor White
Write-Host "   - Scoring: T1×0.2 + T2×0.3 + T3×0.5" -ForegroundColor White
Write-Host ""
Write-Host "📡 Available Endpoints:" -ForegroundColor Cyan
Write-Host "   - POST /gateway/scan - Main scan endpoint" -ForegroundColor White
Write-Host "   - GET  /gateway/status/{scan_id} - Poll status" -ForegroundColor White
Write-Host "   - GET  /gateway/result/{scan_id} - Full result" -ForegroundColor White
Write-Host "   - GET  /gateway/health - Health check" -ForegroundColor White
Write-Host "   - API Docs: http://localhost:8001/docs" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the gateway" -ForegroundColor Yellow
Write-Host ""

# Start the gateway
python gateway.py
