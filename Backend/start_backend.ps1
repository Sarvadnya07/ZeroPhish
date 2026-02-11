# ZeroPhish Backend Startup Script
# This script starts the FastAPI backend server

Write-Host "🛡️  ZeroPhish Backend Startup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "✅ Activating virtual environment..." -ForegroundColor Green
    & "venv\Scripts\Activate.ps1"
} else {
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
GEMINI_API_KEY=your_actual_gemini_api_key_here
"@ | Out-File -FilePath ".env" -Encoding UTF8
}

# Check if tier_2/.env exists
if (-not (Test-Path "tier_2\.env")) {
    Write-Host "⚠️  tier_2/.env file not found. Creating default..." -ForegroundColor Yellow
    @"
REDIS_URL=redis://localhost:6379
# For Redis Cloud:
# REDIS_URL=redis://username:password@host:port
"@ | Out-File -FilePath "tier_2\.env" -Encoding UTF8
}

Write-Host ""
Write-Host "🚀 Starting ZeroPhish Backend Server..." -ForegroundColor Green
Write-Host ""
Write-Host "📊 Available Endpoints:" -ForegroundColor Cyan
Write-Host "   - API Docs:     http://localhost:8000/docs" -ForegroundColor White
Write-Host "   - Health Check: http://localhost:8000/health" -ForegroundColor White
Write-Host "   - Cache Stats:  http://localhost:8000/cache/stats" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Change to tier_2 directory and start the server
Set-Location tier_2
python main.py
