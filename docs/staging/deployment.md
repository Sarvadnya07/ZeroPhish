# ZeroPhish — Staging Deployment Guide

## Prerequisites
- Docker & Docker Compose (or local Python 3.13 virtual environment)
- Configured `.env.staging` (copied from `.env.staging.example`)

## Launching Staging Stack
### Option 1: Docker Compose (Recommended)
```bash
docker compose -f docker-compose.staging.yml up -d
```

### Option 2: PowerShell Automation
```powershell
.\scripts\staging-up.ps1
```

## Verifying Deployment
Run the automated health checker:
```powershell
.\scripts\staging-health.ps1
```
