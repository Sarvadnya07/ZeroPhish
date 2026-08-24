# ZeroPhish — Staging Troubleshooting Guide

## Common Symptoms & Solutions

### 1. `STAGING_UNREACHABLE`
- **Cause:** Port 8000 is not actively listening or the container failed to start.
- **Remedy:** Check `docker compose -f docker-compose.staging.yml logs` or start a local staging process using `.\scripts\staging-up.ps1 -LocalProcess`.

### 2. `ZEROPHISH_ENV must be 'staging'`
- **Cause:** Environment variable is missing or set to `production` / `development`.
- **Remedy:** Export `$env:ZEROPHISH_ENV="staging"`.

### 3. `Refusing to target production domain`
- **Cause:** `ZEROPHISH_STAGING_BASE_URL` contains `zerophish.com` or `api.zerophish.com`.
- **Remedy:** Set base URL to a valid staging host (`127.0.0.1`, `staging.zerophish.internal`).
