# ZeroPhish — P1 Operations Runbook

**Version:** 2.0.0-p1  
**Target Audience:** Site Reliability Engineers (SRE), Security Operations Center (SOC), System Administrators  
**Operating Environment:** Single-Instance Linux / Docker / Windows Server  

---

## 1. Architecture & Port Reference

- **Canonical API Gateway:** Port `8001` (FastAPI / Uvicorn)
- **Frontend Dashboard:** Port `3000` (Next.js 16)
- **Primary Database:** SQLite (Development / Testing) or PostgreSQL (Production via `DATABASE_URL`)
- **Speed Layer Cache:** In-Memory (Default) or Redis (`REDIS_URL`)
- **SSE Stream Endpoint:** `http://localhost:8001/tier1/stream`
- **Telemetry & Prometheus Metrics:** `http://localhost:8001/metrics`
- **Readiness Probe:** `http://localhost:8001/ready`

---

## 2. Health & Monitoring Endpoints

### 2.1 Basic Health Check
```bash
curl -f http://localhost:8001/health
```
**Expected Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "tier3_circuit_breaker": "closed"
}
```

### 2.2 Prometheus Metrics
```bash
curl -s http://localhost:8001/metrics
```
Exposes:
- `http_requests_total{method, endpoint, status_code}`
- `http_request_duration_seconds{method, endpoint}`
- `sse_queue_full_total`
- `sse_events_dropped_total`
- `sse_subscriber_evictions_total`

### 2.3 Cache Statistics & Clear
```bash
# Check Cache Backend State
curl -s http://localhost:8001/cache/stats

# Clear Cache
curl -X DELETE http://localhost:8001/cache/clear
```

### 2.4 Circuit Breaker Status & Manual Reset
```bash
# Check Circuit Breaker Status
curl -s http://localhost:8001/gateway/circuit/status

# Manual Reset (if upstream recovery needs immediate forcing)
curl -X POST http://localhost:8001/gateway/circuit/reset
```

---

## 3. Incident Troubleshooting Procedures

### 3.1 Alert: Circuit Breaker Stuck in `OPEN` State
**Symptoms:** Logs indicate `Circuit 'tier3_ai_analysis' OPEN; request rejected`. Scan responses return with Tier 3 status `PROCESSING` or fallback without AI reasoning.
**Root Cause:** Upstream Gemini API is rate-limiting (HTTP 429), timing out (> 7s), or credentials (`GEMINI_API_KEY`) are missing/invalid.
**Action:**
1. Check backend logs for upstream errors:
   ```powershell
   Get-Content -Tail 50 Backend/logs/zerophish.log
   ```
2. Verify API Key validity:
   ```powershell
   $env:GEMINI_API_KEY
   ```
3. If upstream is restored, the breaker will automatically probe with a request every 30s (`CIRCUIT_BREAKER_TIMEOUT`) and reset to `CLOSED` upon success.
4. If immediate manual reset is required:
   ```bash
   curl -X POST http://localhost:8001/gateway/circuit/reset
   ```

### 3.2 Alert: SSE Subscriber Evictions Spiking
**Symptoms:** `sse_subscriber_evictions_total` counter increases rapidly. Web dashboard displays connection drops.
**Root Cause:** Network latency between clients and gateway, or browser tabs placed in background suspending WebSocket / SSE consumption.
**Policy:**
- Per-subscriber queue size is capped at 50 events.
- On saturation, newest event is pushed and oldest event is discarded (`sse_events_dropped_total`).
- If a slow client repeatedly overflows (`MAX_OVERFLOW_THRESHOLD = 5`), the gateway automatically evicts the slow subscriber to prevent server-side memory starvation.
**Action:**
1. Check connected client count in `/metrics`.
2. Ensure reverse proxy (e.g. Nginx, Cloudflare) does not buffer SSE responses (`proxy_buffering off;`).
3. Evicted clients will automatically reconnect and retrieve current state.

### 3.3 Alert: Webhook Delivery Failures
**Symptoms:** Webhook logs report `Webhook delivery error` or retries.
**Policy:**
- Webhook dispatches are executed in detached background tasks (`_spawn_background_task`) and do not block core scan responses.
- SSRF validation enforces HTTPS in production and rejects loopback/private IPv4/IPv6 ranges.
- Signatures are transmitted via `X-ZeroPhish-Signature` header (`sha256=<hex_hmac>`).
- Retries use exponential backoff with jitter up to `WEBHOOK_MAX_RETRIES` (default 3).
**Action:**
1. Verify target webhook endpoint accepts POST with JSON payload and returns HTTP 200 within 10 seconds.
2. Verify recipient validates HMAC using the subscription secret.
3. Check SSRF logs for blocked loopback or private addresses.

### 3.4 Alert: Database Rollback Errors Spiking
**Symptoms:** API returns HTTP 500 on scan submissions or incident creation.
**Root Cause:** SQLite locked by another process, disk full, or schema migration mismatch.
**Action:**
1. Verify database write permissions:
   ```powershell
   Test-Path Backend/zerophish.db
   ```
2. Check disk space:
   ```powershell
   Get-PSDrive C
   ```
3. Check PostgreSQL connection pool if running in production (`DATABASE_URL`).

---

## 4. Graceful Shutdown & Operational Deployment

ZeroPhish implements a robust graceful shutdown handler:
- Retains strong references to background tasks via `_spawn_background_task()`.
- On `SIGTERM` or `SIGINT`, drains pending background tasks up to 5.0 seconds before process exit.
- Closes the pooled httpx webhook client and Redis cache connections.
- Cleans up active SSE connections.

### Windows PowerShell Runtime
```powershell
# 1. Activate Python Environment & Start Gateway
cd Backend
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" -m uvicorn gateway:app --host 0.0.0.0 --port 8001

# 2. Start Frontend
cd ../Frontend
npm run start
```

### Docker Compose Staging Runtime
```bash
docker compose -f docker-compose.staging.yml up -d --build
```

---

## 5. Automated Operational Acceptance Verification

To execute the full evidence-hardened operational acceptance test suite:

```powershell
# 1. Multi-Process Circuit Breaker Test
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" scripts/p1_acceptance/test_circuit_multiprocess.py

# 2. Webhook Network Isolation Test (Runs local receiver on TCP 8995)
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" scripts/p1_acceptance/test_webhook_network.py

# 3. Live SSE & Performance Tests (Requires Gateway running on port 8001)
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" scripts/p1_acceptance/test_sse_network.py
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" scripts/p1_acceptance/test_http_tcp_performance.py
```
