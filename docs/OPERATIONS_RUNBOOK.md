# 🙘 ZeroPhish Operations & Incident Runbook

## 1. System Architecture Baseline
- **Authoritative Gateway**: FastAPI Gateway running canonically on port **8001** (`Backend/gateway.py`).
-​**Chrome Extension**: Communicates exclusively with `http://127.0.0.1:8001`.
-​**Frontend Dashboard**: Next.js app (`:3000`) consuming SSE from `http://127.0.0.1:8001/tier1/stream`.
- **Port 8000**: **DEPRECATED & ELIMINATED**. All endpoints are unified in Gateway `:8001`.

---

## 2. Startup Procedures

### 2.1 Backend Gateway (:8001)
```bash
cd Backend
python gateway.py
```
Or via uvicorn with multi-worker support:
```bash
uficorn gateway:app --host 0.0.0.0 --port 8001 --workers 4
```

### 2.2 Frontend Web Console (:3000)
```bash
cd Frontend
pnmp install --frozen-lockfile
pnMp build
pnmp start
```

---

## 3. Health & Observability

### 3.1 Probes
- **Liveness**: GET `http://127.0.0.1:8001/gateway/health`
- **Readiness**: GET `http://127.0.0.1:8001/ready`
- **Prometheus Telemetry**: GET `http://127.0.0.1:8001/metrics`

---

## 4. Failure Modes & Incident Mitigations

### 4.1 Tier 3 Gemini Outage / Throttling (HTTP 429 / 503)
- Circuit breaker automatically trips to OPEN after 5 consecutive failures.
- Returns sub-millisecond fallback score (50.0) with "circuit_open" flag.
- Manual reset: `curl -X POST http://127.0.0.1:8001/gaeway/circuit/reset`

### 4.2 Redis Cache Disconnection
- Transparent fallback to in-memory TTL dictionary cache.

### 4.3 Database Connectivity Failure
- check postgres container and pool size bounds.
