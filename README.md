<div align="center">

# 🛡️ ZeroPhish

### Browser-Centric Phishing Detection for Gmail

Detect suspicious emails using layered heuristics, machine learning, and AI through a Chrome Side Panel.

[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

[![CI](https://github.com/Sarvadnya07/ZeroPhish/actions/workflows/ci.yml/badge.svg)](https://github.com/Sarvadnya07/ZeroPhish/actions)

</div>

---

## Project Status

**Stage:** production-oriented security and reliability hardening.

ZeroPhish is a security-focused phishing detection platform built around a three-tier detection cascade, a canonical FastAPI gateway, a Chrome extension, and a Next.js dashboard. The repository includes automated security, reliability, backend, and frontend validation.

> **Security note:** Detection results are signals for investigation. No phishing detector should be treated as infallible.

---

## What Is ZeroPhish?

ZeroPhish is a browser-centric phishing detection platform for Gmail. The Chrome extension captures email context and presents the result through a Side Panel while the FastAPI gateway orchestrates layered analysis.

```text
Gmail
  │
  ▼
Chrome Extension
  │
  │ Email context
  ▼
FastAPI Gateway :8001
  │
  ├── Tier 1 — Deterministic heuristics
  ├── Tier 2 — URL / domain / ML analysis
  └── Tier 3 — Contextual AI analysis
          │
          ▼
      Final assessment
          │
          ├──────────────► SSE
          │
          ▼
     Next.js Dashboard
```

The architecture deliberately avoids making one model or one external provider the sole detection authority.

---

## Why ZeroPhish?

Phishing messages can combine deceptive URLs, impersonated domains, social engineering, redirects, suspicious infrastructure, and obfuscated or AI-generated content.

ZeroPhish therefore treats email content, URLs, redirect targets, remote responses, uploaded messages, external intelligence, and AI inputs as untrusted data. Detection is performed through multiple layers so that deterministic signals and deeper analysis can complement one another.

---

## Core Features

| Capability | Description |
|---|---|
| Gmail Chrome Extension | Manifest V3 extension with a browser Side Panel workflow |
| Tier 1 Heuristics | Fast deterministic analysis of suspicious email and URL patterns |
| Tier 2 Analysis | URL/domain analysis, metadata, threat indicators, and ML classification |
| Tier 3 AI Analysis | Contextual Gemini analysis when configured and available |
| Three-Tier Cascade | Combines different evidence sources in a single scan flow |
| Real-Time Updates | Server-Sent Events for live scan progress |
| SSRF Protection | Outbound destinations and redirects are validated before access |
| Authentication & RBAC | Protected application routes enforce authentication and role checks |
| Redis Cache | Optional Redis cache with in-memory fallback |
| Persistence | SQL-backed repositories for durable application state |
| Circuit Breaker | Protects external Tier 3 dependency paths from repeated failures |
| SSE Backpressure | Bounded subscriber queues with slow-consumer handling |
| Background Task Lifecycle | Tracks asynchronous work and bounds shutdown handling |
| Webhook Isolation | Webhook dispatch does not block scan finalization |
| Observability | Health, readiness, metrics, logging, and runtime diagnostics |

---

## Detection Pipeline

### Tier 1 — Deterministic Heuristics

The first layer is optimized for fast, explainable signals, including suspicious URL structure, IP-based URLs, urgency indicators, suspicious domains, brand/domain mismatches, and other deterministic phishing indicators implemented by the extension and gateway.

### Tier 2 — URL, Domain & ML Analysis

Tier 2 performs deeper analysis such as URL normalization, redirect-aware inspection, domain metadata, threat patterns, and machine-learning classification.

### Tier 3 — Contextual AI Analysis

Tier 3 uses Gemini for contextual analysis when configured. It can assess phishing context, social-engineering signals, suspicious intent, and related evidence. Tier 3 output is constrained by the surrounding security and scoring pipeline rather than being treated as an unrestricted authority.

---

## Scoring

The current application configuration uses the following default weighting:

```text
T1 = 20%
T2 = 30%
T3 = 50%
```

Conceptually:

```text
Final Score = (T1 × 0.20) + (T2 × 0.30) + (T3 × 0.50)
```

The current configured verdict ranges are:

| Score | Verdict |
|---:|---|
| `0–29` | SAFE |
| `30–69` | SUSPICIOUS |
| `70–100` | CRITICAL |

These thresholds are application configuration, not calibrated probabilities of maliciousness.

---

## Architecture

ZeroPhish uses a layered modular-monolith backend with one canonical API gateway.

```text
                         ┌─────────────────┐
                         │  Chrome Gmail   │
                         │   Extension     │
                         └────────┬────────┘
                                  │
                                  ▼
                    ┌────────────────────────┐
                    │ Backend/gateway.py     │
                    │ Canonical API :8001    │
                    └───────────┬────────────┘
                                │
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
          Tier 1              Tier 2             Tier 3
       Heuristics          URL / Domain / ML      Gemini
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ▼
                         Scan Result / SSE
                                │
                                ▼
                         Next.js Dashboard
```

### Backend topology

```text
Backend/
├── gateway.py
├── tier_2/
├── tier_3/
├── ml/
├── repositories/
├── infrastructure/
├── security/
├── auth/
├── models/
└── tests/
```

The repository also contains automated architecture-boundary checks covering important dependency directions between security, repositories, infrastructure, feature routers, and application orchestration.

### Legacy Tier 2 entrypoint

`tier_2/main.py` is retained as a deprecated compatibility reference. It is not the supported deployment entrypoint.

> **Supported gateway:** `Backend/gateway.py` on port `8001`.

Do not build new integrations against the legacy standalone port `8000` service.

---

## Security Model

ZeroPhish treats external data and remote destinations as untrusted.

### Security boundaries

- SSRF validation before outbound connections
- Redirect-by-redirect destination validation
- Authentication and RBAC
- Bounded input/payload handling
- Rate limiting where configured by the application
- Cache controls
- Circuit-breaker protection for external dependencies
- Bounded SSE queues and slow-consumer handling
- Secret scanning and dependency auditing
- Static security analysis
- Constrained AI/Tier 3 authority

Security tooling in the repository includes the configured Gitleaks, Semgrep, dependency, and CodeQL workflows where enabled by the current CI configuration.

---

## Components

### Chrome Extension

The Manifest V3 extension provides the Gmail integration and Side Panel workflow. It performs browser-side Tier 1 analysis and communicates with the canonical backend gateway.

Current extension permissions include the capabilities required for the product workflow, such as:

- `activeTab`
- `sidePanel`
- `storage`
- `scripting`

Host access is intentionally constrained rather than granting unrestricted access to arbitrary websites.

### Backend

Primary technologies include:

- Python
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- Redis
- SQL persistence
- ONNX Runtime / Transformers / PyTorch components used by the ML path
- Gemini integration

Canonical entrypoint:

```text
Backend/gateway.py
```

Canonical development port:

```text
8001
```

### Frontend

The dashboard uses Next.js, React, TypeScript, and Server-Sent Events to visualize scan state and results.

---

## Repository Structure

```text
ZeroPhish/
├── Backend/
│   ├── gateway.py
│   ├── tier_2/
│   ├── tier_3/
│   ├── ml/
│   ├── repositories/
│   ├── infrastructure/
│   ├── security/
│   ├── auth/
│   ├── models/
│   └── tests/
├── Frontend/
├── extension/
├── scripts/
├── docs/
├── LICENSE
└── README.md
```

Detailed engineering documentation is indexed in [`docs/INDEX.md`](docs/INDEX.md).

---

## Quick Start

### Prerequisites

- Python 3.13+
- Node.js 20+
- pnpm 10+
- Google Chrome
- Git
- Redis (optional for the cache-backed deployment path)
- Gemini API credentials when Tier 3 is required

### 1. Clone

```bash
git clone https://github.com/Sarvadnya07/ZeroPhish.git
cd ZeroPhish
```

### 2. Backend setup

#### Windows PowerShell

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
Copy-Item Backend\.env.example Backend\.env
pip install -r Backend\requirements.txt
```

#### Linux/macOS

```bash
python3.13 -m venv .venv
source .venv/bin/activate
cp Backend/.env.example Backend/.env
pip install -r Backend/requirements.txt
```

Edit `Backend/.env` for your environment.

### 3. Start the gateway

```bash
cd Backend
python gateway.py
```

The canonical gateway is:

```text
http://127.0.0.1:8001
```

Verify it with:

```bash
curl http://127.0.0.1:8001/health
```

### 4. Start the frontend

In another terminal:

```bash
cd Frontend
pnpm install
pnpm dev
```

### 5. Load the extension

1. Open `chrome://extensions/`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Select the repository's `extension/` directory.
5. Reload the extension after extension source changes.

---

## Configuration

The primary backend template is:

```text
Backend/.env.example
```

Important configuration areas include:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Persistent database configuration |
| `REDIS_URL` | Redis cache and supported shared state |
| `GEMINI_API_KEY` | Gemini Tier 3 configuration |
| `ENV` | Runtime environment |
| Metrics settings | Prometheus-compatible runtime metrics |
| OpenTelemetry settings | Optional tracing |

Never commit API keys, credentials, or `.env` files.

---

## API

The supported API is exposed through `Backend/gateway.py` on port `8001`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/gateway/scan` | Submit an email for analysis |
| `GET` | `/gateway/status/{scan_id}` | Retrieve scan status |
| `GET` | `/gateway/result/{scan_id}` | Retrieve a completed result |
| `GET` | `/gateway/health` | Gateway health information |
| `POST` | `/vision/analyze` | Vision analysis |
| `GET` | `/auth/me` | Authentication context |
| `POST` | `/email/scan-eml` | Analyze a raw `.eml` message |
| `GET` | `/analytics/threat-feed` | Threat-feed information |
| `GET` | `/cache/stats` | Cache statistics |
| `DELETE` | `/cache/clear` | Clear cached scan reports |

### Example scan request

```bash
curl -X POST http://127.0.0.1:8001/gateway/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "security@suspicious-bank.xyz",
    "subject": "URGENT: Verify your account now",
    "body": "Your account has been suspended. Verify your credentials immediately.",
    "links": [
      "http://192.168.1.1/verify",
      "http://paypa1.com/secure"
    ],
    "tier1_score": 72,
    "tier1_evidence": [
      "Urgency keyword",
      "IP-based URL",
      "Brand mismatch"
    ]
  }'
```

A completed response contains the scan identifier, tier results, evidence, score, verdict, completion state, and cache state where applicable.

---

## Webhook Semantics

Webhook events can include:

- `scan.complete`
- `scan.critical`
- `scan.suspicious`

Webhook dispatch is asynchronous so slow or unavailable receivers do not block scan finalization.

### Current delivery model

Webhook delivery is currently **best-effort / at-most-once**.

A gateway restart or process failure between scan finalization and background dispatch can lose an event. The current implementation does not provide a durable delivery ledger or transactional outbox.

The persisted scan result is the authoritative record.

Durable webhook delivery and guaranteed retry behavior are not represented as implemented functionality unless the current repository adds those guarantees.

---

## Reliability

The reliability layer focuses on controlled failure behavior and recovery.

### Database

- Explicit transaction commit/rollback handling
- Rollback on failed mutations
- Persistent repository support
- Recovery after transactional failure

### Redis

- Optional Redis-backed cache
- Connection-failure fallback
- In-memory fallback path
- Cache lifecycle management

### Circuit breaker

The Tier 3 dependency path uses circuit-breaker behavior to reduce repeated calls while an external dependency is failing.

```text
CLOSED
  │ repeated failures
  ▼
 OPEN
  │ recovery timeout
  ▼
HALF_OPEN
  │
  ├── success ──► CLOSED
  └── failure ──► OPEN
```

Distributed state behavior depends on the configured shared-state mechanism. Process-local behavior remains relevant to the deployment model.

### SSE

Subscriber queues are bounded and support backpressure handling so slow consumers do not cause unbounded queue growth.

### Background work

Asynchronous tasks are tracked so application shutdown can cancel and drain active work within a bounded shutdown window.

---

## Scaling Model

ZeroPhish currently favors explicit state ownership over assuming automatic horizontal scalability.

### Single instance

The simplest deployment keeps application and SSE subscriber state in one gateway process.

### Persistent single instance

Configure the database and Redis integrations when durable persistence and cache-backed operation are required.

### Multiple instances

Multi-instance deployment requires explicit treatment of shared state:

- database state must be shared
- Redis should be configured where shared state is required
- SSE subscribers remain instance-local
- load-balanced SSE traffic requires appropriate routing or a dedicated SSE strategy

Adding more gateway processes does not by itself make SSE state distributed.

---

## Observability

Current observability surfaces include:

- structured security/application logs
- health checks
- readiness checks
- Prometheus-compatible metrics where enabled
- optional OpenTelemetry tracing
- cache statistics
- circuit-breaker state
- SSE runtime metrics

Typical operational endpoints include:

```text
/health
/ready
/metrics
```

Exact availability depends on runtime configuration.

---

## Chrome Extension Development

The extension is a Manifest V3 application.

### Debugging

1. Open `chrome://extensions/`.
2. Inspect the ZeroPhish extension service worker.
3. Use browser DevTools for content-script, Side Panel, and messaging diagnostics.

### Hot reload

After changing extension files, reload the extension from the Chrome extensions page.

### Build

The extension uses the repository's current vanilla JavaScript extension structure and does not require a conventional application build pipeline.

---

## Testing & Quality

ZeroPhish uses multiple verification layers:

```text
Unit Tests
    │
    ▼
Integration Tests
    │
    ▼
Runtime / Network Verification
    │
    ▼
Deployment / Staging Verification
```

### Backend

```powershell
python -m pytest Backend/tests/
```

### Frontend

```powershell
cd Frontend
pnpm test
```

### TypeScript

```powershell
npx tsc --noEmit
```

### Production build

```powershell
pnpm build
```

### Security checks

```powershell
powershell -File scripts/security-gate.ps1
```

The repository separates mocked/unit evidence from runtime and network evidence. A passing unit test is not treated as proof of distributed production behavior.

---

## Troubleshooting

### Port 8001 is already in use

Windows:

```powershell
netstat -ano | findstr :8001
taskkill /PID <PID> /F
```

The supported gateway port is `8001`. Port `8000` is the deprecated standalone Tier 2 entrypoint.

### Redis connection refused

Redis is optional for configurations that support the cache fallback. When Redis is required, verify that the configured `REDIS_URL` is reachable.

### Gemini configuration

When Tier 3 is required, configure the Gemini credentials in the backend environment. Never commit the key.

### Extension not loading

Check `manifest.json` and the service-worker/content-script consoles in Chrome DevTools.

### Frontend dependency problems

Windows PowerShell:

```powershell
Remove-Item -Recurse -Force node_modules
pnpm install
pnpm test
pnpm build
```

### Backend dependency problems

Use a clean virtual environment:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r Backend\requirements.txt
pip check
```

---

## Documentation

Detailed engineering documentation is maintained under [`docs/`](docs/).

Start with [`docs/INDEX.md`](docs/INDEX.md), then use the relevant architecture, testing, reliability, security, deployment, and operations documents.

---

## Contributing

Contributions should preserve the project's security and reliability boundaries.

```bash
git checkout -b feature/your-change
```

Before opening a pull request, run the relevant validation:

```powershell
python -m pytest Backend/tests/
cd Frontend
pnpm test
npx tsc --noEmit
pnpm build
```

For security-sensitive changes:

```powershell
powershell -File scripts/security-gate.ps1
```

Pull requests should include appropriate tests and documentation, avoid unnecessary permissions, and contain no secrets or credentials.

---

## License

ZeroPhish is released under the [MIT License](LICENSE).

---

<div align="center">

**ZeroPhish — security-focused phishing detection for the browser.**

Built with Python, FastAPI, Next.js, Chrome APIs, machine learning, and AI.

</div>
