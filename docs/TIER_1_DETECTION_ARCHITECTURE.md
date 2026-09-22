# ZeroPhish — Tier 1 Detection Architecture & Trust Boundary Specification

## 1. Overview & Purpose

Tier 1 is the fast heuristic detection layer of the ZeroPhish pipeline. It performs sub-5ms deterministic analysis on email headers, body text, links, and sender identities before engaging slower metadata lookups (Tier 2) and semantic AI reasoning (Tier 3).

Prior to Phase 1.2, Tier 1 heuristics existed solely inside the Chrome Extension client (`extension/tier1.js`), and the backend gateway blindly trusted caller-supplied `tier1_score` and `tier1_evidence`.

Under Phase 1.2, **the backend is established as the authoritative Tier 1 detection engine** (`Backend/tier_1/engine.py`), while browser-reported signals are relegated to **advisory and corroborating telemetry**.

---

## 2. Client vs Server Trust Boundary

The browser environment is an untrusted boundary. Any network client or compromised browser session can send arbitrary HTTP requests directly to `POST /api/v1/scan`.

```
                    ┌─────────────────────────────────┐
                    │ Chrome Extension (Untrusted)   │
                    │  - DOM Inspection               │
                    │  - Advisory Local Heuristics    │
                    └────────────────┬────────────────┘
                                     │ HTTP (Advisory tier1_score, tier1_evidence)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ZeroPhish Canonical Gateway (Backend/gateway.py:8001)                 │
│                                                                        │
│  1. Authoritative Server-Side Analysis (Backend/tier_1/engine.py)     │
│     - URL structure, IP hostnames, Punycode, Homoglyphs                │
│     - Urgency, Credential Harvesting, Financial Fraud Phrasing         │
│     - Display Name vs Sender Domain Spoofing                           │
│     - Known Brand Spoofing & Verified Allowlisting                     │
│                                                                        │
│  2. Trust Resolution & Provenance Invariant:                           │
│     - effective_score = max(server_score, client_score)                │
│     - Attacker cannot suppress server risk: client_score=0 is ignored  │
│     - Client evidence is sanitized against HTML/CRLF & tagged:         │
│       "[Client Advisory] ..."                                          │
│     - Server evidence is deterministically tagged:                     │
│       "[Server Verified] ..."                                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Trust Boundary Invariants:
1. **Non-Downgrade Invariant**: A client cannot suppress, lower, or bypass a server-detected threat. `effective_tier1_score >= server_tier1_score` under all conditions.
2. **Corroboration Invariant**: If server finds clean content, but client observed DOM-specific threats (e.g. rendered hidden forms, obfuscated iframe), client signal escalates risk with source `corroborated`.
3. **Evidence Provenance Invariant**: Attacker-supplied evidence strings are strictly sanitized (HTML tags, CRLF, and unprintable characters stripped) and tagged `[Client Advisory]`. They can never masquerade as `[Server Verified]`.
4. **Autonomous Execution Invariant**: If client provides no Tier 1 data (direct API callers, webhooks, mail transfer agents), the backend executes Tier 1 heuristics autonomously.

---

## 3. Heuristic Rules & Scoring Semantics

The server-side heuristic engine (`Backend/tier_1/engine.py`) implements the following deterministic checks:

| Category | Check | Points | Description |
|---|---|---|---|
| **Keywords** | Urgency Patterns | +10 to +14 | Matches `urgent`, `action required`, `account locked/suspended`, `security alert`, `unauthorized`. |
| **Keywords** | Credential Harvesting | +8 to +14 | Matches `password reset`, `login`, `sign in`. |
| **Keywords** | Financial Fraud | +10 to +18 | Matches `wire transfer`, `bank transfer`, `gift card`, `invoice`, `payment`. |
| **Sender** | Allowlist Match | -20 | Sender domain matches trusted organizational domain (e.g. `google.com`, `paypal.com`). |
| **Sender** | Display Name Spoofing | +18 | Display name suggests trusted brand (e.g. "PayPal Security") but sender domain does not match. |
| **Sender** | Punycode / Homoglyphs | +12 / +16 | Sender domain contains `xn--` or non-ASCII characters. |
| **Links** | IP-Based URL | +20 | Link hostname is an IPv4 or IPv6 address. |
| **Links** | Punycode / Homoglyphs | +18 / +22 | Link hostname contains `xn--` or non-ASCII confusable characters. |
| **Links** | URL Shortener | +12 | Link hostname matches known shortener service (`bit.ly`, `tinyurl.com`, etc.). |
| **Links** | Suspicious TLD | +10 | Link domain suffix in suspicious list (`.zip`, `.mov`, `.xyz`, `.top`, etc.). |
| **Links** | Brand Mismatch | +30 | Link text or context references trusted brand but routes to external domain. |
| **Mitigation**| False-Positive Reduction| Reduces to 9 | If score > 25 from urgency, but all links belong to sender's parent org and no deceptive flags exist. |

- **Score Range**: 0 to 100 integer.
- **Status Threshold**: `CleanStatus.SUSPICIOUS` if score >= 20; otherwise `CleanStatus.CLEAN`.

---

## 4. Input & Output Schemas

### Request Schema (`GatewayScanRequest`):
```python
tier1_score: Optional[int] = Field(
    default=None,
    ge=0,
    le=100,
    description="Optional client-reported heuristic score (advisory only)",
)
tier1_evidence: Optional[List[str]] = Field(
    default_factory=list,
    max_length=50,
    description="Optional client-reported evidence strings (advisory only)",
)
```

### Response Schema (`Tier1Result`):
```python
score: int = Field(..., ge=0, le=100)
evidence: List[str] = Field(default_factory=list)
status: CleanStatus = Field(...)
execution_time_ms: Optional[float] = Field(None, ge=0)
source: str = Field(default="server_verified")  # "server_verified" | "corroborated" | "degraded"
server_score: Optional[int] = Field(default=None)
client_score: Optional[int] = Field(default=None)
client_advisory: bool = Field(default=False)
```

---

## 5. Failure Semantics

If the server-side heuristic engine encounters an unexpected parsing or runtime exception:
1. It logs the full stack trace with `exc_info=True`.
2. It **fails closed** to a degraded state:
   - `score = 50`
   - `status = "Suspicious"`
   - `category = "error"`
   - `evidence = ["Tier 1 server-side analysis degraded due to internal error: <ExceptionName>"]`
   - `degraded = True`
3. Under NO circumstances does a failure default to `score = 0` or `SAFE`.
