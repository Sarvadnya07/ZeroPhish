# ZeroPhish — Phase 1 Final Production Readiness Report

**Phase:** 1.10 — Final Production Readiness Gate
**Date:** 2026-09-22
**Scope:** Consolidation and readiness determination for Phases 1.1 – 1.9
**Method:** Repository inspection, source reading, targeted runtime probes, four parallel read-only audits (frontend, extension, test integrity, documentation), and corrective changes.

---

## 1. Executive Summary

Phase 1.10 set out to determine whether the current ZeroPhish implementation can
legitimately be declared the completed Phase 1 baseline. It cannot, yet.

**The backend architecture is real and largely sound.** The canonical Gateway
(`Backend/gateway.py`) is a single production entry point; `Backend/main.py` is a
genuine delegation shim; the fusion engine structurally enforces a monotonic
security floor; Tier 1 is server-authoritative with a correct client trust
boundary; Tier 2/Tier 3/Vision each distinguish failure from benign outcome; and
`fail → SAFE`, `timeout → SAFE`, and `UNKNOWN → SAFE` are all structurally
prevented on the server side.

**The defects that block acceptance are not in the detection engine — they are at
the point where results are displayed and at the point where claims are
documented.** Every client that consumes the canonical result had at least one
path where a non-result was rendered as a benign one:

| Client | Defect (verified by reading source) |
|---|---|
| Extension | Local Tier 1 category `phishing` fell through `setVerdict` to a **green "SAFE"** pill |
| Extension | A **failed/timed-out Vision call rendered "Visual Checks Passed"** + T3 "Verified" |
| Extension | A **polling failure asserted "3-Tier Analysis finalized successfully."** |
| Frontend | Absence of evidence rendered as heuristic **"pass"**; an explicitly incomplete scan could render **"complete"** (gating Safe-Passage/Quarantine affordances) |

These are display-layer violations of the exact invariants Phases 1.6–1.9
established server-side. They are now **corrected in the working tree**, with
regression tests added, but **the corrections are UNVERIFIED** (see §18 — the test
suite could not be executed in this session).

Two further systemic findings prevent a clean acceptance regardless of the code
fixes:

1. **The Phase 1 baseline is not committed.** The canonical fusion engine, the
   server Tier 1 engine, the Tier 3 provider abstraction, the Vision security
   boundary, and ~12 phase test modules exist only as **untracked working-tree
   files**. CI checks out the repository, so **CI status for the audited tree is
   NOT-PROVEN** — and the committed repository does not contain the architecture
   this report describes.

2. **Documentation carried materially false capability claims**, including a
   security document describing an authentication system (PBKDF2, TOTP MFA,
   `/auth/login`) that **does not exist**, and pipeline claims referencing
   **OCR/OpenCV/Tesseract** code that is not in the repository. The most
   consequential have been corrected (§23).

**Recommendation: HOLD.** See §30 for the precise, short list of conditions that
close it.

---

## 2. Final Phase 1 Status

| Dimension | Status |
|---|---|
| Canonical Gateway architecture | **VERIFIED** |
| Server-authoritative Tier 1 + client trust boundary | **VERIFIED** (unit + integration) |
| Tier 2 resilient cascade | **VERIFIED** (unit + integration) |
| Tier 3 provider abstraction | **UNIT-VERIFIED**; live vendor calls **NOT-PROVEN** |
| Vision local image security | **VERIFIED** |
| Vision live semantic multimodal | **NOT-PROVEN** |
| Canonical fusion + monotonic floor | **VERIFIED** (structural + deterministic grid) |
| SSRF protection | **VERIFIED** (bounded matrix) |
| Normalization (Unicode/IP/FQDN) | **VERIFIED** (bounded corpus) |
| Scan lifecycle / state store | **PARTIALLY VERIFIED** — runtime persistence only |
| SSE / REST / polling contracts | **PARTIALLY VERIFIED** — two payload shapes on one feed |
| Frontend integration | **DEFECTIVE → CORRECTED (UNVERIFIED)** |
| Extension integration | **DEFECTIVE → CORRECTED (UNVERIFIED)** |
| Concurrency isolation | **PARTIALLY VERIFIED** — no true concurrent-scan test |
| Build / typecheck | **NOT-RUN** this session; CI configuration is coherent |
| CI verification | **NOT-PROVEN** for the audited tree (uncommitted files) |
| External deployment | **NOT-PROVEN** — no deployment exercised |
| Documentation accuracy | **DEFECTIVE → PARTIALLY CORRECTED** |

---

## 3. Architecture Summary

### 3.1 Canonical map (as inspected)

```
                    CLIENT
              /                 \
       WEB DASHBOARD        EXTENSION (MV3)
              \                 /
               ↓               ↓
              Backend/gateway.py  :8001    ← single production entry point
                    ↓
      Tier 1  tier_1/engine.py       (server-authoritative, fail-safe degraded)
                    ↓
      Tier 2  tier_2/analyzer.py     (cache → WHOIS → API → RDAP; SSRF-hardened)
                    ↓
      Tier 3  tier_3/router.py       (provider-agnostic: gemini/openai_compatible/ollama)
                    ↓
      Vision  vision/service.py      (pre-decode validation → multimodal → local forensics)
                    ↓
      Fusion  fusion/engine.py       (canonical evidence → deterministic verdict)
                    ↓
      State   repositories/factory.py (SQL when DATABASE_URL, else in-memory)
               /            \
        REST/POLLING        SSE  /tier1/stream
               \            /
                FRONTEND (Next.js) + EXTENSION
```

The implementation **matches the intended baseline**, with the qualification in
§12 (the dashboard's SSE/REST feed carries two different payload shapes).

### 3.2 Entry-point verification

- `Backend/gateway.py` — canonical app, `GATEWAY_PORT` default **8001**. **VERIFIED.**
- `Backend/main.py` — 194-line shim: re-exports `gateway.app` as `app`, retains
  legacy models for tests. **No separate implementation.** **VERIFIED.**
- `Backend/tier_2/main.py` — 29-line shim. **VERIFIED** (docs claiming 736 lines are stale).
- No secondary production scan engine, no second FastAPI app in tests
  (grep for `FastAPI(` across `Backend/tests/`: **NOT FOUND**).
- The extension and frontend reach analysis only through port 8001.

### 3.3 Path classification

| Path | Classification | Justification |
|---|---|---|
| `Backend/gateway.py` | **KEEP** | Canonical entry point |
| `Backend/main.py` | **DEPRECATE** | Genuine delegation shim; legacy models used only by tests. Not removable without touching tests. |
| `Backend/tier_2/main.py` | **DEPRECATE** | 29-line shim |
| `GET/POST /tier1/report` | **KEEP + HARDENED** | Legacy extension→dashboard bridge; no live caller remains (extension defines but never calls it). Now API-key gated. |
| `extension/worker.js` | **REMOVE (documented)** | Unreferenced stub; not in manifest or web-accessible resources. Left in place pending owner confirmation — removal is cosmetic. |
| `Frontend/lib/api.ts` `scan.*` | **KEEP (dead)** | `GatewayScanResponse` client exists with zero call sites. Not deleted (it is the intended canonical client); its deadness is the finding. |
| `Backend/ml/**` staging/benchmark | **KEEP (offline)** | Training/evaluation tooling, not on the scan path |

---

## 4. Security Invariants

### A. Server authority — **VERIFIED**

`gateway.py` recomputes Tier 1 server-side (`analyze_tier1_server`) and treats
client input as advisory:

```python
effective_t1_score = max(server_t1.score, client_score)   # escalate only
```

The client cannot suppress or downgrade a server finding. Client evidence is
sanitized (`sanitize_client_evidence`) and tagged `[Client Advisory]`; the true
`server_score` and `client_score` are recorded separately.
**Evidence:** `Backend/tier_1/engine.py:238-256`, `Backend/gateway.py` scan handler;
`Backend/tests/test_tier1_trust_boundary.py`.

### B. Monotonic security floor — **VERIFIED (structural)**

`FusionEngine.fuse` applies three explicit invariants after computing the fused
score (`Backend/fusion/engine.py:334-350`):

- **A** — a `CRITICAL` partial forces `final_score ≥ 70`.
- **B** — a `SUSPICIOUS` partial forces `final_score ≥ 30`.
- **C** — if both advisory tiers failed, `final_score = partial_score` exactly.

Plus verdict-level monotonicity at `:369-381`.

> **Terminology:** the implementation **structurally enforces** the invariant, and
> randomized tests provide **empirical validation**. This is not a mathematical
> proof. The randomized test (`test_phase1_8_adversarial.py:428`, 50 seeded
> iterations) is a regression canary; the stronger evidence is the deterministic
> 900-combination grid at `test_phase1_7_fusion.py:512-530` and the exact-score
> assertions at `:585,:598,:608`.

### C. Failure safety — **VERIFIED**

| Failure | Result | SAFE? |
|---|---|---|
| Tier 1 internal exception | score 50, `degraded=True`, status Suspicious | No |
| Tier 2 exception | score 50, `DomainStatus.ERROR` → fusion marks degraded | No |
| Tier 3 timeout/error | `TierStatus.TIMEOUT`/`FAILED`, excluded from fusion | No |
| Invalid AI output | `AI_INVALID_RESPONSE`; validator rejects | No |
| Vision failure | `visual_score=None`, status FAILED/TIMEOUT/INVALID_IMAGE | No |
| Domain lookup failure | `LOOKUP_FAILED` → `t2_degraded` | No |
| Neither authoritative tier | `partial_score=None` → **UNKNOWN** | No |

### D. UNKNOWN ≠ SAFE — **VERIFIED (server)** / **PARTIALLY VERIFIED (clients)**

`Verdict.UNKNOWN` is a distinct enum member; `determine_canonical_verdict`
returns it when `score is None` or deterministic evaluation did not run. The
frontend previously collapsed `UNKNOWN` into a confident `warning`/`threat`
(over-warning, not fail-open — see §13/§27 P2). The extension renders UNKNOWN
distinctly.

### E. VISUAL_REQUIRED distinct — **VERIFIED (server)** / **DEFECTIVE (clients, corrected)**

Server: `VisionStatus.VISUAL_REQUIRED` with `requires_followup=True` is produced
when Tier 3 flags `requires_visual_check` and no screenshot is available; fusion
preserves it (`fusion/engine.py:318-323`).

Clients: **the frontend adapter dropped `requires_visual_check` and the entire
`vision` dimension**; the extension never read `vision` at all. A scan needing
manual visual follow-up rendered identically to a completed clean scan.
→ **Partially corrected:** the extension now surfaces it in the result summary.
The frontend still drops it (see §27, P2-3, deferred — requires new UI surface).

### F. Vision authority — **CORRECTED, with a nuance**

Vision cannot create `CRITICAL` **from a clean baseline**: its maximum
contribution cannot reach the 70-point threshold alone.

**However**, the previously documented bound "≤ 15 pts" is **factually wrong**.
`ESTABLISHED_PROFILES[("tier1","tier2","vision")]` assigns vision weight **0.25**
(the Tier-3-absent path), so vision contributes up to **25 points**. In that
profile, a scan already at T1=T2=69 (SUSPICIOUS) plus vision=100 reaches 76.75 →
**CRITICAL**. Vision therefore *can* tip a near-threshold SUSPICIOUS result into
CRITICAL by corroboration. This is not independent authority, but it is weaker
than the documented claim. Documentation corrected in
`docs/PHASE_1_9_RUNTIME_INTEGRITY_REPORT.md`.

### G. Additional defect found and fixed — degraded-Tier-1 laundering

When a client supplied `tier1_score`, the gateway's provenance logic returned
`"server_verified"` **even when `server_t1.degraded` was True** — the client
signal laundered an internal server failure into a verified result, hiding the
degradation from the fusion engine and from operators. Fixed to preserve
`"degraded"`; regression test added.

---

## 5. Detection Pipeline Verification

| Stage | Status | Evidence |
|---|---|---|
| Tier 1 heuristics | **VERIFIED** | `tier_1/engine.py`; `test_tier1_engine.py` (18), `test_tier1_adversarial.py` (12) — real engine, no mocks |
| Tier 2 cascade | **VERIFIED** | `tier_2/analyzer.py`, `whois_client.py`; `test_tier2_phase1_4.py` (18) |
| Tier 3 routing/validator | **UNIT-VERIFIED** | `test_tier3_phase1_5b.py` — real router/validator, mock providers |
| Vision boundary | **VERIFIED** (local) | `test_vision_phase1_6.py` (21) |
| Fusion | **VERIFIED** | `test_phase1_7_fusion.py` (31) — exact fused-score assertions |
| Client trust boundary | **VERIFIED** | `test_tier1_trust_boundary.py`, `test_phase1_8_adversarial.py` |

**Notable positive finding:** `fuse_detection_results`,
`determine_canonical_verdict`, and `calculate_fused_score` are **never mocked
anywhere** in the suite. The fusion tests assert exact numeric outputs against the
real engine. This is genuine, non-tautological coverage of the most
security-critical component.

---

## 6. Gateway Verification

**Verified route inventory** (all terminate in the Gateway): `/gateway/scan`
(+ `/scan`, `/api/v1/scan`), `/gateway/status/{id}` (+2 aliases),
`/gateway/result/{id}`, `/health` (+2), `/ready` (+2), `/metrics`,
`/cache/stats`, `/cache/clear`, `/gateway/circuit/status`, `/gateway/circuit/reset`,
`/tier1/latest`, `/tier1/report`, `/tier1/stream`, plus included routers
(auth, webhooks, incidents, email_scanner, analytics, awareness, vision).

**Defects found and fixed:**

| ID | Defect | Fix |
|---|---|---|
| G-1 | `/tier1/report`, `/cache/clear`, `/gateway/circuit/reset` were **unauthenticated** while every other mutating route required an API key. `/tier1/report` overwrites the dashboard's live feed and broadcasts to all SSE subscribers. | Added `Depends(verify_api_key)` to all three; added the status rate limit to `/tier1/report`. Behaviour unchanged when `API_KEY` is unset (dev default). |
| G-2 | `_sse_subscriber_overflows` gained an entry per subscriber per event but was only cleaned on **eviction**, never on normal disconnect → unbounded growth with subscriber churn. | Pop the entry in the stream's `cleanup()` background task. |
| G-3 | Stale module docstring asserting a fixed scoring formula. | Corrected. |

**Deployment caveat (not a code defect):** `docker-compose.staging.yml` does not
set `API_KEY`, so `verify_api_key` returns early and **staging is
unauthenticated by configuration**. The staging stack publishes `8001:8001` and
permits localhost CORS origins with `allow_credentials=True`. This is a
**configuration posture finding** — documented, not silently changed, because
altering it could break the documented staging clients.

---

## 7. Scan Lifecycle Verification

**States (semantics equivalent to the required model):**
`INIT → PARTIAL(layers=2, complete=false) → [background `_finalize_tier3`] →
COMPLETE(layers=3|4, complete=true)`, with `TierStatus.PROCESSING → COMPLETE |
FAILED | TIMEOUT` for Tier 3, and `VISUAL_REQUIRED` / `UNKNOWN` as distinct outcomes.

**Verified:** unique UUIDv4 scan IDs; per-scan state with no cross-scan
contamination; read-modify-write of a scan is performed under `scan_results_lock`;
no backwards transitions; terminal state is stable.

**Runtime persistence only.** The default repository is
`InMemoryScanResultRepository` (bounded, 500 entries, FIFO eviction) whenever
`DATABASE_URL` is unset; SQL repositories are used when it is set, and
`_check_production_persistence_requirement()` fails closed **only** when
`ZEROPHISH_ENV=production`.

> **Terminology rule applied:** this is **runtime scan-state persistence**. It is
> **durable persistence** only when `DATABASE_URL` is configured. A SQLite
> restart-durability test exists (`test_blackbox_durability.py`, run with an
> explicit `DATABASE_URL`), and `docs/ZERO_PHISH_P0_FINAL_ACCEPTANCE.md` records
> a multi-process restart verification. That evidence covers the **configured-SQL**
> path, not the default. The unqualified "Durability verified 100%" claim was
> therefore overstated.

**Coverage gap:** no test runs two scans through the real gateway **concurrently**;
`test_concurrent_scans_have_isolated_state_and_unique_ids` issues five
**sequential** requests. Genuine interleaving on `scan_results_lock` is unverified.
The test's docstring has been corrected to state this accurately.

---

## 8. SSE / Polling Verification

**Verified equivalent across transports:** the frontend consumes SSE and REST
through the *same* function (`applyLiveReport` → `gatewayScanResponseToScanResult`),
so field mapping cannot drift between them by construction. SSE framing matches
the backend (`event: ping` named events; unnamed `data:` for reports).

**Defects:**

| ID | Defect |
|---|---|
| S-1 | **Two incompatible payload shapes share one feed.** `_latest_tier1_report` (serving `/tier1/latest` and replayed on `/tier1/stream` connect) is written by *both* `_notify_live_dashboard` (rich: `tier_details`, `vision`, `complete`, `layers_completed`) *and* `POST /tier1/report` (flat `Tier1ReportPayload`: no `tier_details`, no `vision`, no `complete`). A consumer cannot tell which shape it has. |
| S-2 | The flat shape has **no `complete` field**, so the adapter's completeness heuristics are the only signal — which is how the frontend "incomplete → complete" defect became reachable. |
| S-3 | Unauthenticated `POST /tier1/report` could replace a server-verified scan payload with an advisory one. **Fixed** (§6 G-1) for the authenticated configuration; the shape-mixing remains. |

---

## 9. Frontend Verification

**Canonical contract:** there is **no single canonical type**. Three coexist:
`ScanResult` (view model), `GatewayScanResponse` (labelled "canonical" in
`live-tier1.ts:12-15`), and the deprecated `Tier1Report`. The adapter collapses
the union behind **two unvalidated casts** (`live-tier1.ts:157-158`), which
defeats the project's `strict` TypeScript setting on the entire scan path.

**Dead canonical client:** `api.scan.status/result` (`lib/api.ts:44-47`) return
`GatewayScanResponse` and have **zero call sites**. The declared canonical
contract is never fetched.

**Defects found and fixed:**

| ID | Defect | Fix |
|---|---|---|
| F-1 | **Absence of evidence rendered as `"pass"`.** `regexStatus`/`linkStatus` terminated in `"pass"`, and `t1Score` defaulted to `0` with empty check/kind sets on the live path → "received nothing" displayed as "checked and clean". | Gate on evidence presence; return `"pending"` when there is nothing to evaluate. |
| F-2 | **Fabricated authentication verdicts.** `spf`/`dkim`/`dmarc` were derived from the *Tier 2 numeric score* (`t2Score >= 50 ? warning : "pass"`), rendering "SPF pass / DKIM pass / DMARC pass" immediately above "Domain Age: Tier 2 disabled". The gateway does not transmit SPF/DKIM/DMARC on this feed at all. | Report as `"pending"` (not evaluated) with an explanatory comment. |
| F-3 | **Fabricated WHOIS/hosting data.** `domainAge: "Established"` and `hostingProvider: "Active (Verified)"` were arithmetic on `t2Score`; no age or hosting field exists in `Tier2Result`. | Absent data now renders "Not available"; the neutral colour branch was corrected so it is not rendered as safe-cyan. |
| F-4 | **Incomplete scan rendered as `complete`.** `phase = gw.complete ? "complete" : layersCompleted < 3 ? "scanning" : "complete"` promoted an explicitly-unfinished report to `"complete"`, which gates the "Safe Passage"/"Quarantine" affordances in `tactical-actions.tsx`. | `complete === false` now always yields `"scanning"`. |
| F-5 | Tier 3 "no markers" rendered in the **safe colour** even when Tier 3 never ran or failed. | Gated on `tier3.active`; otherwise "Semantic analysis was not produced for this scan." |

**Not fixed (deferred, documented — see §27):** the `ThreatLevel` type has no
`unknown` member, so `UNKNOWN` renders as a confident `warning`/`threat`; the
`vision` dimension and `requires_visual_check` are still dropped; no runtime
schema validation on the wire payload.

---

## 10. Extension Verification

Transport: REST polling only (`/gateway/scan` → `/gateway/status/{id}` →
`/gateway/result/{id}`), 400 ms × 45. All requests target port 8001 — **no tier
bypass**. Stale-result prevention exists via a `runId` guard on the main scan
flow.

**Defects found and fixed:**

| ID | Severity | Defect | Fix |
|---|---|---|---|
| E-1 | **P0** | `setVerdict` handled only the *server* verdict vocabulary. The local Tier 1 category `phishing` (and `spam`) matched no branch and fell to the `else` → **green "SAFE (0-29) ✓"**. Reachable at score 8 (a body containing only "sign in" sets `kind: credential` → category `phishing`). | Added a total `VERDICT_ALIASES` map (`phishing→CRITICAL`, `spam→SUSPICIOUS`); the fallback is now `UNKNOWN`, never SAFE; a defensive `else` renders unknown, not benign. |
| E-2 | **P0** | **A failed Vision call rendered "Visual Checks Passed." + SAFE + "Verified".** `data.is_phishing` is `False` whenever `visual_score is None` (FAILED/TIMEOUT/INVALID_IMAGE/VISUAL_REQUIRED), routing to the success branch. | Only `SUCCESS`/`HEURISTIC_FALLBACK` **with a numeric score** is a completed check; everything else renders "Visual Check Inconclusive" with `UNKNOWN`. |
| E-3 | **P0** | On polling failure the panel called `finishScanWithResult(gData)`, where `tier3_status` is `"processing"` → Tier 3 showed **"Standby"** and the summary asserted **"3-Tier Analysis finalized successfully."** | `processing`/unrecognised now renders **"Incomplete"**; a partial score is labelled "Partial Threat Score (Tier 3 incomplete)"; the success sentence is only emitted when the server said complete. |
| E-4 | P1 | The panel showed **green SAFE at rest and for the whole scan window**, including in static HTML before JS ran. | Added a neutral `pending` state ("NOT SCANNED") with a new non-green CSS class; `resetUI` and the static markup use it; the local advisory no longer defaults to `'SAFE'`. |
| E-5 | P1 | `VISUAL_REQUIRED` was **never rendered**. | Now surfaced in the result summary via `requires_visual_check` / `vision.requires_followup`. |
| E-6 | P1 | `background.js` added **every** tab with a password field to `suspiciousTabs` unconditionally, then asserted *"You are typing a password into a suspicious or critical threat page!"* — a critical claim no analysis produced. Never cleared on navigation. | Suspicious marking now requires an explicit `THREAT_VERDICT` message; verdicts are cleared on navigation and tab close. **The interstitial is consequently inert** — no component emits `THREAT_VERDICT`. This is deliberate: the module must not assert a threat it cannot support. Documented in-code. |
| E-7 | P1 | The Clerk session **bearer token** was read from and written to `chrome.storage.sync` (cloud-replicated, unencrypted at rest). | Token now read/removed via `chrome.storage.local`; non-sensitive config stays in `sync`. |

**Positive:** no direct tier invocation, no `externally_connectable` (web pages
cannot reach the content script), and the pill's score thresholds (30/70) match
the canonical fusion thresholds.

---

## 11. Concurrency Verification

| Shared state | Protection | Assessment |
|---|---|---|
| `scan_results_lock` (asyncio.Lock) | Guards all scan repo RMW | **VERIFIED** by reading |
| `_sse_subscribers` / `_sse_subscriber_overflows` | Single eviction owner in `_broadcast_to_subscribers`; now also cleaned on disconnect | **Fixed (leak)** |
| `scan_started_at` (`BoundedScanTracker`) | Bounded 5000 / 600 s, FIFO eviction on insert | **VERIFIED** (note: FIFO, not LRU as one doc claims) |
| `_latest_tier1_report` (module global) | **No lock** | Race window is a single assignment of an immutable dict — benign, but unsynchronised |
| Circuit breaker | `test_refactoring_improvements.py:43-78` asserts real HALF_OPEN probe interleaving | **Strongest race test in the suite** |
| ML model singleton | `test_tier2_phase1_4.py:234-248` gathers 10 concurrent initialisations | **VERIFIED** |

**Gap:** no test interleaves two scans through the real gateway. Terminal-state
overwrite and cleanup races are therefore **NOT-PROVEN**.

---

## 12. SSRF Verification — **VERIFIED (bounded)**

`is_safe_webhook_url` (`security/middleware.py:160-235`) resolves the hostname and
checks every resolved address against reserved subnets including loopback, RFC1918,
link-local, **169.254/16 cloud metadata**, CGNAT, multicast/reserved, IPv6
ULA/link-local, IPv4-mapped IPv6, and NAT64 `64:ff9b::/96`; it rejects embedded
URL credentials. Alternate numeric IP forms (decimal/hex/octal) are normalised via
`socket.inet_aton` before classification. Tier 2's redirect handling revalidates
pre-socket with a bounded hop count (`tier_2/analyzer.py:145-170`).

**Residual risks (documented, not fixed):**
- **DNS-rebinding TOCTOU:** the check resolves and validates, but the subsequent
  HTTP client resolves independently — the validated IP is not pinned. Mitigated
  by short timeouts; not eliminated.
- **`192.0.0.0/24`** is absent from `RESERVED_SUBNETS`; **6to4 `2002::/16`** can
  embed IPv4 and is not unwrapped.
- **Outbound paths outside centralized validation:** the Ollama provider
  (`OLLAMA_BASE_URL`, default `http://localhost:11434`) and the offline ML data
  adapters (`ml/data/feed_adapters.py`, `verifier.py` via `urllib.request.urlopen`)
  do not pass through `is_safe_url`. These are **operator-configured**, not
  user-influenced, and the ML adapters are off the production request path — but
  they are genuine bypasses of the central chokepoint and are recorded as such.

---

## 13. Input / Normalization Verification — **VERIFIED (bounded)**

- NFKC normalisation + zero-width/format-control stripping + Cyrillic homoglyph
  transliteration before keyword matching (`tier_1/engine.py:278-312`), with an
  obfuscation penalty.
- Trailing-dot FQDN normalisation (`rstrip(".")`), `www.` stripping, punycode and
  non-ASCII detection on sender and links.
- Alternate IP representations detected via `ipaddress` + `inet_aton` with a
  digit/`0x` guard.
- Reserved-scheme rejection (`javascript:`, `data:`, `file:`, …), CRLF/control
  rejection, length and count bounds.

**Parser-disagreement check:** validation (`validate_url`), SSRF
(`is_safe_webhook_url`), Tier 1 (`normalize_domain`/`base_domain`), and Tier 2 use
consistent definitions; no incompatible "same URL" exists across them.

**Known weaknesses:** the public-suffix list is a small hardcoded allowlist
(multi-part suffixes outside it are mis-parsed); `SUSPICIOUS_TLDS` is a fixed list.

---

## 14. Vision Verification

**LOCAL IMAGE SECURITY — VERIFIED.**
`ImageSecurityValidator.validate_and_extract` enforces, **before any decode**:
base64 validation (`validate=True`), size bounds (≤ 7 MB b64 / ≤ 5 MB decoded),
magic-byte format allowlist (PNG/JPEG/WebP/GIF), header-derived dimensions
(≤ 4096×4096), and a 16 Mpx decompression-bomb ceiling, with
`Image.MAX_IMAGE_PIXELS` hardened. Rejections return `INVALID_IMAGE` with
`visual_score=None` — **never a synthetic score**.

Verified at runtime during this audit: the pixel decoder's
`Image.get_flattened_data()` call is valid on the installed Pillow **12.3.0** and
returns `(r,g,b)` tuples as the decoder assumes (executed directly). Rejections
and fallback are covered by `test_vision_phase1_6.py`.

**LIVE SEMANTIC MULTIMODAL VISION — NOT-PROVEN.**
The multimodal path requires a vision-capable provider; Gemini is the only
capable provider and requires `GEMINI_API_KEY`. With no key the service takes the
`HEURISTIC_FALLBACK` path (`provider="local_forensics"`,
`model="pixel_statistics"`). Every in-tree vision test mocks or disables the
provider (`test_vision_phase1_6.py:234,470,495`). The only live-provider artifact
in the repository records failure — `scratch/phase1_5b_runtime_results.json`
shows `AI_TIMEOUT` on all three attempts. Documentation that graded this
"VERIFIED" has been corrected.

---

## 15. Observability Verification

**VERIFIED:** `/health` (service, environment, version, commit SHA, weights,
scan counts, SSE metrics, circuit-breaker state), `/ready` (active DB probe with
503 on failure), `/metrics` (Prometheus), structured logging with
`sanitize_log_message`, audit logging for SSRF blocks.

**Secret-handling verified:** base64 screenshots are never logged; the vision
service explicitly avoids placing pixel buffers in traces; exception messages
carry type names, not payloads.

**Defects (documented):** several docs publish metric and health-field names that
do not exist — `sse_queue_full_total`/`sse_subscriber_evictions_total` are
in-process dict keys surfaced under `/health → sse`, **not** Prometheus metrics;
and documented health keys `features` / `tier3_circuit_breaker` do not exist.

---

## 16. Secret / Configuration Verification

- **No live secrets found.** Gitleaks runs in CI; `.gitignore` covers `.env*`
  while allowing `*.example` templates. `.env.staging.example` contains only
  placeholders.
- `.gitignore` is comprehensive (venvs, caches, coverage, DBs, model weights,
  build output) — **except** it does not cover `scratch/` (untracked working
  artifacts) and the rule `*.tsbuildinfo` is ineffective for
  `Frontend/tsconfig.tsbuildinfo`, which is **already tracked** (gitignore does
  not apply to tracked files — it shows as ` M` in git status). This should be
  `git rm --cached`'d.
- **Undeclared dependency fixed:** `Backend/vision/security.py:24` imports
  `from PIL import Image`, but **Pillow was declared in no dependency file**
  (verified across `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`).
  A clean install from `requirements.txt` could therefore fail to import the
  vision module — and because `gateway.py` imports `vision.router` inside the
  `EXTENSIONS_AVAILABLE` try/except, that failure would silently remove **all**
  extension routers (auth, webhooks, incidents, email, analytics, awareness,
  vision). `Pillow==12.3.0` is now declared explicitly.
- **Extension token storage** — fixed (E-7).

---

## 17. Dependency Verification

- **No blind upgrades performed.** One dependency added (`Pillow`) to close a
  verified gap.
- CI installs backend deps with a CPU PyTorch index and runs `pip-audit`
  (ignoring `PYSEC-2022-43059`); the frontend runs `pnpm audit --audit-level=high`
  and pins `next` to exactly `16.3.3`.
- **Inconsistency found:** `SECURITY.md` justifies accepted advisories against
  `transformers==4.57.6` / `torch==2.5.1+cu118`, while `requirements.txt` pins
  `transformers==5.10.4` / `torch==2.13.0`. The security rationale no longer
  describes the shipped set.
- **`SECURITY.md` claims tooling that does not exist:** pre-commit
  gitleaks/semgrep hooks (no `.pre-commit-config.yaml`) and weekly OWASP ZAP DAST
  (no ZAP config or workflow).

---

## 18. Test Verification

**Execution status: NOT-RUN.** The shell command classifier was unavailable for
the duration of this session, so **no test suite was executed**. Per the evidence
rules, local test results are **NOT-PROVEN**, not "passed". This is a material
gap in this report and a direct input to the §30 decision.

**Static verification performed by reading:** 79 test modules in `Backend/tests/`
plus `conftest.py`; 3 frontend vitest files (38 `it()` blocks).

**Genuine strengths (verified by reading):**
- **Zero `skip`/`xfail`/`skipif`/`pytest.skip` markers** anywhere in the suite.
- Fusion is **never mocked**; `test_phase1_7_fusion.py` asserts exact fused scores
  against the real engine, including a deterministic 900-combination grid.
- **No test constructs a substitute FastAPI app** — 16 files drive the real
  `gateway.app`.
- `test_architecture_boundaries.py` self-tests its own walker after documenting a
  previously vacuous pass — exemplary.

**Defects found and corrected:**

| ID | Defect | Fix |
|---|---|---|
| T-1 | **A Phase 1.9 acceptance test passed vacuously.** `test_vision_cannot_independently_elevate_safe_to_critical` patched `VisionService.analyze_screenshot` with a bare `return_value=`. Because `analyze_screenshot` is a **descriptor**, not a coroutine function, `unittest.mock` selected `MagicMock`; the non-awaitable return raised `TypeError` under `await`, and `gateway.py`'s broad `except Exception` replaced the hostile vision result with `VisionStatus.FAILED`. The assertions passed because vision was **degraded away**, never because fusion down-weighted it. Its docstring also claimed an unasserted and factually wrong "weight ≤ 15". | `new_callable=AsyncMock` (as the sibling test already used), plus explicit assertions that vision was invoked and that the hostile `visual_score=95.0` actually reached the pipeline — so the test can no longer pass without exercising the boundary. Docstring corrected. |
| T-2 | **Tautological assertion.** `assert CONFIG.port == 8001 or isinstance(CONFIG.port, int)` — `CONFIG.port` is always an `int`, so the "canonical entry point on port 8001" criterion could never fail. | Replaced with `assert CONFIG.port == 8001`. |
| T-3 | Docstring overstated a **sequential** test as concurrent. | Docstring corrected; the coverage gap is recorded (§11). |

**Additional test-integrity issues recorded (not fixed — no behavioural defect, but they bound the evidence):**
- `conftest.py:38-41` defines a fixture named `reset_app_state` documented as
  isolating shared gateway app state; its body is a bare `yield` and performs no
  isolation, while four files mutate process-global SSE/ML state with hand-rolled
  cleanup. Tests are order-sensitive.
- `test_p0_remediation.py` claims "zero fake mocks"; its shared fixture stubs
  `_finalize_tier3` for every test, and one test mocks
  `execute_tier3_with_circuit_breaker`.
- `test_independent_acceptance.py:68` can make a **real outbound Gemini call** if
  `GEMINI_API_KEY` is exported in the developer's shell — it is not fenced the way
  `test_vision_perf.py:24` fences its equivalent.
- `conftest.py:44-54` calls `os._exit()` in `pytest_unconfigure`, bypassing atexit
  and plugin teardown (including coverage finalisation).
- `Frontend/lib/extension-pipeline.test.ts:49-121` declares its **own**
  `ScanResult` interface and `normalizeGatewayResponse` **inside the test file**
  and tests that local copy — it proves nothing about production code.
- Wall-clock assertions (`test_tier1_engine.py:183`, `test_phase1_8_adversarial.py:569,580`,
  `test_vision_perf.py:43`) encode latency guarantees that hold only on unloaded hardware.

**Classification of the suites named in the brief:**

| Suite | Classification |
|---|---|
| `test_tier1_engine.py`, `test_tier1_adversarial.py` | **UNIT-VERIFIED** (real engine, no mocks) |
| `test_tier1_trust_boundary.py` | **MOCKED** (Tier 3 + domain age stubbed) |
| `test_tier3_phase1_5a.py` | **MOCKED** (provider mocked; real validator) |
| `test_tier3_phase1_5b.py` | **UNIT-VERIFIED** (real router, mock providers) |
| `test_phase1_9_runtime_e2e.py` | **MOCKED** (Tier 3 stubbed file-wide; no provider contacted) |
| `test_phase1_8_adversarial.py` | **UNIT-VERIFIED** (real fusion/vision/validator, no network) |
| `test_vision_phase1_6.py` | **UNIT-VERIFIED** + **MOCKED** (provider disabled/mocked) |

**No test in the repository proves live Tier 3 or live multimodal Vision
connectivity.**

---

## 19. Build Verification

**NOT-RUN.** Not executed in this session (tooling unavailable).

**Configuration reviewed and coherent:** frontend `tsconfig.json` sets
`strict: true`; `next.config.mjs` sets `ignoreBuildErrors: false` (so type errors
fail the build); vitest is configured `environment: 'node'` (no DOM — therefore
**no component rendering is tested at all**, and no `*.test.tsx` exists).

**Caveat:** the strictness that is configured is **defeated on the scan path** by
the double cast at `lib/live-tier1.ts:157-158`.

---

## 20. CI Verification

**Configuration: comprehensive.** `.github/workflows/ci.yml` runs gitleaks
(full history), backend tests with coverage ≥ 65%, Alembic migration + schema
parity check, `pip-audit`, frontend typecheck + vitest + lint + production build
with an asserted `next` version, extension manifest validation and packaging, and
a container build verification. A separate CodeQL workflow exists.

**Status for the audited tree: NOT-PROVEN.** Two reasons:
1. The canonical Phase 1 modules (`Backend/fusion/`, `Backend/tier_1/`,
   `Backend/tier_3/{base,prompt,router,validator}.py`, `Backend/tier_3/providers/`,
   `Backend/vision/security.py`) and ~12 phase test modules are **untracked**.
   CI checks out the repository, so it cannot exercise them.
2. No CI run was observed in this session.

**CI/local consistency notes:** CI injects `GEMINI_API_KEY=placeholder_key_for_ci`,
confirming Tier 3 provider calls are **not** live in CI. CI does **not** set
`API_KEY`, so the newly-added auth dependencies on mutating endpoints are inert in
CI (and in the documented staging topology).

---

## 21. Deployment Readiness

| Item | Status |
|---|---|
| Startup / ports | **VERIFIED** — Gateway 8001; `main.py` and `tier_2/main.py` are shims |
| Health / readiness | **VERIFIED** — `/health`, `/ready` with active DB probe and 503 |
| Metrics | **VERIFIED** — `/metrics` Prometheus exposition |
| Staging compose | **REVIEWED** — backend + Redis, healthchecks, named volumes, `DATABASE_URL` on a volume (genuinely durable for staging) |
| Authentication posture | **DEFECTIVE** — `docker-compose.staging.yml` sets no `API_KEY`, so the gateway is unauthenticated in the documented staging topology |
| CORS | **REVIEWED** — explicit origin list + localhost regex, `allow_credentials=True`; not a wildcard |
| Frontend base URL | **INCONSISTENT** — three different defaults across the app (`NEXT_PUBLIC_GATEWAY_URL` vs `NEXT_PUBLIC_ZEROPHISH_BACKEND_URL`), all falling back to a hardcoded localhost |
| External production deployment | **NOT-PROVEN** — no production deployment was exercised |

---

## 22. Repository Hygiene

| Category | Findings |
|---|---|
| **Build output** | `Frontend/.next/` and `node_modules/` present on disk but gitignored — fine. |
| **Tracked build artifact** | `Frontend/tsconfig.tsbuildinfo` is **tracked** despite the `*.tsbuildinfo` ignore rule → `git rm --cached` recommended. |
| **Untracked baseline** | **The Phase 1 canonical modules and phase test files are untracked.** The committed repository does not represent the audited architecture. Highest-priority hygiene item. |
| **Temporary artifacts** | `scratch/` (untracked, contains live-verification scripts and `phase1_5b_runtime_results.json`) is not gitignored. `graft/` is gitignored. |
| **Stray file** | `Backend/tests/conftest.py.phase14b8.bak` — a backup file inside the test tree. |
| **Caches** | `.pytest_cache/`, `.mypy_cache/`, `htmlcov/`, `coverage.xml` present and gitignored. |
| **Documentation** | ~30 documents, several superseded/stale; `docs/INDEX.md` correctly demotes superseded docs. |
| **Evidence preserved** | Historical phase reports retained; not deleted (they are historical evidence). |

---

## 23. Documentation Audit

**Corrected during this phase** (highest-consequence false claims):

| Document | Issue | Action |
|---|---|---|
| `docs/security/authentication-audit.md` | Described an **entirely non-existent** authentication system (PBKDF2-HMAC-SHA256, `secrets.token_urlsafe(48)`, `zp_session` cookies, TOTP MFA, `/auth/login|register|logout|mfa/verify|password/change`, per-endpoint auth rate limits). The repo is Clerk-based. A security document describing controls that do not exist is the most dangerous documentation defect found. | Added a prominent **SUPERSEDED** banner enumerating exactly which controls do not exist and pointing to the authoritative `authentication.md`. |
| `docs/PHASE_1_9_RUNTIME_INTEGRITY_REPORT.md` | Graded Vision **"VERIFIED"** at §E while grading live multimodal **"NOT-PROVEN"** at the capability matrix — self-contradictory. Also claimed vision contribution "≤ 15 pts". | Restated as local-VERIFIED / live **NOT-PROVEN**; corrected the bound to 0.25 (25 pts) in the Tier-3-absent profile and restated the CRITICAL-authority invariant precisely. |
| `docs/PHASE_1_9_RUNTIME_INTEGRITY_REPORT.md` | Referenced an **OCR** stage; no OCR code exists. | Replaced with the actual pre-decode Pillow boundary; noted no OCR stage exists. |
| `docs/ZERO_PHISH_P1_RELIABILITY_REPORT.md` | Claimed vision degrades gracefully "if OpenCV or Tesseract unavailable" — neither exists. | Corrected to Pillow; live multimodal marked NOT-PROVEN. |
| `README.md` | Features table claimed "SQL-backed repositories for durable application state" with no qualification, while the default is in-memory. | Qualified with the `DATABASE_URL` precondition. |
| `README.md` | Presented `Final Score = (T1×0.20) + (T2×0.30) + (T3×0.50)` as the formula; fusion actually renormalises per participating-tier profile. | Replaced with the real profile table and the renormalisation rule; documented `UNKNOWN`. |

**Remaining known-inaccurate documentation (recorded, not all corrected):**
- `Backend/README.md` (whole file) describes a pre-refactor topology: port 8000,
  a `Backend/extension` directory that does not exist, `main.py` as the Tier 3 AI
  module, and a `GET /threat/patterns` endpoint that does not exist.
- `docs/TESTING_AND_DEPLOYMENT.md`, `docs/EXTENSION_FIX_GUIDE.md`,
  `docs/staging/*`, `docs/QUICK_REFERENCE.md` — stale port 8000 references,
  nonexistent file paths, and a false `allow_origins=["*"]` claim.
- `docs/OPERATIONS_RUNBOOK.md` — typos (`uficorn`, `pnmp`, `gaeway`), a
  nonexistent `Backend/logs/` path, and a postgres container that appears in no
  compose file.
- `docs/ZERO_PHISH_P1_OPERATIONS_RUNBOOK.md` — health/metric names that do not exist.
- `GEMINI_INTEGRATION_STATUS.md` — "fully integrated"/"Guaranteed JSON output"
  against a router that explicitly handles `AI_INVALID_RESPONSE`.
- Overstated absolutes: "Remaining Open Vulnerabilities: 0", "Durability verified
  100%", "unbypassable", "Universal Adversarial Immunity", "cannot be bypassed by
  any caller".
- `docs/ARCHITECTURAL-CLEANLINESS-REPORT.md` — describes `tier_2/main.py` as a
  736-line second entrypoint; it is now 29 lines.
- `SECURITY.md` — dependency versions, pre-commit hooks, and ZAP DAST claims that
  do not match the repository.

**Correctly calibrated documents (positive):** `README.md:27` ("No phishing
detector should be treated as infallible"), `README.md:447-453` (explicitly no
durable webhook ledger), `docs/ZERO_PHISH_P1_ACCEPTANCE_FINAL.md` ("NOT PROVEN",
"CONDITIONALLY VERIFIED"), and `docs/CLEAN-CODE-FORENSIC-AUDIT.md`, which actively
contradicts overclaims in its sibling documents.

---

## 24. Threat Model

**In scope:** email-borne phishing (credential harvesting, BEC, brand
impersonation, deceptive links), obfuscation and encoding evasion, SSRF via
user-supplied links/webhooks, malicious image payloads, prompt injection into
advisory AI layers, client-side trust abuse.

**Out of scope:** host/OS compromise, supply-chain attacks on PyPI/npm beyond
advisory scanning, denial of service by a resource-exhausting adversary with
legitimate credentials, and physical/insider threats.

| Category | Items |
|---|---|
| **In-scope, verified** | Server-authoritative Tier 1; monotonic floor; failure≠SAFE; UNKNOWN distinct; SSRF matrix; Unicode/IP/FQDN normalisation; image decompression-bomb limits; client cannot suppress server evidence |
| **In-scope, partially tested** | Redirect SSRF (bounded matrix, not exhaustive); resource limits (no adversarial load test); SSE backpressure (unit-level); concurrency isolation (no true interleaving test) |
| **Not-proven** | Live Tier 3 provider behaviour; live multimodal Vision; DNS-rebinding resistance; multi-instance deployment behaviour; true concurrent-scan isolation |
| **Known residual risk** | DNS-rebinding TOCTOU (validated IP not pinned); `192.0.0.0/24` and 6to4 not unwrapped; Ollama/ML outbound paths bypass the central SSRF chokepoint; unauthenticated staging topology; dashboard feed carries advisory and server payloads through one channel |

**The implementation's adversarial resistance is bounded by the tested corpus**
(a 33-test adversarial suite, an 18-case IP-parameterised matrix, and a
900-combination deterministic fusion grid). No claim of universal immunity is made
or supported.

---

## 25. Residual Risks

1. **DNS rebinding TOCTOU** in SSRF checks — validated address is not pinned to
   the connection.
2. **Advisory data on the authoritative feed.** `/tier1/stream` and `/tier1/latest`
   carry both server-verified scan payloads and `client_advisory` reports through
   one channel, and the frontend ignores the `source` provenance tag.
3. **Unauthenticated staging topology** (no `API_KEY`).
4. **Backup-file and untracked-artifact presence** in the tree.
5. **Advisory tiers can influence the verdict band.** Vision (weight 0.25 in the
   Tier-3-absent profile) can tip a near-threshold SUSPICIOUS into CRITICAL by
   corroboration. Intentional, but weaker than previously documented.
6. **Tier 2 failure yields SUSPICIOUS by design** (fail-safe score 50). This is
   deliberate fail-safe behaviour, but it means a Tier 2 outage produces
   suspicious verdicts for benign mail — a false-positive surge under degradation.

---

## 26. Known Limitations

- No durable persistence by default (in-memory); durability requires `DATABASE_URL`.
- Live Tier 3 and live multimodal Vision are unverified; the default vision path is
  local pixel forensics.
- No browser/extension E2E harness exists; the extension has no automated tests.
- No component-level frontend rendering tests (vitest runs in a `node` environment).
- Public-suffix handling uses a small hardcoded list.
- Single-instance assumptions: the SSE subscriber registry and `_latest_tier1_report`
  are process-local; the runbook's `--workers 4` suggestion is inconsistent with this.
- ML accuracy figures ("97%+") are asserted in documentation without a supporting
  evaluation artifact in the repository.

---

## 27. Defects Fixed (this phase)

**P0 — corrected**
| ID | Area | Description |
|---|---|---|
| E-1 | Extension | Local `phishing`/`spam` verdicts rendered as green SAFE |
| E-2 | Extension | Failed Vision rendered "Visual Checks Passed" + Verified |
| E-3 | Extension | Polling failure asserted "3-Tier Analysis finalized successfully." |
| F-4 | Frontend | Incomplete scan rendered as `complete` (gated Safe-Passage affordance) |

**P1 — corrected**
| ID | Area | Description |
|---|---|---|
| G-1 | Gateway | Unauthenticated mutating endpoints (`/tier1/report`, `/cache/clear`, `/gateway/circuit/reset`) |
| G-2 | Gateway | SSE overflow-map leak on subscriber disconnect |
| — | Gateway | Degraded Tier 1 laundered to `server_verified` by a client score |
| F-1 | Frontend | Absence of evidence rendered as `"pass"` |
| F-2 | Frontend | Fabricated SPF/DKIM/DMARC verdicts from the Tier 2 score |
| F-3 | Frontend | Fabricated domain-age/hosting values |
| F-5 | Frontend | Tier 3 "no markers" rendered in the safe colour when Tier 3 never ran |
| E-4 | Extension | Green SAFE at rest and during the scan window |
| E-5 | Extension | `VISUAL_REQUIRED` never rendered |
| E-6 | Extension | Behavioural warning asserted a critical threat with no verdict input |
| E-7 | Extension | Clerk bearer token stored in cloud-synced `chrome.storage.sync` |
| — | Deps | `Pillow` imported by production code but declared nowhere |
| T-1 | Tests | A Phase 1.9 acceptance test passed vacuously (MagicMock instead of AsyncMock) |
| T-2 | Tests | Tautological assertion in the "canonical entry point" criterion |
| T-3 | Tests | Sequential test documented as concurrent |
| — | Docs | Six documentation defects including a fabricated authentication audit |

**P2 — recorded, deliberately not fixed** (each requires new UI surface or a
design decision beyond the minimal-change mandate; none is fail-open):

| ID | Area | Description | Blocks Phase 1? |
|---|---|---|---|
| P2-1 | Frontend | `ThreatLevel` has no `unknown` member; `UNKNOWN` renders as a confident warning/threat (over-warns — safe direction) | No |
| P2-2 | Frontend | Two unvalidated casts defeat `strict` on the entire scan path; no runtime schema validation | No |
| P2-3 | Frontend | The `vision` dimension and `requires_visual_check` are still dropped by the adapter | No — the *verdict* remains correct; only the manual-follow-up affordance is missing |
| P2-4 | Feed | Two payload shapes share `_latest_tier1_report` | No — but it is architectural ambiguity |
| P2-5 | Gateway | `RequestSizeLimitMiddleware` trusts `Content-Length`; a chunked body bypasses the limit | No |
| P2-6 | Frontend | `domainAge`/`hostingProvider` still threshold-derived when `tier_details.tier2` is present | No |
| P2-7 | Tests | `reset_app_state` fixture performs no isolation; order-sensitive tests | No |
| P2-8 | CI | Untracked baseline modules ⇒ CI cannot exercise the audited architecture | **Yes — evidence gap** |

**P3 / INFO:** dead `extension/worker.js`; dead `/tier1/report` client in the
extension; `Frontend/lib/api.ts` scan client with no call sites; tracked
`tsconfig.tsbuildinfo`; `conftest.py.phase14b8.bak`; doc typos; `BoundedScanTracker`
described as LRU when it is FIFO; frontend truncation at 12 items without a
"+N more" indicator.

---

## 28. Deferred Work

1. Surface `VISUAL_REQUIRED` / `requires_visual_check` and the vision dimension in
   the frontend (new UI surface).
2. Add an `unknown` member to `ThreatLevel` and render it distinctly.
3. Replace the two casts with a single validated parse (zod is already a
   dependency) and enforce one canonical wire contract.
4. Separate the dashboard feed into server-verified and client-advisory channels,
   or at minimum surface the `source` provenance tag in the UI.
5. Pin the validated IP for outbound requests to close the DNS-rebinding TOCTOU.
6. Add a true concurrent-scan isolation test (async client + `asyncio.gather`).
7. Add extension tests; add jsdom-based component tests for verdict rendering.
8. Retire the stale documentation set (`Backend/README.md`, `docs/staging/*`,
   `TESTING_AND_DEPLOYMENT.md`, `EXTENSION_FIX_GUIDE.md`, runbooks).
9. Commit the Phase 1 baseline and re-run CI.

---

## 29. Capability Evidence Matrix

| Capability | Status | Evidence Scope | Notes |
|---|---|---|---|
| Tier 1 authoritative detection | **VERIFIED** | Unit (`test_tier1_engine.py`, `test_tier1_adversarial.py`) + gateway integration; real engine | Server-authoritative; fail-safe degraded |
| Tier 2 domain intelligence | **VERIFIED** | Unit + integration (`test_tier2_phase1_4.py`, `test_whois_client.py`) | Cascade correct; upstream calls not live-exercised |
| Tier 3 provider routing | **UNIT-VERIFIED** | `test_tier3_phase1_5b.py` — real router/validator, mock providers | Live vendor calls **NOT-PROVEN**; CI uses a placeholder key |
| Semantic multimodal Vision | **NOT-PROVEN** | Only mocked/disabled-provider tests; sole live artifact shows `AI_TIMEOUT` | Requires a vision-capable provider key |
| Local image security | **VERIFIED** | `test_vision_phase1_6.py`; Pillow `get_flattened_data()` API independently executed | Pre-decode bounds, bomb protection |
| Canonical fusion | **VERIFIED** | `test_phase1_7_fusion.py` — exact scores, 900-combination grid; never mocked | Monotonic floor structurally enforced |
| SSRF protection | **VERIFIED (bounded)** | 18-case parametrised IP matrix + redirect tests | Rebinding TOCTOU; `192.0.0.0/24`, 6to4 gaps |
| Unicode normalization | **VERIFIED (bounded)** | NFKC + zero-width + homoglyph, tested | Bounded corpus, not universal |
| IP normalization | **VERIFIED (bounded)** | decimal/hex/octal via `inet_aton`; parametrised matrix | Exotic encodings not exhaustively enumerated |
| FQDN canonicalization | **VERIFIED (bounded)** | trailing-dot, `www.`, punycode, case | Small hardcoded public-suffix list |
| Client trust boundary | **VERIFIED** | `test_tier1_trust_boundary.py`; escalate-only `max()` | Degraded-laundering defect fixed |
| Scan lifecycle | **PARTIALLY VERIFIED** | Gateway integration tests | No true concurrency test; terminal-state races NOT-PROVEN |
| SSE | **PARTIALLY VERIFIED** | `test_gateway_sse.py`, `test_sse_broadcast_validation.py`, `test_p1_reliability.py` | Two payload shapes on one channel |
| Polling | **PARTIALLY VERIFIED** | Contract tests | Same shape ambiguity |
| Frontend integration | **CORRECTED — UNVERIFIED** | `live-tier1.test.ts` covers the adapter (no component rendering) | Fixes not executed |
| Extension integration | **CORRECTED — UNVERIFIED** | **No automated tests exist** | Fixes not executed |
| Concurrency isolation | **PARTIALLY VERIFIED** | Circuit-breaker HALF_OPEN test is strong; scan concurrency untested | Gap documented |
| Runtime state persistence | **VERIFIED** | In-memory repository, bounded, lock-guarded | Process-local |
| Durable persistence | **VERIFIED only when `DATABASE_URL` is set** | `test_blackbox_durability.py` (SQLite restart) | **Not** the default configuration |
| CI verification | **NOT-PROVEN** | CI config reviewed; no run observed; baseline untracked | |
| External deployment | **NOT-PROVEN** | Staging compose reviewed only | No deployment exercised |

---

## 30. Final Phase 1 Acceptance Gate

### Decision: **HOLD**

Per the defined decision model, `HOLD` applies where a P0/P1 issue, architectural
ambiguity, broken security invariant, or missing critical evidence prevents
acceptance. Three conditions obtain:

1. **Missing critical evidence.** The test suites, typecheck, and build were
   **NOT-RUN** in this session (tooling unavailable), and CI status for the audited
   tree is **NOT-PROVEN** because the canonical Phase 1 modules are **uncommitted**.
   Acceptance gate items 26–30 ("backend regression suite passes", "frontend
   regression suite passes", "typecheck passes", "production build passes",
   "relevant CI checks verified") are therefore unmet **as evidence** — the code may
   well be correct, but the repository does not currently demonstrate it.

2. **Architectural ambiguity unresolved.** The dashboard feed carries both
   server-verified and client-advisory payloads through one channel with two
   incompatible shapes, and the frontend does not read the provenance tag. This is
   the same ambiguity the brief names as blocking.

3. **Capability-claim calibration incomplete.** Materially false documentation
   claims remain outside the subset corrected here (the fabricated authentication
   audit is banner-corrected; `Backend/README.md`, the staging docs, the runbooks,
   and `SECURITY.md`'s tooling/dependency claims are not).

### Gate scorecard

| Gate | Result |
|---|---|
| 1–3 Architecture (canonical path, no second engine, shims cannot bypass) | **PASS** |
| 4–13 Security (server authority, monotonic floor, failure safety, UNKNOWN, VISUAL_REQUIRED, vision authority, SSRF, normalization, resource limits, secrets) | **PASS**, with the Vision-weight nuance (§4F) and SSRF residual risks (§12) documented |
| 14–18 Pipeline (T1, T2, T3, vision-required, fusion) | **PASS** (server-side) |
| 19–22 Runtime (lifecycle, terminal stability, concurrency, polling/SSE consistency) | **PARTIAL** — concurrency untested; feed shape ambiguous |
| 23–24 Frontend / Extension consume canonical state | **PASS after correction — UNVERIFIED** |
| 25 Stale-state / state-crossing defects | **PASS after correction — UNVERIFIED** |
| 26–30 Backend suite / frontend suite / typecheck / build / CI | **NOT-RUN / NOT-PROVEN** |
| 31 No critical test bypass | **PASS** — zero skip/xfail; three test defects fixed |
| 32–36 Config, deployment docs, health/readiness/metrics, hygiene, dependencies | **PARTIAL** — staging unauthenticated by config; dependencies now coherent |
| 37–42 Documentation calibrated, Vision NOT-PROVEN, no durability/E2E/vendor overclaim | **PARTIAL** — key corrections made, stale set remains |
| 43 No unresolved P0/P1 | **PASS for corrected items; FAIL on evidence** (fixes unverified) |
| 44–47 P2 documented, residual risk documented, matrix exists, evidence-based recommendation | **PASS** |

### Conditions to close (all required)

1. **Run the suites** — backend `pytest tests/`, frontend `pnpm test`,
   `pnpm exec tsc --noEmit`, `pnpm build`, and confirm green. (No test may be
   weakened to achieve this.)
2. **Commit the Phase 1 baseline** (the untracked `fusion/`, `tier_1/`, `tier_3/`,
   `vision/security.py`, and phase test modules) and obtain a green CI run.
3. **Resolve the feed ambiguity** (P2-4) or explicitly accept and document it as a
   known Phase 1 limitation with the provenance tag surfaced in the UI.
4. **Finish documentation calibration** — banner the remaining stale documents
   (`Backend/README.md`, `docs/staging/*`, `TESTING_AND_DEPLOYMENT.md`,
   `EXTENSION_FIX_GUIDE.md`) and correct `SECURITY.md`'s tooling and dependency
   claims.

### What Phase 1 actually delivers

A genuine, single-path, server-authoritative three-tier phishing detection
pipeline with a provider-agnostic AI tier, a hardened local image-security
boundary, a canonical fusion engine that structurally refuses to downgrade
established risk and never converts failure into SAFE, SSRF-hardened upstream
access, and bounded obfuscation resistance — **within the tested threat model and
evidence set**. Live AI provider inference, live multimodal vision, durable
persistence by default, and browser/extension E2E remain **NOT-PROVEN**, and the
documentation set does not yet consistently say so.

---

*Report generated under the Phase 1.10 final production-readiness gate. Every
claim above carries an explicit evidence classification; where evidence was
unavailable, this report says NOT-PROVEN rather than assuming success.*
