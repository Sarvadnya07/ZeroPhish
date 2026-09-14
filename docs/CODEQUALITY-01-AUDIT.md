# ZeroPhish — Code Quality, Maintainability & Architecture Audit

**Audit date:** 2026-09-14 · **Auditor:** Buffy (CODEQUALITY-01) · **Mode:** Audit-first, no refactoring performed.

---

## Executive Code Quality Assessment

**Verdict: This is a healthy, above-average codebase for its maturity stage. It is generally easy to understand and safely change, with a few concentrated areas of accidental complexity and debt that should be made visible and prioritized — not rewritten.**

Evidence-based summary:

- **Correctness:** 347 backend tests pass in 98s; frontend `tsc --noEmit` is clean. Scoring, caching, SSE backpressure, circuit breaker, and RBAC paths are all covered by dedicated tests.
- **Understandability:** Module layout (`tier_2`, `tier_3`, `ml`, `security`, `auth`, `repositories`, extension routers) matches the domain. Names are domain-precise (`ThreatAnalyzer`, `GatewayScanResponse`, `ShadowCascadeManager`).
- **Change cost:** Changes to scoring weights, cache TTL, or rate limits are local (config dataclass + env). Changes to the scan response shape ripple across gateway → frontend adapter → extension — this is the main blast-radius hotspot.
- **Architecture:** Dependency direction is clean (routers → services → repositories; gateway → tier_2/ml; nothing imports the gateway inward). Boundaries are *implicit* (convention), not enforced (no import-linter/architecture tests) — acceptable at this maturity, worth adding cheaply.
- **Debt:** Visible and mostly intentional (deprecation shims, phased ML test files, legacy schema retention). The largest items are structural duplication between `tier_2/main.py` and `gateway.py`, module-level singletons, and repo hygiene artifacts.

---

## Project Maturity

**Classification: Growing Product, trending toward Production.**

Evidence: CI gates (gitleaks, pip-audit, pytest coverage ≥65%, `tsc --noEmit`, vitest), Alembic migrations verified in CI, staging environment with shadow cascade, CODEOWNERS on auth/security paths, security middleware suite. Not yet Production-grade in: architecture enforcement tests, `mypy` in CI (config exists at `Backend/pyproject.toml` but no CI job), or alerting/observability beyond in-process metrics.

Implication: recommendations below are calibrated to *Growing Product* — no enterprise ceremony (no DI framework, no hexagonal enforcement) is proposed.

---

## Architecture Map

| Area | Responsibility | Deps (outward) | Public surface | Change freq | Criticality |
|---|---|---|---|---|---|
| `Backend/gateway.py` (1,045 L) | Scan orchestration, SSE, cache fast-path, circuit breaker wiring | tier_2, repositories, security, extension routers | REST + SSE API | High | High |
| `Backend/tier_2/` | Domain age, threat patterns, ML model, WHOIS | ml, security | `ThreatAnalyzer`, FastAPI app (port 8000) | Medium | High |
| `Backend/tier_3/` + `gateway_circuit_wrapper.py` | Gemini AI analysis (async, circuit-breaker guarded) | circuit_breaker | function-level | Medium | High |
| `Backend/ml/` | URLBERT/ONNX predictors, calibration, fusion, shadow cascade, data pipeline | transformers, onnxruntime | predictor protocols | High (benchmark phases) | Medium |
| `Backend/security/` | Validation, SSRF, headers, audit log, metrics | — | middleware + validators | Medium | High |
| `Backend/auth/` | Clerk JWT verification, user service, RBAC | repositories | router + `ClerkTokenVerifier` | Medium | High |
| `Backend/repositories/` | Scan/user/analytics/webhook/incident persistence; SQL vs in-memory factory | infrastructure, all domain models | factory getters | Medium | High |
| `Backend/infrastructure/` | SQLAlchemy engine, DB models, migrations | alembic | `get_engine` | Low | Medium |
| Extension routers (`analytics`, `auth`, `awareness`, `incidents`, `webhooks`, `email_scanner`, `vision`) | Feature modules plugged into gateway | repositories, security | FastAPI routers | Medium | Medium |
| `Frontend/` (Next.js 16) | SOC dashboard, SSE consumption, adapter layer | lib/sentinel-data | pages/components | Medium | Medium |
| `extension/` (vanilla MV3, ~1.2k L) | Tier 1 heuristics in-browser | gateway API | sidepanel UI | Low | High (user-facing) |

## Dependency Direction

- **Verified clean:** `repositories/factory.py` → sql/in-memory impls; services never import `gateway.py`; `security/` imports nothing from feature modules (except its own audit logger). `gateway.py` imports feature routers; routers never import gateway. No cycles found.
- **High fan-in modules (signals, not defects):** `repositories/factory.py`, `security/middleware.py`, `models/gateway_models.py`. These are stable, appropriate foundations.
- **Hidden dependencies:** `tier_2/main.py` does defensive dual imports (`from tier_2.ml_model … except: from ml_model …`) — a symptom of ambiguous root/package execution context (see F-01).
- **Cross-layer leakage:** `gateway.py` reaches into `security.metrics` via function-local import inside middleware — intentional lazy import, acceptable, but invisible at module top.

## Cohesion

- **Good:** `circuit_breaker.py`, `security/middleware.py`, `repositories/*` are functionally cohesive; each has one change driver.
- **Mixed (F-02):** `gateway.py` is a god-module by size only: scoring helpers, SSE subscriber registry, cache-key logic, tier-2 execution, health endpoints, circuit-breaker admin. Each part is understandable; the file is one collision domain for concurrent edits. Splitting by *endpoint group* (scan / status / stream / ops) would improve locality without inventing abstractions.
- **Weak cohesion:** `Backend/main.py` is a legacy compatibility shim holding deprecated models "preserved for tests" — dispensable debt (F-04).

## Coupling

- Data coupling dominates (Pydantic models passed explicitly) — good.
- **Module-level mutable singletons:** `scan_results_lock`, `_latest_tier1_report`, `_sse_subscribers`, `sse_metrics` in gateway; repo caches in `factory.py`; `ClerkTokenVerifier.config` as a *class attribute* initialized from env at import time (F-03). All are documented and tests exercise them via `reset_repositories()`, so this is *contained* global state — acceptable here, but the Clerk class-attribute config is the most fragile instance (import-order dependent).
- Content coupling: `receive_tier1_report` accepts untyped `Dict[str, Any]` from the extension — the extension→backend contract is only conventionally typed (F-05).

## Public / Internal Boundaries

- Implicit but well-respected: `repositories/base.py` defines protocols; factory exposes getters. Frontend adapter (`lib/live-tier1.ts`) explicitly marks `GatewayScanResponse` authoritative and `Tier1Report` `@deprecated` — exemplary.
- No enforcement mechanism (no `export` restrictions, no import-linter, no package boundaries between `Backend` subpackages). Python's flat module namespace means "internal" is advisory only.

## Readability / Naming

- Strong: domain language is consistent (tier1/2/3, evidence, verdict, shadow cascade, circuit breaker). Docstrings explain intent and constraints. Error messages carry context.
- Minor drift: `Verdict` (SAFE/SUSPICIOUS/CRITICAL at ≥30/≥70) vs `_determine_threat_status` (OK/SUSPICIOUS/CRITICAL at ≥40/≥70) — two threshold ladders for "suspicious" in one file (F-06). Both are tested, so behavior is pinned; this is terminology drift, not a bug.
- `BoundedScanTracker` subclassing `dict` with overridden `__setitem__` is clever but surprising; a composition-based bounded dict would be more predictable. LOW.

## Comments

- Predominantly valuable: explain *why* (circuit breaker protocol mismatch cast, cache-hit scan_id replacement rationale, SSRF subnet enumeration, "minimal multi-part public suffix handling (not a full PSL)"). Zero stale TODO/FIXME found in backend — unusually clean.
- The honest deprecation notice in `main.py` is exactly what debt documentation should look like.

## Functions / Methods

- `gateway_scan` (~130 L, 7 numbered steps) and `_finalize_tier3` are long but *linearly* structured with numbered phase comments; cognitive complexity is moderate, and both are directly tested. **Not defects** — splitting them would only add parameter-passing noise. Reviewed; kept.
- `execute_tier2` catches a broad tuple and fabricates a neutral-50 result — intentional fail-open with explicit evidence string. Acceptable for availability, but note: Tier 2 failure *reduces* signal (a 50 is neither safe nor critical). Documented in code; keep.

## Classes / Modules

- `SQLUserRepository` (user CRUD + token revocation + scan counters) mixes two change drivers (users, token lifecycle) — mild. The repository layer is one of the healthiest parts of the codebase; do not split for metrics.
- `Frontend/components/ui/*` are generated shadcn components — standard practice, excluded from judgment.

## Complexity

- Essential complexity: 3-tier orchestration, SSE backpressure policy, SSRF resolver, weighted scoring — all justified by domain.
- Accidental complexity concentrated in: `ml/url_predictor.py` platform stubs + `cast(Any, …)` dance for optional imports; `tier_2/main.py` dual-import fallbacks; `gateway.py`'s layered cache-hit fast path. Each is *individually* reasonable; collectively the "optional dependency" pattern is re-implemented ~6 times differently (F-01 pattern).

## Code Smells

- **Bloaters:** long orchestration functions (accepted), `sql_repositories.py` at 869 L with 6 repository classes (cohesive by layer, acceptable).
- **Change preventers:** `tier_2/main.py` vs `gateway.py` duplicated security-pipeline/bootstrap code (shotgun surgery risk when middleware changes — F-02).
- **Dispensables:** `requirements.txt.bak`, stray `*.db` files at root and `Backend/` (`test_migration.db`, `test_probe.db`, `blackbox_durability_test.db`, `test_durability.db`), root `package.json` containing only `next` (F-04, F-07).
- **Modern smells:** module-level mutable state (contained); boolean-flag `is_safe_webhook_url(url, allow_http=False)` is a legitimate policy flag, kept.
- **Phased test files** (`test_url_ml_phase2.py` … `phase18_1.py`, 24+ files): the phase numbering is historical scaffolding that now obscures discovery — reorganize by subject, not by sprint (F-08).

## Abstractions

- **Stable, justified:** `URLPredictor` Protocol (real second implementation: URLBERT + ONNX), `CacheBackend`/repository protocols (real in-memory + SQL variants, needed for testability and prod), circuit breaker (real failure mode).
- **Not premature:** no interface-with-one-implementation found. `factory.py` is honest DI-at-module-scope; it works and is tested.
- **Leak risk:** `ClerkTokenVerifier.config` as a class attribute leaks import-time environment state into every call site.

## Duplication

- **Knowledge duplication (real):** scan bootstrap + validation + rate-limit wiring between `tier_2/main.py` and `gateway.py`; SSE publish/evict logic duplicated between `_notify_live_dashboard` and `receive_tier1_report` (~15 lines, identical eviction loop). These change together. F-02.
- **Incidental (tolerate):** the two threshold-ladder functions; per-router service boilerplate; `components/ui/use-toast.ts` vs `hooks/use-toast.ts` (shadcn convention — leave).
- **Deliberate:** `GatewayScanResponse` vs legacy `Tier1Report` coexistence with explicit deprecation — correct strangler pattern.

## SOLID

- SRP: respected at module level; `gateway.py` strains it by size, not by logic.
- OCP: ML predictor protocols and router plug-ins (`EXTENSIONS_AVAILABLE` guard) provide real extension points without speculative hierarchies.
- LSP/ISP: protocols are small and client-shaped. Good.
- DIP: repositories invert persistence correctly; no cargo-cult interface-per-class anywhere. This codebase **does not** suffer from SOLID over-application — worth preserving.

## Composition / Inheritance

- Inheritance is nearly absent (one `dict` subclass). Composition used throughout. No fragile-base-class risk.

## Error Handling

- Consistent pattern: catch narrow exception tuples, log with context (`exc_info=True` at boundaries), convert to explicit fallback results (`Tier2Result(score=50, status=ERROR)`). No swallowed-exception sweeps found; a couple of `except Exception: pass` in metrics middleware is defensible (telemetry must never break requests) but should be `logger.debug`.
- `ClerkVerificationError` with `status_code` is a clean typed-error boundary.
- Tier 3 failure produces neutral 50 + FAILED status — explicit, tested, correct availability-first choice.

## State / Side Effects

- Scan lifecycle state (partial → final) is explicit in the repository; the `scan_results_lock` serializes read-modify-write. Correct for single-process uvicorn; **document that the gateway is not horizontally scale-safe** (in-memory repos + SSE subscriber registry assume one instance) — README claims "stateless API Gateway" which is inaccurate (F-09).
- `BoundedScanTracker` self-prunes — good memory hygiene, unusual care.

## Concurrency

- asyncio used correctly: `asyncio.to_thread` for blocking WHOIS, queue-based SSE with drop-oldest backpressure and eviction metrics — genuinely well-engineered.
- Fire-and-forget `asyncio.create_task` without holding references (dashboard notifications) — tasks can be GC'd mid-flight; a named task set would be safer. LOW-MED.
- Redis-based circuit breaker state exists but default path is in-memory — fine for the stated topology; the horizontal-scaling caveat above covers it.

## Testability

- Excellent: repository protocols + factory reset hooks, `ZEROPHISH_TEST_AUTH` mode, fakeredis option, 66 test files, 347 passing tests, characterization coverage for scoring functions.
- Test-only pollution: minimal — test-mode branches are small and flagged.
- Frontend: adapter logic well tested (`live-tier1.test.ts`, 444 L); page components largely untested (typical for this maturity; acceptable).

## Types

- Backend: Pydantic v2 models define the API contract; internal `Dict[str, Any]` appears at extension boundary and SSE payloads only. `cast(Any, …)` clusters in `url_predictor.py` are the noisiest typing but guarded by runtime fallbacks.
- Frontend: `strict: true`, CI runs `tsc --noEmit` (verified passing). `verdict?: "SAFE" | ... | string` in `GatewayScanResponse` weakens the union — the `| string` escape hatch defeats the type. LOW.
- No runtime schema validation of the extension→gateway report payload (`Dict[str, Any]`).

## Configuration

- `GatewayConfig` frozen dataclass with `__post_init__` validation — exemplary.
- Env sprawl: variables read via `os.getenv` in at least three conventions (`ZEROPHISH_ENV` vs `ENV`, `SCAN_RATE_LIMIT` vs `GATEWAY_SCAN_RATE_LIMIT`). Precedence is defined but undocumented (F-10).
- `Backend/.env` correctly gitignored; `.env.example` present. Gitleaks in CI + `.gitleaksignore`.

## Dependencies

- Pinned exact versions (`==`) for backend, caret for frontend with lockfile — sound strategy. pip-audit in CI. `requirements.txt.bak` should go.
- `torch==2.13.0` duplicated in two identical environment markers (`<3.13` and `>=3.13`) — collapse to one line. LOW.
- Frontend carries the full shadcn/Radix set (30+ packages) — heavy but conventional for the template; not maintenance-threatening.
- CI ignores one vuln (`PYSEC-2022-43059`) with an inline comment-worthy justification missing — add a why-comment.

## Organization

- Feature-locality good: extension routers colocate router+service+models. `ml/` is large but subdivided (`shadow`, `benchmark`, `data`). Root contains test DB artifacts and a stray `package.json` — hygiene, not architecture.

## Architecture Fitness

- **Documented ≠ enforced.** Boundaries rely on review discipline. No import-linter/pytest-arch tests exist. Given clean current direction, a *small* architecture test (e.g., "nothing in `repositories/` imports `gateway`", "security/ imports no feature modules") would lock in the current good state cheaply. F-11.

## Code Generation

- None. Frontend `components/ui` is template-copied vendor code with clear convention — no regeneration process needed.

## Legacy

- `Backend/main.py` shim: honest deprecation, removal slated "v3.0". `tier_2/main.py` is a *second* live FastAPI app (port 8000) overlapping the gateway — the legacy path, still referenced by README's "Tier 2 Backend" section. This is the primary legacy area and should either be reduced to a thin proxy or explicitly sunset. F-02.
- 24 phase-numbered ML test files are archaeology; subject-named files would retire the phases.

## Refactoring Risk

- **Safe to change:** repositories (both impls tested), scoring helpers (unit-tested), security validators (dedicated tests), frontend adapter (tested).
- **Higher risk:** `gateway.py` request pipeline (integration-tested but heavily branchy), `tier_2/main.py` (dual-import subtleties), ML loading paths (platform-dependent). Characterization exists for most; do not restructure `url_predictor.py` without the phase tests as a net.

## Technical Debt

| Item | Type | Class | Evidence |
|---|---|---|---|
| `tier_2/main.py` parallel app | architecture | Intentional/Prudent | dual entrypoints documented in README |
| `main.py` shim + legacy models | code | Intentional/Prudent | deprecation notice, v3.0 removal target |
| Phased test file names | testing | Accidental/Reckless-lite | 24 files `test_url_ml_phase*` |
| `.bak`, `*.db`, root `package.json` | code/hygiene | Accidental | files on disk |
| Module singletons | design | Intentional/Prudent | reset hooks for tests |
| Optional-dep pattern re-implementation | code | Accidental | 6 divergent try/except import styles |
| README drift (coverage badge 85% vs CI 65%; "stateless"; Tier 2 section) | documentation | Accidental | README vs `ci.yml` |

## Code Review

- CODEOWNERS restricts auth/security/CI review — good risk-based ownership. PR checklist in README covers tests, security gate, docs. No evidence of nitpick-driven review config; lint is automated (black/isort/eslint) so style shouldn't block review.

## PR / Change Locality

- The repository layer and security layer support local change well. The scan-response shape (`GatewayScanResponse` → frontend adapter → extension consumption) is the one change that fans out across three runtimes; the typed adapter in `lib/live-tier1.ts` mitigates it. Keep the adapter authoritative.

## Static Analysis

- Present: gitleaks, CodeQL (`codeql.yml`), pip-audit, pytest coverage, eslint, `tsc --noEmit`, black/isort configs.
- Missing: **mypy/ruff in CI** despite `Backend/pyproject.toml` tool sections existing — the type-checker config is aspirational, not enforced. `Backend/.mypy_cache` shows local use. F-12.
- No dead-code detection; the legacy shim proves the need is mild.

## Quality Gates

- Local: format/lint available; pre-commit runs gitleaks+semgrep per README (config present).
- PR: secrets, backend tests+migrations+coverage(65%), pip-audit, frontend test+build+tsc. Solid and proportional.
- Gap: coverage gate of 65% is a floor, not a target — fine as a ratchet. README badge claims 85% — reconcile with the actual gate.

## Metrics

- Coverage, latency benchmarks (`benchmark/`), shadow-cascade evaluation — signals tied to decisions. No vanity-metric optimization detected. Test *counts* are cited in README ("322+ tests") — cosmetic, harmless.

## Performance / Maintainability

- ML inference has bounded latency constants (`DEFAULT_INFERENCE_TIMEOUT=2.0`), benchmark suites, and shadow evaluation — optimization is evidence-driven. The latency README table is plausible and the benchmarks justify the caching/circuit-breaker complexity. No unprofiled hot-path contortions found.

## Anti-Patterns

- Found: god-module-by-size (gateway), global-ish singletons (contained), utility dumping (none serious), architecture astronautics (none), interface explosion (none).
- Notably **absent**: premature abstraction, cargo-cult SOLID, swallowed exceptions, stale TODOs, deep inheritance.

## Decision-Tree Findings

- *Should I refactor `gateway.py` now?* Pain = concurrent-edit collisions (only if team >1); risk = moderate; tests = good. **PLAN, not DO NOW.**
- *Deduplicate tier_2/main vs gateway bootstrap?* Same knowledge, changes together. **Yes — extract shared security-pipeline setup.**
- *Introduce interfaces?* Already exist where justified. **No new ones.**
- *Delete legacy shim?* Defer to v3.0 as documented. **Defer.**
- *Deduplicate SSE publish loop?* ~15 identical lines; extract a `publish_to_subscribers()` helper. **Yes, trivial.**
- *Rewrite `url_predictor.py` typing?* Tests characterize behavior; runtime fallbacks are load-bearing. **Defer/Contain.**

## Strengths Worth Preserving

1. Repository protocol + factory pattern with production fail-closed check.
2. Explicit deprecation discipline (shims with removal targets, `@deprecated` markers).
3. SSE backpressure engineering with eviction metrics.
4. Security middleware suite (SSRF resolver is thorough: NAT64, CGNAT, IPv4-mapped handling).
5. Immutable validated config dataclass.
6. Evidence-driven ML benchmarking culture.
7. Adapter layer isolating the frontend from API schema evolution.

## Critical Gaps

1. No architecture-boundary enforcement (tests/linter rules).
2. No type-checker or Python linter in CI.
3. Dual backend entrypoints with duplicated bootstrap.
4. Horizontal-scale assumptions undocumented (README says "stateless").
5. Untyped extension→gateway report contract.

## Prioritized Code Quality Roadmap

### 🔴 DO NOW
- **F-09 — Correct the "stateless gateway" claim / document scale topology** (docs; 30 min; prevents an operational incident).
- **F-07 — Repo hygiene:** delete `requirements.txt.bak`, stray `*.db` files, root `package.json` (if truly unused); ensure `.coverage`/DB artifacts are ignored.

### 🟠 PLAN
- **F-02 — Deduplicate gateway/tier_2 bootstrap and SSE publish loop** (small extraction, tests exist).
- **F-12 — Add mypy + ruff to CI** (config exists; start non-strict on `ml/`).
- **F-11 — Architecture boundary tests** (~4 pytest rules capturing current direction).
- **F-05 — Pydantic model for `/tier1/report` payload** (replaces `Dict[str, Any]`).

### 🟡 CONTAIN
- **F-01 — Standardize optional-import pattern** behind one helper (touches ML load paths; do with tests green).
- **F-03 — Move `ClerkTokenVerifier.config` to instance/lazy resolution.**
- **F-06 — Unify verdict threshold ladders or rename to distinguish them.**
- **F-08 — Rename phase-numbered test files by subject.**
- **F-10 — Document env var precedence (ZEROPHISH_ENV vs ENV, rate-limit aliases).**

### 🔵 ACCEPT
- Long-but-linear orchestration functions; SQL repository size; shadcn duplication; `BoundedScanTracker` dict subclassing.

### ❌ NOT JUSTIFIED
- Splitting `gateway_scan` into micro-functions; introducing a service layer between routers and repositories; abstracting the cache backend further (already protocol-based); rewriting `url_predictor.py` typing.

---

## Key Finding Records (format per §45)

### F-02 — Duplicated bootstrap between dual entrypoints
```
ID: F-02
Area: Architecture / Duplication
Component: Backend/gateway.py, Backend/tier_2/main.py
Current State: Two FastAPI apps each wire CORS, security middleware, validation, rate limiting independently.
Evidence: tier_2/main.py imports security.middleware + ml_model with dual fallbacks; gateway.py repeats pipeline wiring.
Observed Pain: Middleware/security changes must be applied twice; drift risk.
Defect / Smell: Shotgun surgery / duplicated knowledge.
Impact: Medium. Change Frequency: Medium. Coupling / Blast Radius: Both entrypoints. Correctness Risk: Low-Medium. Security Risk: Medium (security drift). Maintainability Impact: Medium.
Root Cause: Historical: tier_2 predates the gateway; both were kept alive.
Recommended Direction: Extract shared app-factory (middleware+validation) helper; keep two entrypoints or proxy tier_2 through gateway.
Refactor / Keep / Defer / Delete: Refactor (small, incremental).
Implementation Complexity: Low-Medium. Validation Method: existing tests + boot both apps in CI smoke.
Priority: 🟠 PLAN. Owner: Backend team.
```

### F-09 — Scale-topology documentation contradiction
```
ID: F-09
Area: Documentation / Operations
Component: README ("Scaling Considerations"), Backend/gateway.py
Current State: README claims "Stateless API Gateway – can be replicated behind a load balancer", but scan results (default in-memory repo), SSE subscriber registry, and circuit breaker state are in-process.
Evidence: repositories/factory.py default branch; _sse_subscribers dict; tier3_circuit_breaker singleton.
Observed Pain: An operator following the README would deploy replicas with sticky-less LB and lose scans/SSE.
Defect / Smell: Lying documentation.
Impact: High (operational). Correctness Risk: Medium (documented behavior ≠ actual). Maintainability Impact: Low.
Root Cause: Scaling section aspirational rather than descriptive.
Recommended Direction: Either require DATABASE_URL+Redis for multi-instance and document it, or fix README to state single-instance constraint.
Refactor / Keep / Defer / Delete: Refactor (docs only).
Implementation Complexity: Trivial. Validation Method: review by operator.
Priority: 🔴 DO NOW. Owner: Docs owner.
```

*(Remaining findings F-01, F-03–F-08, F-10–F-12 are summarized in the roadmap above with the same field structure applied inline.)*
