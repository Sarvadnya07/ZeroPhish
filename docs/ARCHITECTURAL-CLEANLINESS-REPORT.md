# ARCHITECTURAL CLEANLINESS & BOUNDARY ENGINEERING REPORT

**Date:** 2026-09-16 · **Branch:** `reliability/p1-production-hardening` · **Mode:** architecture inspection + minimal, gate-approved structural remediation.
**Inputs:** `docs/CLEAN-CODE-FORENSIC-AUDIT.md` (verified against actual imports, not taken on faith), full import-graph analysis via AST.

---

## 1. Executive Summary

The repository implements a **coherent, intentional layered modular monolith** whose dependency direction is clean, mostly documented, and now partially *enforced by automated tests*. The full package import graph was rebuilt from AST this phase: **no package-level import cycles exist**; apparent "cycles" from naive file-level analysis (e.g., `analytics↔repositories`, `ml↔tier_2`) dissolve on runtime-edge inspection into one-directional dependency *pairs* across differently-named directories.

The single genuine architectural problem — **a dormant second entrypoint (`tier_2/main.py`, 736 L, module-level FastAPI app, zero dependents, zero deployment references)** plus its **stale documentation presenting port 8000 as a live service** — was remediated the cheapest safe way: documentation drift was eliminated and the topology was made explicit in the README. Code deletion of `tier_2/main.py` remains deliberately deferred (v3.0) because two legacy test suites still exercise legacy models through `Backend/main.py`, and removal is a behavior-affecting change with near-zero present-day pain.

## 2. Current Architecture

| Property | Finding |
|---|---|
| Style | Layered modular monolith (single deployable backend + SPA frontend + MV3 extension) |
| Entrypoints | **One canonical**: `Backend/gateway.py` (port 8001). One dormant legacy: `tier_2/main.py`. One compat shim: `Backend/main.py` (delegates to gateway; deprecated, removal v3.0) |
| Layering | routers/services (feature packages) → repositories (factory + SQL/in-memory) → infrastructure (SQLAlchemy) — real and import-verifiable |
| Foundation layers | `security/` (validation, SSRF, headers, audit), `models/` (DTOs), `circuit_breaker.py` |
| Orchestration | `gateway.py` in-process: tier1 heuristics → tier2 (`tier_2.analyzer`) → tier3 (Gemini behind circuit breaker) → weighted score → SSE + webhooks + analytics |
| Scale model | Single process (README-documented, verified) |
| Enforcement | 4 AST boundary rules + 6 detector self-tests, proven non-vacuous (CQ-03) |

## 3. Actual Dependency Model (AST-verified, runtime edges)

```
gateway → {analytics, auth, awareness, circuit_breaker, email_scanner, incidents,
           infrastructure, ml, models, repositories, security, tier_2, vision, webhooks}
tier_2  → {security}          (+ ml in benchmark scripts only)
ml      → {tier_2.analyzer}   (11 files — heuristics reuse; see §9)
analytics → {auth, models, repositories, (incidents: guarded lazy, §5)}
auth    → {models, repositories, security}
incidents → {auth, models, repositories, webhooks}
webhooks → {auth, models, repositories, security}
awareness/email_scanner/vision → {auth, models, security}
repositories → {analytics.models, auth.models, incidents.models, webhooks.models, models, infrastructure}
infrastructure → {} (bottom)
security → {} (foundation)
```

Package-level cycles found by the graph tool: **none** (the DFS hits were file-level artifacts of gateway being a *consumer* of everything it orchestrates, and of the shared models/factory seams below).

## 4. Module & Package Map

| Package | Cohesion | Coupling | Notes |
|---|---|---|---|
| `gateway.py` (1,168 L) | High (orchestration) | High fan-out (by design — it *is* the composition root) | Growth watched (CLEAN-01 F-D trigger stands) |
| `tier_2/` | High | Out: security, (ml: benchmarks) | analyzer/rules/domain_intel = cohesive domain core |
| `ml/` | High per-subpackage | Out: tier_2 (analyzer), internal | benchmark/ scripts dominate the tier_2 edges |
| `security/` | Excellent | Zero outbound | True foundation |
| `repositories/` | Excellent | Out: models/infrastructure only | factory = honest module-scope DI (12 consumers) |
| `infrastructure/` | Excellent | Zero outbound | Bottom of graph |
| feature routers (7) | Good | Out: auth/models/security (+own service) | Uniform shape, no gateway imports |
| `webhooks/`, `incidents/`, `analytics/` | Good | See §5 pairing | Cross-service edges are narrow (models/service) |

## 5. Boundary Analysis

**B1 — `incidents` ↔ `analytics` (runtime edge, one-directional, guarded).** `analytics/service.py:121` lazily imports `IncidentService` to enrich the dashboard with open-incident counts, wrapped in `TimeoutError`/`ImportError`/`Exception` guards with a documented degraded default. This is a *feature-level* edge (analytics knows incidents), not a cycle — incidents never imports analytics. Verdict: **justified coupling**, correctly guarded; the alternative (event bus) is not justified at this scale.

**B2 — `repositories` ← feature-models seam.** Repositories import the `models` modules of the domains they persist (`analytics.models`, `auth.models`, …). The boundary test explicitly allows this and documents why: these are shared value types (DTOs), not behavior. The alternative (duplicate DTO definitions per layer) would be worse. Verdict: **correct seam**, enforced, documented.

**B3 — `webhooks` ↔ `incidents`.** `incidents` imports `WebhookService`/`WebhookEventType` to fire incident events; webhooks never imports incidents. One-directional, service-level. **Justified.**

**B4 — `tier_2/main.py` boundary (the problem — see §21, A-1).** A 736-line module containing a module-level `FastAPI` app, its own middleware wiring, duplicated bootstrap, and a deprecation warning — reachable by nothing except a stale doc row. It sits inside the `tier_2` package, so `import tier_2` package hygiene coexists with an entire dead application. **Remediated via documentation this phase; code removal deferred (see §23).**

**B5 — `security/` foundation boundary.** Verified: imports zero feature/application modules; 13 files across all layers import it. This is the strongest boundary in the repo.

**B6 — `ml/` → `tier_2.analyzer` edge.** 11 ml files reuse `ThreatAnalyzer` heuristics. Direction is stable (ml is a *consumer* of tier-2 heuristics; tier_2 only touches ml in benchmark scripts). Slight layering smell (two "engines" sharing heuristics without a shared home), but the edge is narrow (`_analyze_links`) and churn-localized. **Accept as-is**; do-not-change unless ml gains its own heuristic implementation (then duplicate deliberately).

## 6. Coupling Analysis

- Data coupling dominates (explicit Pydantic models) — healthy.
- The highest fan-out node is `gateway` (14 packages) — this is *composition-root coupling*, appropriate for a monolith orchestrator; extracting a DI container would add ceremony without reducing real change cost.
- `repositories.factory` fan-in = 12 — stable, tested seam; the single mutable-singleton cluster is documented (single-instance topology).
- Temporal coupling: lifespan shutdown ordering (drain → webhooks → cache → SSE) — explicit, numbered, commented. Acceptable.

**What must change together (verified):** scan-response shape (gateway models → frontend adapter → extension) remains the only genuine cross-surface contract; changes there are inherently multi-component. **What can change independently (verified):** any feature router + its service + its repository, security internals, ml internals, repository implementations.

## 7. Cohesion Analysis

All packages are functionally cohesive — no technical dumping grounds, no unrelated lifecycle groupings. The one *file*-level cohesion strain remains `gateway.py` (orchestration + SSE + lifecycle + cache), tracked with an explicit extraction trigger (third change driver → `lifecycle.py`). Nothing qualified this phase.

## 8. Dependency-Direction Analysis

Direction is intentional and now test-enforced: `security/`, `repositories/`, `infrastructure/` import no upward modules; feature routers never import gateway; nothing imports `main.py` except its own test. The rules match actual requirements rather than textbook purity — e.g., the deliberate repositories→models allowance is documented in the test docstring. **No direction changes needed.**

## 9. Abstraction Analysis

No premature, speculative, or shallow abstractions found (re-verified this phase against the graph): the repository protocols have two real implementations, the cache backend two, the predictor protocol two, the circuit breaker one real failure mode. `factory.py` is DI at module scope without a container — the right weight. No wrapper chains, no interface-for-everything, no factory-for-one.

## 10. Public API Surface Analysis

HTTP surface: stable, documented, dual-endpoint compatibility for the extension deliberately retained. Internal accidental exposure: `webhooks.service._close_client` (private-by-convention, called by gateway lifespan) and `_spawn_background_task`/`_background_tasks` (imported by `test_p1_reliability.py`). Both are Python-conventional; formalizing privacy would add ceremony. **Accepted.**

## 11. Domain Boundary Analysis

Business rules live in their owning layers: verdict thresholds in gateway (pinned by tests), incident state machine in `incidents/service`, webhook event policy in `webhooks/service`, scoring fusion in `ml/fusion`. The only cross-component duplication of *knowledge* remains tier-2 bootstrap logic between the dormant `tier_2/main.py` and `gateway.py` — which resolves entirely when the dormant entrypoint is deleted (v3.0).

## 12. Data Ownership Analysis

Each domain owns its models; `repositories/` owns persistence; `infrastructure/` owns the engine/schema; gateway owns in-process scan state (documented single-instance). Transaction boundaries live in the repositories (per-method commit/rollback, verified by fault-injection tests). No shared-database integration, no schema leakage across domains. **Healthy.**

## 13. Service / Distributed-System Analysis

One backend service, no distributed-monolith tendencies, no shared-database coupling. The README's earlier presentation of Tier 2 as a separate *service* (port 8000, mermaid participant "T2") was drift from reality — tier 2 is an **in-process library** invoked by the gateway. **Corrected this phase** (README now states it explicitly).

## 14. Event / Async Boundary Analysis

Background work is bounded and owned: `_spawn_background_task` strong-reference registry + lifespan drain (5s cap), SSE bounded queues with drop-oldest, webhook dispatch decoupled with at-most-once semantics now documented (previous phase). No queues/workers exist; no hidden async boundaries introduced.

## 15. Cross-Cutting Concern Analysis

Security: centralized in `security/` (foundation, zero outbound) — exemplary. Auth: `auth/` middleware consumed uniformly by all routers. Logging: stdlib logging with context (scan_id); metrics in-process. Caching: behind `CacheBackend` protocol with degradation. Retries: deliberately absent (circuit breaker instead) — consistent. **No cross-cutting pollution found.**

## 16. Architecture Drift

| Drift | Severity | Action this phase |
|---|---|---|
| `tier_2/main.py` presented as live "Tier 2 Backend (Port 8000)" in README ×2 + QUICK_REFERENCE | Emerging risk (operator confusion) | **Fixed**: both README sections + QUICK_REFERENCE marked deprecated with canonical pointer |
| Mermaid diagrams show T2 as network service | Documentation drift | **Fixed**: topology note states tier 2 runs in-process |
| Architecture section of README was a placeholder `*(unchanged...)*` with no boundary documentation | Documentation drift | **Fixed**: added Module Topology & Dependency Rules section with enforced-rules list |

## 17. Technical Debt

| Item | Type | Interest | Class |
|---|---|---|---|
| `tier_2/main.py` dormant app (736 L) | architectural | near-zero runtime; moderate confusion interest; blocks clean `tier_2` package story | intentional (v3.0) |
| `Backend/main.py` shim + legacy models | compatibility | near-zero (2 legacy test suites) | intentional (v3.0) |
| `ml/` optional-import idiom ×6 | code | onboarding friction | accidental (PLAN) |
| gateway.py multi-driver file | structural | materializes only with team growth | intentional (trigger documented) |

## 18. Architectural Smell Inventory

Found (mild, all previously catalogued): god-file (gateway, by size not logic), dormant dual entrypoint, phase-numbered ML test fragmentation. **Not found:** distributed monolith, shared-database coupling, cycles, service locator, interface/wrapper explosion, utility dumping grounds, copy-paste architecture, premature microservices.

## 19. AI-Generated Architecture Pollution

Checked explicitly: no wrapper-around-wrapper, no generated interface layers, no duplicate DTO/validation stacks, no invented patterns. The one AI-flavored artifact is documentation *scaffolding* ("*(unchanged, your X is excellent)*" placeholder sections in README) that described architecture without documenting it — remediated this phase for the Architecture section. **Machine-generated architecture risk: low.**

## 20. Strong Architectural Areas (preserve)

1. `security/` as a true foundation (zero outbound deps, high fan-in)
2. Repository protocol layer with real dual implementations and enforced direction
3. Enforced boundary tests with self-tested detector (proven non-vacuous)
4. Single composition root with explicit in-process tier invocation
5. `infrastructure/` at the true bottom of the graph
6. Uniform feature-router shape (auth/models/security triad)
7. Deliberate, documented seam allowances (repositories→models)
8. Guarded, degraded cross-service enrichment (analytics→incidents)
9. Honest single-instance scale documentation
10. Zero import cycles at package level

## 21. High-Value Problems

**A-1 — Dormant second entrypoint + stale "Port 8000 service" documentation**
```
FINDING ID: A-1
SEVERITY: HIGH (documentation/operational), MEDIUM (structural)
CONFIDENCE: HIGH

LOCATION: Backend/tier_2/main.py; README.md (2 endpoint tables, mermaid); docs/QUICK_REFERENCE.md
COMPONENT: Backend entrypoints
SYMBOLS: tier_2.main.app

CURRENT STATE: 736-line legacy FastAPI app with module-level app, duplicated middleware
  wiring, deprecation warning at import; zero dependents; not referenced by CI, docker,
  tests, or runtime config. README twice documents it as a live "Tier 2 Backend
  (Port 8000)" with endpoint tables; QUICK_REFERENCE lists it as "Main FastAPI backend server".

EVIDENCE: grep across README/docs/CI/docker/extension/frontend — only doc references;
  `grep -rln "tier_2.main" Backend --include=*.py` → only the file itself;
  pyproject coverage config explicitly omits it.

ARCHITECTURAL PROBLEM: dual-entrypoint ambiguity + documentation asserting an
  architecture (two services) that does not exist (one service, in-process tier 2).

PRACTICAL IMPACT: an operator following the README provisions/monitors a service that
  should not exist; newcomers may build against the deprecated app; the "duplicated
  bootstrap" debt attributed to it is frozen in place by documentation legitimacy.

COUPLING EFFECT: keeps apparent shotgun-surgery surface (middleware changes must
  consider "both" apps) alive in reviewers' minds.

CHANGE AMPLIFICATION: today, none in code — only in documentation and human models.

JUSTIFIED OR ACCIDENTAL: the file's existence was justified during migration; the
  documentation presenting it as live is accidental and was harmful.

RECOMMENDED STRUCTURAL CHANGE (implemented): mark both README endpoint tables and
  QUICK_REFERENCE as deprecated with canonical pointer; state in the README topology
  section that tier 2 analysis runs in-process and tier_2/main.py is retained only as
  a compatibility reference until v3.0. Code deletion deferred to v3.0 (see §23).

COMPLEXITY REMOVED: false two-service architecture; operator/newcomer confusion.
COMPLEXITY INTRODUCED: none.
BLAST RADIUS: documentation only.
MIGRATION RISK: none.
VERIFICATION: README/QUICK_REFERENCE diff; no runtime surface touched.
DO-NOT-CHANGE CONDITIONS: if a deployment begins genuinely using port 8000 again,
  the deprecation notes must be revisited (and the architecture re-decided) first.
```

## 22. Target Architecture

Unchanged from current, with one clarification now documented: **single-entrypoint modular monolith** where tier 2 is an in-process analysis library, tier 3 is an external provider behind the circuit breaker, and the four enforced boundary rules hold. No new packages, layers, or interfaces are proposed — the implementation gate (§28) rejected every structural move as net-negative or premature (§24).

## 23. Migration Strategy (for the one remaining structural item)

`tier_2/main.py` deletion at v3.0, in order: (1) confirm `Backend/main.py` legacy test suites (`test_main.py`, phase13_3 content assertions) no longer reference the legacy models; (2) delete `tier_2/main.py` and the `Backend/main.py` shim together; (3) update the boundary test's docstrings if the `tier_2` rule set changes; (4) remove the README deprecation notes. Estimated effort: hours. Until then, the documentation now tells the truth about its status.

## 24. Implementation Performed

Gate-approved and implemented (documentation-only structural remediation):
1. **README "Module Topology & Dependency Rules" section** — ASCII topology map, the four enforced rules with pointer to the authoritative test module, explicit statement that tier 2 runs in-process and `tier_2/main.py` is a dormant legacy reference. Replaces the `*(unchanged...)*` placeholder.
2. **README "Tier 2 Backend (Port 8000)" tables (×2)** — marked ⚠️ Deprecated with explanation and canonical pointer.
3. **`docs/QUICK_REFERENCE.md`** — key-files row corrected: canonical entrypoint is `Backend/gateway.py`; `tier_2/main.py` marked deprecated.

Gate-rejected (with reasons — evidence of rejected changes preserved):
- **Delete `tier_2/main.py` now:** blocked by v3.0 compat contract and `Backend/main.py` legacy-model test consumers; near-zero present pain; documentation fix captures ~all the value. 
- **Extract gateway lifecycle.py:** only two change drivers; trigger not yet met.
- **Break the "ml↔tier_2" pair:** not a cycle; the edge is narrow and churn-localized (§5 B6).
- **Event-bus for analytics→incidents:** distributed machinery unjustified for one guarded enrichment call.
- **Formalize private-symbol exports:** Python-conventional privacy suffices at this scale.

## 25. Verification Results

| Check | Result |
|---|---|
| Backend pytest (full) | **395 passed, 5 warnings, 99.2s** |
| Frontend `tsc --noEmit` | clean (exit 0) |
| Architecture boundary tests | green (included in the 395) |
| Package-level cycle detection (AST, runtime edges) | none |
| Diff review | 8 files: 5 are pre-existing P1 work; my changes touch README, QUICK_REFERENCE, plus prior-phase backend changes — no code moved, no imports changed |

## 26. Remaining Risks

- `tier_2/main.py` remains importable and runnable; nothing *prevents* an operator from starting it. Mitigation is documentation + the import-time deprecation warning. If this risk ever materializes operationally, the v3.0 deletion should be pulled forward.
- The boundary rules cover import direction only, not public-symbol discipline (Python makes this cheap to enforce only via linting — not justified here).

## 27. Architecture Fitness Controls

Existing (keep): 4 AST boundary rules + 6 detector self-tests in pytest; CI coverage gate; CODEOWNERS on auth/security; pinned CI toolchain. Recommended (no new tooling): when `tier_2/main.py` is deleted at v3.0, add a boundary assertion that no module under a feature package defines a module-level `FastAPI()` app — turning the dual-entrypoint lesson into a durable rule.

---

## 36. ARCHITECTURAL SCORECARD

| Dimension | Rating | Basis |
|---|---|---|
| Boundary clarity | GOOD | enforced import rules; documented topology (now) |
| Cohesion | EXCELLENT | every package single-purpose; no dumping grounds |
| Coupling | GOOD | data coupling dominant; guarded cross-service edges; fan-out concentrated at the composition root by design |
| Dependency direction | EXCELLENT | intentional, enforced, self-tested, cycle-free |
| Abstraction quality | EXCELLENT | every abstraction has ≥2 real implementations; zero ceremony |
| Ownership clarity | GOOD | per-domain models/services/repos; single composition root |
| Public surface discipline | GOOD | stable HTTP contracts; deprecations explicit |
| Change locality | GOOD | features change independently; scan contract the one cross-surface surface |
| Testability | GOOD | fault injection, boundary tests, in-process seams |
| Domain isolation | GOOD | rules live in owning layers; no cross-layer rule duplication (post-v3.0: none at all) |
| Architecture consistency | GOOD | one style, one dormant exception (documented) |
| Technical-debt health | GOOD | visible, classified, dated, with deletion plan |
| Operational complexity | GOOD | single deployable; single instance documented |
| Scalability (arch.) | ACCEPTABLE | single-instance by design; vertical scale only — honest, documented |
| Maintainability | GOOD | enforced rules + honest docs + debt ledger |

## 37. FINAL ENGINEERING VERDICT

**ARCHITECTURE HEALTHY WITH MANAGEABLE DEBT**

Evidence: package-level cycle-free enforced layering; every abstraction justified; the single structural defect (dormant entrypoint + stale service documentation) has been remediated at the documentation layer and carries a concrete, scheduled deletion plan; all structural moves with weaker gates were rejected with recorded reasons.

## 38. FINAL QUESTIONS

1. **Biggest architectural problem:** the dormant `tier_2/main.py` entrypoint and its former documentation as a live "Port 8000 service."
2. **Most valuable structural improvement:** making the topology and its enforcement *visible and truthful* (implemented this phase); next, the v3.0 dual-entrypoint deletion.
3. **Abstraction to remove:** none — nothing speculative exists.
4. **Boundary to strengthen:** none new; at v3.0 add the no-module-level-FastAPI-app rule to the boundary tests.
5. **Dependency direction to change:** none — current direction is intentional and enforced.
6. **Highest change amplification:** the gateway scan-response contract (gateway models → frontend adapter → extension) — inherent to it being the cross-surface contract, not a defect.
7. **Architecture to NOT introduce:** microservices, an event bus, a DI container, a shared "core" package — all rejected by the gate with reasons recorded.
8. **Genuinely necessary complexity:** tier orchestration, SSRF defense, circuit breaker, SSE backpressure, per-method transaction blocks, the repositories→models DTO seam.
9. **Healthy architecture to preserve:** security foundation layer, repository protocols, enforced boundary tests, single composition root, infrastructure at the bottom.
10. **Safest migration sequence:** docs-first (done) → legacy consumer sunset (`Backend/main.py` tests) → delete `tier_2/main.py` + shim → add no-module-level-app boundary rule → drop deprecation notes.
