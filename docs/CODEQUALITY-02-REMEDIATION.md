# CODEQUALITY-02 — Remediation Report & Refactoring Ledger

**Date:** 2026-09-14 · **Phase:** CODEQUALITY-02 (remediation of CODEQUALITY-01 findings)
**Validation:** 351/351 backend tests pass (92s) · frontend `tsc --noEmit` clean.

---

## Code Quality Changes Implemented

Six targeted, evidence-backed remediations from the CODEQUALITY-01 roadmap. No behavioral changes to externally visible API responses; all existing tests pass unchanged plus 4 new architecture tests.

## Refactoring Summary

| ID | Finding | Change | Risk | Result |
|---|---|---|---|---|
| R-1 | F-07 repo hygiene | Deleted 5 stray `.db` artifacts + `requirements.txt.bak` | LOW | Trivially safe; files unreferenced by code, CI, or scripts |
| R-2 | F-09/F-10/F-13 doc drift | README: single-instance scale topology warning, coverage-gate correction, env-var precedence table | LOW | Documentation only |
| R-3 | F-02a SSE eviction duplication | Extracted `_broadcast_to_subscribers()` in `gateway.py`; two call sites now share one owner of the eviction policy | LOW | Tests (`test_gateway_sse.py`) characterize behavior before/after |
| R-4 | F-05 untyped extension contract | New `models/tier1_report.py` (`Tier1ReportPayload`, permissive) on `/tier1/report` | MEDIUM (mitigated) | Behavior-preserving; see ledger |
| R-5 | F-11 unenforced boundaries | New `tests/test_architecture_boundaries.py` — 4 AST-based dependency rules run in every `pytest` invocation | LOW | Codifies the *current clean* direction |
| R-6 | Dependency hygiene | Collapsed duplicated `torch` requirement lines in `requirements.txt` | LOW | Identical effective constraint |

## Function / Method Changes

- `gateway.py`: added `_broadcast_to_subscribers(payload)`; `_notify_live_dashboard` and `receive_tier1_report` each replaced their inline eviction loops with a call to it. `_publish_to_subscriber` unchanged.

## Class / Module Changes

- New `Backend/models/tier1_report.py`: `Tier1ReportPayload` (Pydantic v2, `extra="allow"`, all fields optional). Module docstring records *why* permissiveness is intentional (dashboard-update path must never 400 on a malformed extension report).

## Cohesion Improvements

- The SSE backpressure/eviction policy now has exactly one implementation (was two — one per broadcast call site). That policy is the piece most likely to change (queue sizes, thresholds, metrics), so its change locality is now a single function.

## Coupling Reduction

- `/tier1/report` no longer accepts an anonymous `Dict[str, Any]`; the endpoint's dependency on a *shape* is now explicit and named. Runtime coupling to the extension is unchanged (permissive model, extra fields preserved).

## Abstraction Changes

- Exactly one new abstraction (`Tier1ReportPayload`) — justified by F-05 (contract existed only by convention). No interfaces, protocols, or factories were added anywhere. The model is deliberately *not* strict: a strict schema here would change observable behavior (400s on legacy extension payloads), violating the preservation rule.

## Duplication Decisions

- **Eliminated (knowledge duplication):** SSE publish-evict loop (changes together: backpressure policy).
- **Deliberately kept:** tier_2/main vs gateway bootstrap (F-02 full remediation requires the shared app-factory — deferred, see below); the two threshold ladders (pinned by tests, rename-only value); shadcn toast duplication (vendor convention).

## SOLID Changes

- None. No new interfaces. Existing protocols untouched.

## Composition / Inheritance Changes

- None.

## Error Handling

- No changes. Audit verified the existing pattern (narrow tuples, context-rich fallbacks) was healthy; nothing here justified touching it.

## State / Side Effects

- `_broadcast_to_subscribers` makes the eviction side effect *explicit by name* in both call sites. The underlying module-level `_sse_subscribers` state remains (single-process safe, tested, documented in the README topology note).

## Concurrency

- No changes. Eviction loop runs in the same async context as before (no lock semantics altered).

## Type Safety

- `Tier1ReportPayload` names the extension→gateway contract. Timestamp field is `Optional[Any]` because the extension sends ISO strings — tightening it would require first verifying every extension version's payload, which is exactly the kind of speculative typing the audit warned against.

## Configuration

- Documented env-var precedence in README (`ZEROPHISH_ENV` vs `ENV`; `SCAN_RATE_LIMIT` vs `GATEWAY_SCAN_RATE_LIMIT`; `STATUS_RATE_LIMIT` vs `GATEWAY_STATUS_RATE_LIMIT`). Code unchanged — the precedence logic is correct, only undocumented.

## Dependency Changes

- `requirements.txt`: two identical `torch==2.13.0` marker lines collapsed to one. No version changes. `requirements.txt.bak` deleted.

## Architecture Boundary Enforcement

`Backend/tests/test_architecture_boundaries.py` (runs in normal pytest, no extra tooling):
1. `repositories/` must not import application-layer modules (gateway, routers, tier_2/3, ml, services).
2. `security/` must not import feature modules or repositories.
3. `infrastructure/` must not import domain or application modules.
4. Feature routers must not import `gateway`.

AST-based: `TYPE_CHECKING`-guarded imports are treated as annotation-only seams (base.py legitimately uses them for protocol signatures); runtime try/except optional imports count as real edges. These tests document the *as-is* architecture — changing direction intentionally means updating the rules deliberately.

## Legacy Modernization

- None performed. `Backend/main.py` shim and `tier_2/main.py` remain per audit (`Defer` to v3.0 / PLAN).

## Technical Debt Changes

- **Retired:** F-07 (hygiene artifacts), F-09 (false "stateless" claim), F-13 (coverage badge drift), F-05 (anonymous contract), F-11 (unenforced boundaries), duplicate torch lines.
- **Made visible, not paid:** F-01 (optional-import pattern), F-02 remainder, F-03, F-06, F-08, F-10 code-side — remain classified CONTAIN/PLAN in the audit.

## Code Review Improvements

- No process changes. The new architecture tests give reviewers an automated first line for boundary questions.

## Static Analysis

- Unchanged in CI. (Adding mypy/ruff to CI — F-12 — is a CI-workflow change that should land with a clean mypy baseline; intentionally not bundled into this behavioral-remediation pass to keep the change reviewable.)

## Quality Gates

- Architecture rules are now enforced at the PR test stage (they run inside the existing `pytest tests/` CI job — no workflow edit needed).

## Complexity Changes

- Net: gateway.py +12 lines (helper + docstring) − 16 lines of duplicated loops; one more named concept. Cognitive complexity unchanged or slightly lower; no functions split.

## Dead Code

- Deleted: `Backend/requirements.txt.bak`, `test_migration.db`, `test_probe.db`, `test_durability.db`, `blackbox_durability_test.db`, `test_blackbox_durability.db` (all verified unreferenced by code, CI, scripts, and configs before deletion; `*.db` already gitignored — these were local residue, plus the tracked-list check confirmed none were in git).

## Documentation / Comments

- README: honest scale-topology warning (with the *why*: in-memory repos, SSE registry, breaker state), coverage-gate correction (`≥65%` CI gate, 85% remains local target), env precedence table.
- `models/tier1_report.py`: module docstring explains the permissiveness trade-off.
- `tests/test_architecture_boundaries.py`: docstring states the rules assert current direction and must be updated deliberately.

## Observability

- No changes. Existing SSE metrics and health endpoints already cover the refactored path.

## Performance-Sensitive Code

- `_broadcast_to_subscribers` is the identical loop moved into a function — zero measurable overhead (one function call per broadcast). No hot-path changes; nothing required profiling.

## Tests Added / Updated

- **Added:** `Backend/tests/test_architecture_boundaries.py` (4 tests).
- **Updated:** none. All 347 pre-existing tests pass unchanged; total is now 351.

## Validation Performed

1. Full backend suite: `351 passed, 9 warnings in 92.09s`.
2. Frontend: `npx tsc --noEmit` → clean.
3. Reference checks before every deletion (grep across code, CI, scripts, configs).
4. Architecture test initially failed on `repositories/base.py` — diagnosed as `TYPE_CHECKING`-guarded imports (annotation-only), refined the test rather than changing production code.

## Files Changed

- `README.md` (scale topology, coverage gate, env precedence)
- `Backend/gateway.py` (SSE broadcast helper; typed report endpoint)
- `Backend/models/tier1_report.py` (new)
- `Backend/tests/test_architecture_boundaries.py` (new)
- `Backend/requirements.txt` (torch line collapse)
- Deleted: `Backend/requirements.txt.bak`, 5 stray `*.db` files
- `docs/CODEQUALITY-01-AUDIT.md`, `docs/CODEQUALITY-02-REMEDIATION.md` (documentation)

## Remaining Debt

Per audit classification: F-01 (standardize optional-import helper — CONTAIN), F-02 remainder (shared app-factory for tier_2/main — PLAN), F-03 (Clerk import-time class config — CONTAIN), F-06 (threshold-ladder naming — CONTAIN), F-08 (phase-named test files — CONTAIN), F-12 (mypy/ruff in CI — PLAN).

## Deferred Refactoring

- **Gateway god-module split (F-02 full):** pain is only realized with >1 concurrent backend engineer; tests exist but the refactor touches the highest-traffic orchestration file. Deferred until merge-conflict or drift evidence materializes.
- **tier_2/main bootstrap dedup:** requires deciding the dual-entrypoint strategy first (proxy vs shared factory) — an architecture decision, not a cleanup.
- **Legacy `main.py` shim removal:** scheduled v3.0 per its own deprecation notice.

## Explicitly Rejected Changes

- Strict Pydantic validation on `/tier1/report` — would 400 legacy extension payloads (behavior change).
- Interface/abstraction layers for cache or repositories — protocols already exist.
- Splitting `gateway_scan` — long but linear, tested, high regression risk for zero local-reasoning gain.
- Renaming `_determine_threat_status` / merging threshold ladders — behavior pinned by tests; rename-only churn.
- Removing module-level gateway singletons — single-process topology is now documented as intentional; tests reset them cleanly.
- Mass dependency upgrades — no security driver; separate maintainability urgency from security urgency.

---

## Refactoring Ledger

### R-3 — SSE broadcast helper extraction
```text
Refactor ID: R-3
Area: Duplication / Cohesion
Original Pain: Backpressure-eviction policy duplicated in two call sites; policy drift risk.
Evidence: CODEQUALITY-01 F-02a; identical ~15-line loops in _notify_live_dashboard and receive_tier1_report.
Behavior Characterized: tests/test_gateway_sse.py exercises both endpoints (report→broadcast→latest, stream).
Refactoring: Extract Method → _broadcast_to_subscribers(payload).
Why This Abstraction / Structure: The eviction policy is the changing knowledge; one function owns it.
Alternative Considered: Leave duplicated (viable — but policy is the highest-churn SSE element); event-bus class (rejected — over-abstraction for 2 call sites).
Risk: LOW.
Tests Before: 347 passing. Tests After: 351 passing (same SSE tests, unchanged).
Complexity Before: 2× identical loops. Complexity After: 1 shared loop + 2 one-line calls.
Coupling Before: both call sites coupled to subscriber dict + overflow map details. After: both depend on one named function.
Change Locality Improvement: backpressure policy changes touch exactly one function.
Performance Impact: none (identical loop, one call frame).
Maintenance Impact: policy drift now impossible without failing the shared call sites.
Decision: Implemented.
```

### R-4 — Typed /tier1/report payload
```text
Refactor ID: R-4
Area: Type Safety / API Contract
Original Pain: Extension→gateway contract existed only by convention (Dict[str, Any]).
Evidence: CODEQUALITY-01 F-05; grep confirmed only test_gateway_sse.py consumes the endpoint.
Behavior Characterized: test_gateway_tier1_report_and_latest pins store-and-broadcast behavior.
Refactoring: Introduce Parameter Object (Tier1ReportPayload, extra="allow", all-optional).
Why This Abstraction / Structure: Names the contract at the boundary without changing it; single place to tighten later.
Alternative Considered: Strict schema (rejected — 400s legacy payloads = behavior change); leave untyped (rejected — audit flagged the contract gap as PLAN).
Risk: MEDIUM mitigated to LOW by extra="allow" + all-optional fields; model_dump preserves unknown keys.
Tests Before: 347 passing. Tests After: 351 passing (SSE tests unchanged and green).
Complexity Before: n/a. Complexity After: +1 small model with documented intent.
Coupling Before: anonymous dict. After: named, documented shape; runtime coupling identical.
Change Locality Improvement: contract changes now have a declared home.
Performance Impact: negligible (one validation pass on a low-frequency endpoint).
Maintenance Impact: extension-payload questions resolve by reading one file.
Decision: Implemented.
```

### R-5 — Architecture boundary tests
```text
Refactor ID: R-5
Area: Architecture Enforcement
Original Pain: Clean dependency direction enforced only by convention/review.
Evidence: CODEQUALITY-01 F-11 ("documented ≠ enforced").
Behavior Characterized: Direction verified by grep during audit; tests assert current direction.
Refactoring: Introduce 4 AST-based dependency-rule tests in the normal pytest run.
Why This Abstraction / Structure: Uses existing pytest gate (no new tooling, no CI edit); failures name file + rule.
Alternative Considered: import-linter plugin (rejected for now — extra tool, config, and CI wiring for 4 rules); package restructuring (rejected — no functional benefit).
Risk: LOW (tests-only). False-positive risk handled by treating TYPE_CHECKING imports as annotation-only seams (validated against repositories/base.py).
Tests Before: 347. Tests After: 351 (4 new).
Complexity Before/After: production code unchanged.
Coupling Before/After: unchanged; violations now fail CI.
Change Locality Improvement: boundary drift caught at the PR that causes it.
Performance Impact: +0.12s pytest time.
Maintenance Impact: intentional architecture changes require a deliberate rule update — by design.
Decision: Implemented.
```
