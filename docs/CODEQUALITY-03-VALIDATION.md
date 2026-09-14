# CODEQUALITY-03 — Validation & Regression Report

**Date:** 2026-09-14 · **Phase:** CODEQUALITY-03 (validation of CODEQUALITY-02 remediations)
**Final state:** 372/372 backend tests pass · frontend `tsc --noEmit` clean.

---

## Code Quality Validation Summary

**Headline result: the validation phase caught a serious defect in CODEQUALITY-02's own deliverable — the architecture boundary tests (R-5) were passing vacuously. They are now fixed, self-tested, and proven to fail on injected violations. R-1/R-2/R-3/R-4/R-6 validated as KEEP. No behavioral regressions found in production code.**

This is the single most important finding of CODEQUALITY-03: *a green test suite proves nothing about tests that can never fail.* The R-5 tests ran green in the CODEQUALITY-02 validation pass while detecting zero imports — their import scanner inspected the children of `Import`/`ImportFrom` nodes (which are `alias` leaves), so `runtime`/`typing_only` were always empty and every rule passed unconditionally.

## Behavioral Regression Results

| Change | Method | Result |
|---|---|---|
| R-3 SSE broadcast extraction | New characterization suite (`test_sse_broadcast_validation.py`, 6 tests) asserting observable state: payload delivery order, drop-oldest on full queue, overflow counters, eviction at threshold >5, registry/overflow-map cleanup, cross-call-site consistency | **No regression.** All pre-refactor side-effect semantics reproduced exactly. One test-harness correction: a hostile non-Queue object raising `AttributeError` was *never* guarded pre-refactor either (verified against git HEAD `baa62ba`); the test was corrected to characterize the actual contract (`TypeError/ValueError/RuntimeError` guard), not an imagined one |
| R-4 typed `/tier1/report` | New contract suite (`test_tier1_report_contract.py`, 9 tests): empty object, unknown extra fields round-trip, nulls, in-range `layers_completed` (0–3), non-dict bodies, numeric coercion | **One intentional narrowing found and documented:** `layers_completed=99` now returns 422 (was accepted as `Dict[str,Any]`). Judged acceptable — the 0–3 bound is domain-true (three tiers) and the behavior is pinned by an explicit test, not accidental. Empty payloads, unknown fields, and nulls (the compatibility-critical cases) preserved exactly |
| R-5 architecture tests | Negative validation: injected `from incidents.models import Incident` into `security/middleware.py`, ran the rule | **FAILED TO DETECT — test was vacuous.** Root cause in `_module_imports`. Fixed (see below); re-validated: injected violation now fails with a named offender, `TYPE_CHECKING`-style seam still correctly allowed, production file restored to pristine (`git diff` empty) |
| R-6 torch requirement | Effective constraint comparison | Identical: `torch==2.13.0` unconditioned (the two marker lines were disjoint and covered all Pythons) |
| R-1/R-2 (hygiene/docs) | Deletion reference-checks re-run; README claims diffed against code | No runtime surface touched; see Configuration Validation |

## Public API Compatibility

- `/tier1/report`: response shape (`{"status": "success", ...}`) unchanged; acceptance behavior preserved except the documented `layers_completed` bound.
- `/tier1/latest`: returns the broadcast dict verbatim including extra extension fields (test-pinned).
- `/gateway/*`, `/scan`, `/health`, `/metrics`, SSE endpoints: untouched by this phase; full suite green.
- No new public surface: `_broadcast_to_subscribers` is module-private; `Tier1ReportPayload` is a boundary model, not a new API.

## Error Handling Validation

- No production error-handling code changed in CQ-02. Characterization tests confirm the SSE publish guard tuple `(TypeError, ValueError, RuntimeError)` still evicts-and-continues without raising.
- The one *apparent* gap (unguarded `AttributeError` on non-queue objects) was verified pre-existing at git HEAD and left as-is — not silently "fixed", since no real code path produces it.

## State / Side-Effect Validation

- Eviction now occurs from exactly one code path; tests prove eviction performed by the HTTP endpoint path is visible to direct broadcasts (registry consistency — the specific failure mode the R-3 extraction was meant to prevent).
- Metrics (`sse_queue_full_total`, `sse_events_dropped_total`, `sse_subscriber_evictions_total`) increment identically to pre-refactor behavior.

## Concurrency Validation

- Same-loop semantics preserved: broadcast is synchronous within the event loop; no new locks, no changed ordering. Existing suite (incl. `test_gateway_sse.py`) green.

## Complexity Before / After

- `gateway.py`: 1045 → 1056 lines (helper + docstrings); eviction logic 2×~15-line loops → 1×~15-line function + 2 call sites. Cognitive complexity: unchanged or marginally lower. No functions split, no wrappers-for-metrics.

## Cohesion Before / After

- Improved: backpressure policy has one home. Validated by the cross-call-site consistency test.

## Coupling Before / After

- Architecture tests (now functional) confirm: no cycles; `security/`, `repositories/`, `infrastructure/` import no upward modules; routers never import gateway. The R-4 model *names* the extension contract without adding runtime coupling.

## Public Surface Changes

- Net zero. One private function, one boundary model, four rule tests + six detector self-tests.

## Abstraction Validation

- `Tier1ReportPayload`: **Strong** — represents a stable existing contract (not speculative), documented why-permissive, single tightening point. Validated against 9 characterized cases.
- `_broadcast_to_subscribers`: **Strong** — two real call sites sharing one policy.
- No premature/leaky/wrong abstractions introduced. Nothing needs inlining.

## Duplication Validation

- Eviction loop dedup verified safe: the two call sites share the *same* change driver (backpressure policy); no parameters were forced; no independent domains coupled. Coverage of the merged loop is complete (delivery, overflow, eviction, failure branches all tested).

## SOLID Validation

- No SOLID-motivated changes in CQ-02; nothing to validate. No interface/micro-class explosion occurred.

## Composition / Inheritance

- Unchanged. No inheritance introduced or removed.

## Testability

- Improved without production pollution: R-3 made the eviction policy testable in isolation (state-based assertions, no mocks of the policy itself). The one Mock used simulates a *hostile environment*, not an internal collaborator.

## Legacy Modernization

- None attempted in CQ-02; nothing to validate. Legacy areas (`main.py` shim, `tier_2/main.py`) untouched per deferral decisions.

## Architecture Boundary Validation

**This section contains the phase's critical finding.**

- **Negative test #1 (pre-fix):** injected `from incidents.models import Incident` into `security/middleware.py` → rule test **passed** (vacuous). 
- **Root cause:** `_module_imports`' `visit_imports` iterated `ast.iter_child_nodes(import_node)` expecting `Import`/`ImportFrom` children, but those children are `alias` nodes. Result: `runtime` and `typing_only` were always empty; all four rules passed unconditionally. The tests' green state in CODEQUALITY-02 was meaningless.
- **Fix:** rewrote the detector around a single `ast.walk` pass with explicit `TYPE_CHECKING`-subtree classification (`if TYPE_CHECKING:` and `if typing.TYPE_CHECKING:`), try/except imports as runtime edges, relative imports excluded as intra-package.
- **Self-tests added (6):** the detector must detect a plain import, classify `TYPE_CHECKING` guards as typing-only (both spellings), count try/except imports as runtime, exclude relative imports, and the assertion helper must fail on a known violation. These guarantee the machinery can never silently regress to vacuous-pass again.
- **Negative test #2 (post-fix):** same injection → `AssertionError: security -> feature modules violated by: security\middleware.py imports ['incidents']`. Seam-style injection (`if TYPE_CHECKING:`) correctly still allowed. Production file restored byte-identical (empty `git diff`).
- **Rule calibration:** initial `repositories` rule was over-broad — `in_memory.py`/`sql_repositories.py` legitimately import domain *model* modules (DTOs) and `factory.py` imports `infrastructure` for the SQL session factory (this is the documented persistence seam). Rule scope corrected to behavior modules (`gateway`, `tier_2/3`, `ml`); the models/infrastructure allowances are documented in the test docstrings as deliberate, not oversights.

## Dead Code Validation

- Deleted `.db`/`.bak` artifacts re-verified: no references in code, configs, CI, or scripts; none were git-tracked. `*.db` remains gitignored so durability-test residue cannot re-enter the repo.

## Configuration Validation

- README precedence claims re-verified against `gateway.py:104-115` and corrected one nuance: `ZEROPHISH_ENV` is used by the gateway *exclusively* (no `ENV` fallback there); the `ENV` fallback exists only in the production-persistence check (`repositories/factory.py`, `infrastructure/database.py`). Wording updated to match code exactly. Production-persistence fallback verified present in both modules.

## Dependency Validation

- torch line collapse: effective constraint identical (disjoint markers `;python_version<"3.13"` / `>=3.13` covered all environments; unconditioned pin is equivalent). No other dependency changes.

## Performance Regression

- Not re-measured beyond reasoning: the only runtime-path change is one function call per SSE broadcast on a path measured in milliseconds with a 10s keepalive cycle. No benchmark is warranted (profiling-before-optimization applies equally to perf *claims*). Coverage tooling absent locally, so coverage % was not used as a gate — state-based assertions stand on their own.

## Change Locality

- Representative change: "adjust SSE backpressure policy." Before CQ-02: 2 files touched (both loops) + tests. After: 1 function. Representative change: "tighten extension contract." Before: grep-and-hope across `Dict[str,Any]`. After: one model file. Validated qualitatively; repo is too young (189 commits, 2 contributors) for meaningful churn statistics.

## Hotspot Results

- No incident history exists. Git-log hotspot check not performed (single-contributor history limits signal). The audit's hotspot identification (gateway.py) remains valid and its remediation remains deferred for cause.

## Code Review Impact

- The vacuous-test finding demonstrates the review-process value this phase adds: *negative testing of test infrastructure* should be a review checklist item for any new enforcement mechanism. Captured in this report as a practice recommendation.

## Technical Debt Reduction

| Debt | Before | After |
|---|---|---|
| F-05 untyped contract | contract by convention | named model + 9 pinned cases; interest now ~zero |
| F-11 unenforced boundaries | rules unenforced | rules enforced **and proven enforceable** (post-fix); regression-protected by self-tests |
| F-02a SSE duplication | 2 loops | 1 function; drift impossible without visible test failure |
| F-07/F-09/F-10/F-13 | see CQ-02 | unchanged, remain retired |

## Debt Regression Protection

- Architecture rules: enforced in CI via existing pytest job + self-tested detector.
- Contract: pinned by characterization suite.
- Hygiene: `*.db` gitignore pattern (pre-existing) verified effective.

## Metric-Gaming Check

- The vacuous R-5 tests were, in effect, accidental metric-gaming: "architecture tests: 4 passing" without enforcement value. This phase rejects that result and replaces it with proven enforcement. No other change was found that improves a metric while worsening maintainability: no function splits, no wrappers, no warning suppressions, no coverage exclusions.

## Readability Review

- `Tier1ReportPayload` and `_broadcast_to_subscribers` carry why-docstrings; a reader can explain both in one pass. The rewritten detector is ~40 lines with a named helper per concept (`_is_type_checking_if`, `_imported_top_level_modules`) and a module docstring recording the failure history — deliberate preservation of the lesson.

## Documentation / Comments

- README env-precedence table corrected to match code exactly (verified line-by-line against `gateway.py` and `factory.py`).
- `test_architecture_boundaries.py` docstring now records the vacuous-pass incident and the fix rationale.

## Observability

- No changes; SSE metrics behavior verified identical (side-effect suite).

## Refactoring Disposition

| Area | Before | Change | After | Behavioral Regression | Complexity | Coupling | Testability | Decision |
|---|---|---|---|---|---|---|---|---|
| R-1 hygiene artifacts | stray files on disk | deleted | clean | None | — | — | — | **KEEP** |
| R-2 README corrections | false claims | corrected | matches code | None (docs) | — | — | — | **KEEP** (wording tightened in CQ-03) |
| R-3 SSE helper | 2 duplicated loops | extracted | 1 owner | None (6 tests) | ↓ slightly | ↓ | ↑ | **KEEP** |
| R-4 report model | `Dict[str,Any]` | typed, permissive | named contract | 1 intentional narrowing (documented+tested) | +1 model | = runtime | ↑ | **KEEP** |
| R-5 architecture tests | — | added | **vacuous → fixed & proven** | Test defect, not behavior | +detector | — | ↑↑ | **TUNE → KEEP** (was REVERT-candidate; fixed instead because the *rules* are right and now validated) |
| R-6 torch lines | duplicate markers | collapsed | equivalent | None | — | — | — | **KEEP** |

## Remaining Maintainability Risks

1. `layers_completed` 422 narrowing is the only accepted behavior delta — if any *existing deployed* extension sends out-of-range values, those reports will fail. Mitigation: extension source (`tier1.js`) is in-repo and emits only known values; risk assessed low but flagged for the extension release process.
2. The AST detector does not execute code — dynamically constructed imports (`importlib.import_module("gateway")`) would evade it. Accepted: no such usage exists in-repo (verified by grep); noted as a known limit.
3. Coverage tooling is configured in `pyproject.toml` but pytest-cov is not installed in the local venv (CI installs it separately) — local coverage gating is therefore not reproducible as configured. Minor environment drift worth an owner.

## Unverified Assumptions

- Assumed no external (out-of-repo) consumers post arbitrary `layers_completed` values; verified only against the in-repo extension and test suite.
- Assumed CI installs pytest-cov (workflow shown installing it) — CI behavior not executed locally in this phase.

## Files Changed

- `Backend/tests/test_architecture_boundaries.py` — rewritten detector + 6 self-tests + 4 rules (the CQ-03 defect fix)
- `Backend/tests/test_sse_broadcast_validation.py` — new (6 side-effect characterization tests)
- `Backend/tests/test_tier1_report_contract.py` — new (9 contract characterization tests)
- `README.md` — env-precedence wording corrected to match code
- `docs/CODEQUALITY-03-VALIDATION.md` — this report
- Production code: **zero changes** in this phase (`security/middleware.py` restored byte-identical after negative testing; `git diff` empty)
