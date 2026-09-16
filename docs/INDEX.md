# ZeroPhish Documentation Index

Canonical navigation for all project documentation. Organized by reader need
(Diátaxis: how-to / reference / explanation / operations). If a document
contradicts the code, the code wins — please open an issue.

## Start here

| Document | Purpose |
|---|---|
| [README](../README.md) | What ZeroPhish is, quick start, setup, API reference |
| [Quick Reference](QUICK_REFERENCE.md) | Commands, ports, entrypoints cheat sheet (canonical backend: `Backend/gateway.py`) |
| [Testing & Deployment](TESTING_AND_DEPLOYMENT.md) | How to test, build, and deploy |

## Operations (SRE / on-call)

| Document | Purpose |
|---|---|
| [P1 Operations Runbook](ZERO_PHISH_P1_OPERATIONS_RUNBOOK.md) | **Canonical runbook.** Architecture & port reference, incident procedures |
| [Legacy Operations Runbook](OPERATIONS_RUNBOOK.md) | ⚠️ Shorter earlier runbook; retained for history — prefer the P1 runbook |

## Architecture & engineering explanation

| Document | Purpose |
|---|---|
| [Architectural Cleanliness Report](ARCHITECTURAL-CLEANLINESS-REPORT.md) | Dependency model, boundaries, module topology rationale |
| [Behavioral Quality Report](BEHAVIORAL-QUALITY-REPORT.md) | Critical behavioral paths, retry/durability contracts, failure-injection results |

## Quality-engineering history (decision records)

These document the clean-code engineering lifecycle. They are **decision
history**, not operating documentation — consult when changing the contracts
they pinned.

| Phase | Document |
|---|---|
| Audit | [CODEQUALITY-01-AUDIT](CODEQUALITY-01-AUDIT.md) · [Clean-Code Forensic Audit](CLEAN-CODE-FORENSIC-AUDIT.md) |
| Remediation | [CODEQUALITY-02-REMEDIATION](CODEQUALITY-02-REMEDIATION.md) · [Clean-Code Refactoring Report](CLEAN-CODE-REFACTORING-REPORT.md) |
| Validation | [CODEQUALITY-03-VALIDATION](CODEQUALITY-03-VALIDATION.md) |
| Final gate | [Clean-Code Final Quality Gate](CLEAN-CODE-FINAL-QUALITY-GATE.md) |

## P1 reliability milestone (decision history)

| Document | Status |
|---|---|
| [P1 Reliability Report](ZERO_PHISH_P1_RELIABILITY_REPORT.md) | Phase report; see status-correction banner — superseded outcome: CONDITIONALLY VERIFIED |
| [P1 Final Acceptance](ZERO_PHISH_P1_ACCEPTANCE_FINAL.md) | **Authoritative P1 certification** (evidence-hardened; CONDITIONALLY VERIFIED) |
| [P1 Acceptance Sign-Off](ZERO_PHISH_P1_ACCEPTANCE.md) | ⚠️ Superseded preliminary sign-off; retained for history |
| [P1 Evidence Matrix](ZERO_PHISH_P1_EVIDENCE_MATRIX.md) · [P1 Failure Matrix](ZERO_PHISH_P1_FAILURE_MATRIX.md) | Supporting evidence tables |
| [P0 Remediation Report](ZERO_PHISH_P0_REMEDIATION_REPORT.md) · [P0 Final Acceptance](ZERO_PHISH_P0_FINAL_ACCEPTANCE.md) | P0 milestone history |

## Extension & integrations

| Document | Purpose |
|---|---|
| [Extension Fix Guide](EXTENSION_FIX_GUIDE.md) | Troubleshooting the Chrome extension |
| [Extension Reload Instructions](RELOAD_EXTENSION_INSTRUCTIONS.md) | How-to: reload during development |
| [Enhancements Config](ENHANCEMENTS_CONFIG.md) | Optional configuration reference |
| [Gemini Integration Status](GEMINI_INTEGRATION_STATUS.md) | Integration state of the Gemini provider |
