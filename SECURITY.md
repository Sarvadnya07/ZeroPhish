# Security Policy

ZeroPhish is committed to protecting our users and their data. This document outlines our security practices, reporting procedures, and supported versions.

---

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅ Yes    |

We actively support the latest release. Security patches are backported as needed.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via:

- **GitHub Security Advisories**: Go to the Security tab → Advisories → Report a vulnerability
- **Email**: `security@zerophish.local` (we will respond within 48 hours)

### What to include:
- A clear description of the vulnerability.
- Steps to reproduce (PoC or code snippet if possible).
- Impact assessment (CVSS score if available).
- Your contact information (for follow-up).

### Response Timeline:
- **Acknowledgement**: Within 48 hours.
- **Triage**: Within 5 business days.
- **Fix for critical issues**: Within 7 days.
- **Fix for high/medium issues**: Within 30 days.
- **Low/informational**: Will be prioritised in the next release cycle.

---

## Disclosure Policy

After a fix is released, we will publish a security advisory with full details (CVE, affected versions, mitigation steps). We follow coordinated disclosure and will credit reporters unless they request anonymity.

---

## Secure Development Practices

### Repository Security
- **Branch Protection**: `main` branch requires pull request reviews and passing status checks.
- **Code Owners**: Critical files require approval from security/architecture team.
- **Pre-commit Hooks**: Run `gitleaks` and `semgrep` locally before committing.
- **Secret Scanning**: Enabled via GitHub Secret Scanning and `gitleaks` in CI.
- **Dependency Audits**: `pip-audit` (Python) and `pnpm audit` (frontend) run in CI.

### Static & Dynamic Analysis
- **Semgrep**: Scans for security anti-patterns in Python and JavaScript.
- **CodeQL**: GitHub Action runs on every pull request.
- **DAST**: Staging environment is scanned with OWASP ZAP weekly.

### CI/CD Security Gates
The [`security-gate.ps1`](../scripts/security-gate.ps1) script runs the following checks in CI:

- Repository sanity (git, directory structure).
- Secret verification (Gitleaks on commit history and working tree).
- Environment file hygiene (`.env` not tracked, `.env.example` without real secrets).
- Git ignore rules.
- Backend tests and coverage.
- Frontend build and audit.
- Python and npm dependency security.
- Chromium extension manifest validation.
- Semgrep static analysis.

CI pipelines fail if any mandatory check fails.

---

## Dependency Security & Upstream Policy

ZeroPhish enforces continuous dependency audits via:

- **Python**: `pip-audit` runs on `requirements.txt` in CI.
- **Frontend**: `pnpm audit --audit-level=high` runs on every build.

### Accepted Upstream Exceptions

The following vulnerabilities are accepted with documented compensating controls:

- **HuggingFace Transformers (`transformers==4.57.6`)**:
  - **Advisories**: `PYSEC-2025-217`, `PYSEC-2026-2288`, `PYSEC-2026-2289`, `PYSEC-2026-2290` (affecting remote code execution during untrusted model deserialisation via PyTorch pickle or CLI utilities).
  - **Compensating Controls**: ZeroPhish restricts model loading strictly to a pinned, hardcoded model repository (`cybersectony/phishing-email-detection-distilbert_v2.1`) using `AutoTokenizer` and `AutoModelForSequenceClassification`. Untrusted user model weights are never loaded; user inputs (email bodies) are truncated and passed purely as tokenized text arrays to forward inference (`torch.no_grad()`). Model upgrading to 5.x will occur once upstream DistilBERT checkpoints release native 5.x `safetensors` targets.

- **PyTorch (`torch==2.5.1+cu118`)**:
  - Advisories related to pickle deserialization are mitigated by the same controls (only trusted models loaded).

---

## Environment & Configuration Security

- **`.env` files**: Never committed to Git. A sample `.env.example` with placeholders is provided.
- **Secrets Rotation**: Gemini API keys, Clerk JWT secrets, and Redis passwords are rotated quarterly.
- **Production Access**: Strict IAM policies; only CI/CD and authorised engineers have access.
- **Audit Logging**: All security events are logged to a centralised `security.*` logger (see `security/audit_logger.py`).

---

## Incident Response Plan

In the event of a confirmed security incident:

1. **Contain**: Disable affected services or features.
2. **Investigate**: Review logs, identify root cause, and assess impact.
3. **Notify**: Inform affected users (if personal data was exposed) and internal stakeholders.
4. **Remediate**: Deploy a hotfix and update the security advisory.
5. **Review**: Conduct a post‑mortem and update security controls.

---

## Acknowledgements

We thank the following contributors for responsible disclosure and security improvements:

- (List will be updated when reports are received)

---

## Contact

For security inquiries, please reach out to:

- **Security Team**: `security@zerophish.local`
- **PGP Key**: (optional, if used)

We take security seriously and appreciate your help in keeping ZeroPhish safe.