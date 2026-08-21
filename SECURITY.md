# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via:
- **GitHub Security Advisories**: Go to the Security tab → Advisories → Report a vulnerability
- **Email**: security@zerophish.local

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Disclosure Policy

After a fix is released, we will publish a security advisory with full details.

## Dependency Security & Upstream Policy

ZeroPhish enforces continuous dependency audits via `pip-audit` in CI/CD and `pnpm audit` for frontend modules.

### Accepted Upstream Exceptions:
- **HuggingFace Transformers (`transformers==4.57.6`)**:
  - **Advisories**: `PYSEC-2025-217`, `PYSEC-2026-2288`, `PYSEC-2026-2289`, `PYSEC-2026-2290` (affecting remote code execution during untrusted model deserialization via PyTorch pickle or CLI utilities).
  - **Compensating Controls**: ZeroPhish restricts model loading strictly to a pinned, hardcoded model repository (`cybersectony/phishing-email-detection-distilbert_v2.1`) using `AutoTokenizer` and `AutoModelForSequenceClassification`. Untrusted user model weights are never loaded; user inputs (email bodies) are truncated and passed purely as tokenized text arrays to forward inference (`torch.no_grad()`). Model upgrading to 5.x will occur once upstream DistilBERT checkpoints release native 5.x safetensors targets.

