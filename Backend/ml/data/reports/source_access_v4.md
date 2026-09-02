# Threat Feed Real-Access Forensic Audit Report

**Verification Timestamp:** 2026-09-02T18:29:53.288675+00:00
**Overall Classification:** `D. ONLY SAMPLE/FIXTURE ACCESS AVAILABLE`

## Source Access Matrix

| Source | Status | Mode | Auth Required | Records | Domains | Bytes | License | Notes |
| :--- | :--- | :--- | :--- | ---: | ---: | ---: | :--- | :--- |
| **Tranco Top 1M** | `SAMPLE_ONLY` | `SAMPLE` | False | 15 | 15 | 0 | MIT License (Approved) | Offline test mode with curated top domains. |
| **OpenPhish Community Feed** | `SAMPLE_ONLY` | `SAMPLE` | False | 10 | 10 | 0 | Open Data / Research Terms | Offline test mode with curated phishing samples. |
| **PhishTank Verified** | `SAMPLE_ONLY` | `SAMPLE` | True | 10 | 10 | 0 | Community API Terms | Offline test mode with curated PhishTank submissions. |
| **Cloud & CDN Assets** | `SAMPLE_ONLY` | `SAMPLE` | False | 10 | 8 | 0 | Public Metadata (Approved) | Manually curated hard-negative samples. Does not represent a live dynamic feed. |
| **ZeroPhish Adversarial Red Team Corpus** | `FIXTURE_ONLY` | `FIXTURE` | False | 10 | 10 | 0 | Proprietary Internal | Synthetic homoglyph, punycode, and port-based evasion test suite. Maintained separately from natural feeds. |

## Blocker & Remediation Table

| Source | Blocker Description | Required Action |
| :--- | :--- | :--- |
| **Cloud & CDN Assets** | No automated bulk feed exists for high-entropy SaaS/CDN URLs | Implement an automated crawler/parser for public IP ranges (e.g. AWS ip-ranges.json, Cloudflare list) |
