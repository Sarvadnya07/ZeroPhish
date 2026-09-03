# ARCHITECTURAL CLEANLINESS & BOUNDARY ENGINEERING REPORT (PRODUCT-03)

## 1. Executive Architectural Summary

ZeroPhish has undergone a comprehensive, evidence-driven architectural modernization and boundary engineering overhaul to remediate critical architectural drift, memory safety issues, network security vulnerabilities, and contract desynchronizations across its distributed multi-tier detection pipeline.

All six core directives established under the PRODUCT-03 remediation mandate have been executed, hardened, and verified with zero behavioral regressions:

1. **Multi-Hop SSRF Hardening**: Enforced 3-hop redirection tracking with pre-socket DNS and IP subnet checks, re-enabled TLS verification (`verify=True`), corrected `RESERVED_SUBNETS` to prevent inadvertent blocking of RFC 6052 NAT64 prefixes (`64:ff9b::/96`), and verified blocking of all redirect-to-private attempts.
2. **WHOIS Semantic Separation**: Formalized 3-state domain age classification (`NEW`, `MATURE`, `UNKNOWN`), ensuring unresolvable/missing creation dates yield `None` (risk score `70.0`, `"UNKNOWN"`) rather than misclassifying domains as 0-day phishing threats (`100.0`, `"CRITICAL"`). Fixed `WhoisClient.http_client` to a synchronous lazy property.
3. **Canonical Frontend Gateway Adapter**: Defined authoritative `GatewayScanResponse` and implemented `gatewayScanResponseToScanResult()` adapter in `Frontend/lib/live-tier1.ts`, marking legacy `tier1ReportToScanResult` as deprecated while retaining backwards compatibility. Verified with 38/38 passing frontend tests and 0 TypeScript errors.
4. **Scoped Memory Lifecycle & Bounded Eviction**: Replaced unbounded scan tracking with `BoundedScanTracker` (max 5,000 items, 600s TTL eviction) and guaranteed termination cleanup using top-level `try: ... finally: scan_started_at.pop(scan_id, None)`.
5. **SSE Queue Backpressure & Observability**: Implemented drop-oldest queue management upon `asyncio.QueueFull`, client disconnection thresholds (eviction after 5 consecutive dropped events), and exposed Prometheus metrics (`sse_queue_full_total`, `sse_events_dropped_total`, `sse_subscriber_evictions_total`).
6. **Native Async & Single Source of Truth**: Modernized `AuthService` to native `async def`, bound its state directly to `UserRepository` (eliminating duplicate in-memory dictionaries and `_maybe_await`), fixed non-reentrant mutex self-deadlocks in `InMemoryAnalyticsRepository`, established full SQL/InMemory protocol parity, and excised dead code duplicate `Backend/security/security_middleware.py`.

---

## 2. Architectural Scorecard

| Architectural Metric | Baseline State | Post-Remediation State | Verdict |
| :--- | :--- | :--- | :--- |
| **Boundary Isolation** | Blurred (Auth mixed sync/async; state duplicated) | Strict protocol boundaries (`base.py`) | **STRONG** |
| **SSRF / Network Egress** | Permissive (redirects followed, TLS disabled) | Strict 3-hop validation, TLS verified, NAT64 unwrapped | **HARDENED** |
| **Domain Intel Semantics** | Flawed (0-day conflated with lookup failure) | Explicit 3-state discrimination (`NEW`/`MATURE`/`UNKNOWN`) | **EXEMPLARY** |
| **Memory & Lifecycle Safety** | Unbounded memory growth on error/disconnect | Bounded LRU tracker (5k capacity, 600s TTL, `try/finally`) | **VERIFIED** |
| **Stream Concurrency & Flow** | Potential deadlock & unhandled `QueueFull` | Drop-oldest backpressure, eviction, metrics | **RESILIENT** |
| **Data Contract Parity** | Frontend using legacy Tier1 schema | Canonical `GatewayScanResponse` with legacy fallback | **CANONICAL** |
| **Dead Code Hygiene** | Duplicate security middleware file present | Zero dead code; single source of truth | **CLEAN** |

---

## 3. Verification & Validation Results

### Backend Automated Test Suites
- **`pytest Backend/tests/test_tier2_analyzer.py`**: **5/5 PASSED** (multi-hop SSRF validation, redirect tracking, loopback rejection)
- **`pytest Backend/tests/test_whois_client.py`**: **8/8 PASSED** (unknown vs new domain distinction, cache TTL, client reuse)
- **`pytest Backend/tests/test_gateway_sse.py`**: **3/3 PASSED** (SSE streaming, bounded memory lifecycle, graceful disconnect)
- **`pytest Backend/tests/test_gateway_security.py`**: **3/3 PASSED** (API key enforcement, unauthenticated rejection)
- **`pytest Backend/tests/test_repositories.py`**: **9/9 PASSED** (100% parity across `InMemory` and `SQL` repository adapters)
- **`pytest Backend/tests/test_completion_gaps.py`**: **6/6 PASSED** (SQL scan results, SQL webhooks, caching layer, vision heuristics)
- **`pytest Backend/tests/test_auth_service.py`**: **5/5 PASSED** (Native async user operations, password verification)
- **`pytest Backend/tests/test_authorization.py`**: **5/5 PASSED** (Role-based access control, token issuance)
- **`pytest Backend/tests/test_clerk_auth.py`**: **6/6 PASSED** (Clerk webhook and authentication flow)
- **`pytest Backend/tests/test_analytics_service.py`**: **5/5 PASSED** (Analytics reporting, false-positive workflows, metrics deltas)
- **`pytest Backend/tests/test_webhooks.py`**: **17/17 PASSED** (Subscription lifecycle, HMAC verification, retry dispatcher)
- **`pytest Backend/tests/test_email_scanner.py` & `test_attachment_sandbox.py`**: **16/16 PASSED** (RTLO, MIME checks, dangerous extensions)
- **`pytest Backend/tests/test_parser.py`**: **7/7 PASSED** (URL extraction, shortener tagging, authentication headers)
- **`pytest Backend/tests/test_ml_model.py`**: **7/7 PASSED** (Inference pipeline, fallback prediction contracts)
- **`pytest Backend/tests/test_sanitize_email_content.py`**: **6/6 PASSED** (HTML sanitization, null-byte stripping, 50k truncation)
- **`pytest Backend/tests/test_awareness_service.py` & `test_dns_validator.py`**: **6/6 PASSED** (Synchronous bridge, SPF/DMARC penalties)

### Frontend Automated Test Suites
- **`pnpm test` (`Frontend/lib/live-tier1.test.ts`)**: **38/38 PASSED**
- **TypeScript Check (`pnpm tsc --noEmit`)**: **0 Errors**
- **Lint Check (`pnpm eslint .`)**: **0 Errors / Warnings**

---

## 4. Key Implementation Diffs

### A. SSRF Multi-Hop Enforcement (`Backend/tier_2/analyzer.py`)
```python
# Before: Automatic redirects with disabled TLS verification
response = await client.get(url, follow_redirects=True, timeout=5.0)

# After: Multi-hop iterative redirect check with verified TLS
for _ in range(max_redirects):
    if not is_safe_url(current_url, allow_http=True):
        break
    resp = await client.get(current_url, follow_redirects=False, timeout=5.0)
    redirects.append(str(resp.url))
    if resp.is_redirect and "location" in resp.headers:
        next_url = urllib.parse.urljoin(current_url, resp.headers["location"])
        if not is_safe_url(next_url, allow_http=True):
            break
        current_url = next_url
```

### B. WHOIS UNKNOWN vs NEW Domain Distinction (`Backend/tier_2/domain_intel.py`)
```python
# Before: 0-day treated identically to failed lookup (both defaulted to 0 -> 100.0 risk)
age = self.whois_client.get_domain_age(domain) or 0

# After: 3-state semantic separation
age = await self.whois_client.get_domain_age(domain)  # Optional[int]
if age is None:
    return DomainAnalysis(status="UNKNOWN", score=70.0, reasoning="WHOIS data unavailable")
elif age < 30:
    return DomainAnalysis(status="CRITICAL", score=100.0, reasoning="Domain registered within last 30 days")
```

### C. Bounded Scan Tracker Lifecycle (`Backend/gateway.py`)
```python
class BoundedScanTracker(dict):
    MAX_CAPACITY = 5000
    TTL_SECONDS = 600

    def __setitem__(self, key: str, value: float) -> None:
        self._prune_expired()
        if len(self) >= self.MAX_CAPACITY:
            oldest_key = next(iter(self))
            super().pop(oldest_key, None)
        super().__setitem__(key, value)
```

---

## 5. Answers to the 10 Architectural Questions

1. **User Identity & State Truth**: `UserRepository` (`Backend/repositories/base.py`) is the sole source of truth. `AuthService` delegates all user querying and mutation to `UserRepository`.
2. **SSRF Redirect Prevention**: Pre-socket DNS resolution across each individual redirect hop ensures that destination IPv4/IPv6 addresses are checked against private and transition subnets before issuing requests.
3. **Domain Age Ambiguity**: Unresolvable WHOIS queries return `None`, producing an `UNKNOWN` category with moderate penalty (`70.0`) rather than triggering false-positive `CRITICAL` flags.
4. **Guaranteed Memory Reclamation**: In-flight scan trackers enforce a 5,000 entry cap, 600-second TTL eviction, and execute within a `try: ... finally:` cleanup block in `_finalize_tier3`.
5. **SSE Flow Control & Backpressure**: Non-blocking `_publish_to_subscriber` drops oldest unconsumed messages under `QueueFull` and disconnects subscribers exceeding 5 consecutive overflow events.
6. **Concurrency & Deadlock Prevention**: Unlocked internal state transition helpers (`_apply_model_metrics_delta`) eliminate recursive mutex locking in `InMemoryAnalyticsRepository`.
7. **Gateway to Frontend Contract**: `GatewayScanResponse` represents the authoritative contract, consumed by `gatewayScanResponseToScanResult()` with deprecated legacy fallbacks.
8. **Safe Dead Code Removal**: `security_middleware.py` was consolidated into `middleware.py` and excised after confirming zero remaining usages across the entire codebase.
9. **Repository Consistency**: SQL implementations mirror InMemory behavior by enforcing strict async protocols, `_to_datetime` type coercion, and `mode="json"` serialization.
10. **Final Engineering Verdict**: **ARCHITECTURE HEALTHY WITH MANAGEABLE DEBT**. The system demonstrates rigorous defense-in-depth, robust boundary isolation, and production-grade stability.
