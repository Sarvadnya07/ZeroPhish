"""
Deterministic URL Normalization and Safe Redaction Module.
Maintains three distinct URL views: Original, Dedupe Canonical, and Model Input.
Supports configurable credential/token redaction for data-retention privacy.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Set, Tuple

TRACKING_PARAMS: Set[str] = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "ref",
    "source",
}

SENSITIVE_PARAMS: Set[str] = {
    "token",
    "access_token",
    "auth_token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "jwt",
    "session",
    "sid",
    "key",
}

TWO_LEVEL_TLDS: Set[str] = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "com.br",
    "gov.br",
    "co.jp",
    "ne.jp",
    "com.cn",
    "net.cn",
    "co.in",
    "net.in",
    "gov.in",
}


class URLNormalizer:
    """Multi-view deterministic URL normalizer and privacy filter."""

    @classmethod
    def extract_hostname(cls, url: str) -> str:
        try:
            parsed = urllib.parse.urlparse(url)
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    @classmethod
    def extract_tld(cls, host: str) -> str:
        if not host:
            return ""
        parts = host.lower().split(".")
        if len(parts) < 2:
            return ""
        possible_tld = ".".join(parts[-2:])
        if possible_tld in TWO_LEVEL_TLDS:
            return possible_tld
        return parts[-1]

    @classmethod
    def extract_registered_domain(cls, host: str) -> str:
        if not host:
            return ""
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()
        possible_tld = ".".join(parts[-2:])
        if possible_tld in TWO_LEVEL_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @classmethod
    def to_model_input_form(cls, url: str, max_length: int = 2048) -> str:
        """
        Clean whitespace and bounded length while strictly preserving security signals:
        Punycode, IDN homoglyphs, port, userinfo @, hex encoding, and full path.
        """
        cleaned = re.sub(r"[\r\n\t\x00-\x1f\x7f]", "", url.strip())
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
            cleaned = "http://" + cleaned
        return cleaned[:max_length]

    @classmethod
    def to_dedupe_canonical_form(cls, url: str) -> str:
        """
        Aggressive canonicalization for duplicate detection only:
        lowercase scheme/host, stripped tracking parameters, sorted query params, stripped fragments.
        """
        try:
            cleaned = cls.to_model_input_form(url)
            parsed = urllib.parse.urlparse(cleaned)
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            filtered = [(k.lower(), v) for k, v in query_tuples if k.lower() not in TRACKING_PARAMS]
            filtered.sort(key=lambda x: x[0])
            sorted_query = urllib.parse.urlencode(filtered)

            return urllib.parse.urlunparse(
                (
                    parsed.scheme.lower(),
                    (parsed.netloc or "").lower(),
                    parsed.path or "/",
                    "",
                    sorted_query,
                    "",
                )
            )
        except Exception:
            return url.lower().strip()

    @classmethod
    def redact_sensitive_params(cls, url: str) -> str:
        """Redacts sensitive tokens and credentials from query string for privacy-compliant storage/logging."""
        try:
            parsed = urllib.parse.urlparse(url)
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            redacted_tuples = [
                (k, "[REDACTED]" if k.lower() in SENSITIVE_PARAMS else v) for k, v in query_tuples
            ]
            new_query = urllib.parse.urlencode(redacted_tuples)
            return urllib.parse.urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )
        except Exception:
            return url
