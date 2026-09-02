"""
Deterministic URL Normalization and Safe Redaction Module.

Maintains three distinct URL views:
- Original (as provided)
- Dedupe Canonical (for duplicate detection, tracking params removed)
- Model Input (for ML inference, preserves security signals)

Supports configurable credential/token redaction for data-retention privacy.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------- Constants ----------
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
    "mc_cid",
    "mc_eid",
    "utm_id",
    "utm_reader",
    "utm_viz_id",
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
    "auth",
    "bearer",
    "x-api-key",
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
    "gov.cn",
    "co.in",
    "net.in",
    "gov.in",
    "org.in",
    "com.sg",
    "net.sg",
    "org.sg",
    "edu.sg",
    "gov.sg",
}

DEFAULT_SCHEME = "http://"
MAX_MODEL_INPUT_LENGTH = 2048
SCHEME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")


class URLNormalizer:
    """
    Multi-view deterministic URL normalizer and privacy filter.

    Provides methods for:
    - Extracting hostname, TLD, and registered domain.
    - Generating model input form (preserves security-relevant signals).
    - Generating deduplication canonical form (aggressive dedupe).
    - Redacting sensitive query parameters for privacy.
    """

    # Class-level configuration (can be overridden)
    tracking_params: Set[str] = TRACKING_PARAMS
    sensitive_params: Set[str] = SENSITIVE_PARAMS
    two_level_tlds: Set[str] = TWO_LEVEL_TLDS
    default_scheme: str = DEFAULT_SCHEME
    max_model_input_length: int = MAX_MODEL_INPUT_LENGTH

    @classmethod
    def extract_hostname(cls, url: str) -> str:
        """
        Extract the hostname (lowercase) from a URL.

        Args:
            url: The URL string.

        Returns:
            Lowercase hostname, or empty string on failure.
        """
        if not url or not isinstance(url, str):
            return ""
        try:
            parsed = urllib.parse.urlparse(url)
            return (parsed.hostname or "").lower()
        except Exception as e:
            logger.debug("Failed to extract hostname from %s: %s", url[:50], e)
            return ""

    @classmethod
    def extract_tld(cls, host: str) -> str:
        """
        Extract the top-level domain (TLD) from a hostname.

        Handles two-level TLDs (e.g., co.uk) via TWO_LEVEL_TLDS set.

        Args:
            host: Hostname (case-insensitive).

        Returns:
            TLD string, or empty string if invalid.
        """
        if not host or not isinstance(host, str):
            return ""
        parts = host.lower().split(".")
        if len(parts) < 2:
            return ""
        possible_tld = ".".join(parts[-2:])
        if possible_tld in cls.two_level_tlds:
            return possible_tld
        return parts[-1]

    @classmethod
    def extract_registered_domain(cls, host: str) -> str:
        """
        Extract the registered (registrable) domain from a hostname.

        Examples:
            "sub.example.co.uk" → "example.co.uk"
            "sub.example.com" → "example.com"

        Args:
            host: Hostname (case-insensitive).

        Returns:
            Registered domain, or empty string if invalid.
        """
        if not host or not isinstance(host, str):
            return ""
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()
        possible_tld = ".".join(parts[-2:])
        if possible_tld in cls.two_level_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @classmethod
    def to_model_input_form(cls, url: str, max_length: Optional[int] = None) -> str:
        """
        Clean URL for model inference input.

        Preserves:
        - Punycode and IDN homoglyphs.
        - Port numbers, userinfo (@).
        - Path and query parameters.
        - Hex/percent encoding.

        Strips:
        - Control characters and whitespace.

        Adds scheme if missing (assumes http://).

        Args:
            url: Raw URL string.
            max_length: Maximum length; defaults to class constant.

        Returns:
            Normalized URL string for model input.
        """
        if not url or not isinstance(url, str):
            logger.warning("to_model_input_form received empty or non-string input")
            return ""

        # Remove control characters and whitespace
        cleaned = re.sub(r"[\r\n\t\x00-\x1f\x7f]", "", url.strip())

        # Add scheme if missing
        if not SCHEME_REGEX.match(cleaned):
            cleaned = cls.default_scheme + cleaned
            logger.debug("Added scheme to URL: %s", cleaned[:50])

        if max_length is None:
            max_length = cls.max_model_input_length

        return cleaned[:max_length]

    @classmethod
    def to_dedupe_canonical_form(cls, url: str) -> str:
        """
        Aggressive canonicalization for duplicate detection only.

        This form is NOT suitable for model input because it strips tracking
        parameters and sorts query parameters, potentially losing semantic signals.

        Transformations:
        - Lowercases scheme and host.
        - Removes tracking parameters (see TRACKING_PARAMS).
        - Sorts remaining query parameters alphabetically.
        - Strips fragment (#).
        - Normalizes path to "/" if empty.

        Args:
            url: Raw URL string.

        Returns:
            Canonicalized URL for deduplication.
        """
        if not url or not isinstance(url, str):
            return ""

        try:
            cleaned = cls.to_model_input_form(url)
            parsed = urllib.parse.urlparse(cleaned)

            # Parse query parameters
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            # Filter out tracking parameters
            filtered = [
                (k.lower(), v)
                for k, v in query_tuples
                if k.lower() not in cls.tracking_params
            ]
            # Sort by key for deterministic ordering
            filtered.sort(key=lambda x: x[0])
            sorted_query = urllib.parse.urlencode(filtered)

            # Normalize path
            path = parsed.path or "/"

            return urllib.parse.urlunparse(
                (
                    parsed.scheme.lower(),
                    (parsed.netloc or "").lower(),
                    path,
                    "",  # params (not used)
                    sorted_query,
                    "",  # fragment stripped
                )
            )
        except Exception as e:
            logger.warning("Failed to canonicalize URL %s: %s", url[:50], e)
            return url.lower().strip()

    @classmethod
    def redact_sensitive_params(cls, url: str) -> str:
        """
        Redact sensitive query parameters for privacy-compliant storage/logging.

        Replaces values of sensitive parameters (see SENSITIVE_PARAMS) with
        the string "[REDACTED]".

        Args:
            url: Raw URL string.

        Returns:
            URL with sensitive values redacted.
        """
        if not url or not isinstance(url, str):
            return url or ""

        try:
            parsed = urllib.parse.urlparse(url)
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            redacted_tuples = [
                (k, "[REDACTED]" if k.lower() in cls.sensitive_params else v)
                for k, v in query_tuples
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
        except Exception as e:
            logger.warning("Failed to redact sensitive params from %s: %s", url[:50], e)
            return url

    @classmethod
    def extract_path(cls, url: str) -> str:
        """
        Extract the path component from a URL.

        Args:
            url: Raw URL string.

        Returns:
            Path string (starts with '/'), or empty string if none.
        """
        if not url or not isinstance(url, str):
            return ""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.path or ""
        except Exception:
            return ""

    @classmethod
    def extract_query_params(cls, url: str) -> Dict[str, List[str]]:
        """
        Extract query parameters as a dictionary of lists (preserving duplicates).

        Args:
            url: Raw URL string.

        Returns:
            Dict mapping parameter names to lists of values.
        """
        if not url or not isinstance(url, str):
            return {}
        try:
            parsed = urllib.parse.urlparse(url)
            return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return {}

    @classmethod
    def is_valid_url(cls, url: str) -> bool:
        """
        Check if a string is a valid URL (has scheme and netloc).

        Args:
            url: String to check.

        Returns:
            True if URL is valid, False otherwise.
        """
        if not url or not isinstance(url, str):
            return False
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False