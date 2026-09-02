"""
URL Preprocessing & Normalization Pipeline for ML Models.

Safely bounds, cleans, and normalizes URLs while strictly preserving
security-critical features (Punycode, credentials, IPs, encoded characters, ports).
Zero network resolution and zero code execution.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Constants
MAX_URL_LENGTH = 1024
DEFAULT_SCHEME = "http://"
SCHEME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_REGEX = re.compile(r"^\[?[a-fA-F0-9:]+\]?$")


class URLPreprocessor:
    """
    Safe, non‑destructive URL normalizer for ML tokenization.

    All methods are static and side‑effect‑free. No network resolution
    or code execution is performed.
    """

    @staticmethod
    def preprocess(url: str, max_length: int = MAX_URL_LENGTH) -> str:
        """
        Clean and bound URL input for ML inference.

        Preserves all security‑relevant features (Punycode, credentials,
        IP addresses, encoded characters, ports).

        Args:
            url: Raw URL string.
            max_length: Maximum allowed length (to prevent DoS).

        Returns:
            Cleaned, normalized URL string, or empty string on failure.
        """
        if not url or not isinstance(url, str):
            return ""

        # 1. Strip whitespace, control characters, and null bytes
        cleaned = "".join(ch for ch in url.strip() if ch >= " " and ch != "\x7f")
        if not cleaned:
            return ""

        # 2. Bound length
        if len(cleaned) > max_length:
            logger.debug("URL truncated from %d to %d characters", len(cleaned), max_length)
            cleaned = cleaned[:max_length]

        # 3. Add default protocol if missing (allows proper parsing)
        if not SCHEME_REGEX.match(cleaned):
            if cleaned.startswith("//"):
                cleaned = "http:" + cleaned
            else:
                cleaned = DEFAULT_SCHEME + cleaned

        return cleaned

    @staticmethod
    def extract_features(url: str) -> Dict[str, object]:
        """
        Extract structural features from URL for heuristic analysis and explainability.

        Purely lexical extraction; no DNS lookups or network calls.

        Args:
            url: Raw URL string.

        Returns:
            Dictionary with keys: valid, is_ip, is_punycode, has_userinfo,
            has_port, length, domain, path, query.
        """
        norm = URLPreprocessor.preprocess(url)
        if not norm:
            return {
                "valid": False,
                "is_ip": False,
                "is_punycode": False,
                "has_userinfo": False,
                "has_port": False,
                "length": 0,
                "domain": "",
                "path": "",
                "query": "",
            }

        try:
            parsed = urllib.parse.urlparse(norm)
            netloc = parsed.netloc or ""
            domain = parsed.hostname or ""

            # IP address detection
            is_ip = bool(IP_REGEX.match(domain) or IPV6_REGEX.match(domain))

            is_punycode = "xn--" in netloc.lower()
            has_userinfo = "@" in netloc
            has_port = parsed.port is not None

            return {
                "valid": True,
                "is_ip": is_ip,
                "is_punycode": is_punycode,
                "has_userinfo": has_userinfo,
                "has_port": has_port,
                "length": len(norm),
                "domain": domain,
                "path": parsed.path or "",
                "query": parsed.query or "",
            }
        except Exception as e:
            logger.debug("Failed to extract URL features from %s: %s", url[:50], e)
            return {
                "valid": False,
                "is_ip": False,
                "is_punycode": False,
                "has_userinfo": False,
                "has_port": False,
                "length": len(url),
                "domain": "",
                "path": "",
                "query": "",
            }