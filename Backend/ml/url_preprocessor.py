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

# Bounded input length to prevent memory exhaustion / ReDoS
MAX_URL_LENGTH = 1024


class URLPreprocessor:
    """Safe, non-destructive URL normalizer for ML tokenization."""

    @staticmethod
    def preprocess(url: str, max_length: int = MAX_URL_LENGTH) -> str:
        """
        Clean and bound URL input for ML inference.
        Preserves all security features without network resolution.
        """
        if not url or not isinstance(url, str):
            return ""

        # 1. Strip whitespace, control characters, and null bytes
        cleaned = "".join(ch for ch in url.strip() if ch >= " " and ch != "\x7f")
        if not cleaned:
            return ""

        # 2. Bound length
        cleaned = cleaned[:max_length]

        # 3. Add default protocol if missing so parser processes scheme correctly
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            # If protocol-relative or bare domain
            if cleaned.startswith("//"):
                cleaned = "http:" + cleaned
            else:
                cleaned = "http://" + cleaned

        return cleaned

    @staticmethod
    def extract_features(url: str) -> Dict[str, bool | str | int]:
        """
        Extract structural features from URL for heuristic analysis and explainability.
        Purely lexical extraction without DNS lookups.
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
            }

        try:
            parsed = urllib.parse.urlparse(norm)
            netloc = parsed.netloc or ""
            domain = parsed.hostname or ""

            # Check IP address host
            is_ip = bool(
                re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
                or re.match(r"^\[?[a-fA-F0-9:]+\]?$", domain)
            )

            is_punycode = "xn--" in netloc.lower()
            has_userinfo = "@" in netloc
            has_port = bool(parsed.port)

            return {
                "valid": True,
                "is_ip": is_ip,
                "is_punycode": is_punycode,
                "has_userinfo": has_userinfo,
                "has_port": has_port,
                "length": len(norm),
                "domain": domain,
                "path": parsed.path,
                "query": parsed.query,
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
            }
