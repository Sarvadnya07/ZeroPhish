"""
ZeroPhish Tier 1: Authoritative Server-Side Heuristic Engine.

Executes deterministic, low-latency (<5ms) heuristic evaluation across:
1. Keyword & phrasing triggers (urgency, credential harvesting, financial fraud)
2. Sender analysis (display name vs domain spoofing, punycode, non-ASCII homoglyphs, allowlist)
3. Link & URL analysis (IP hostnames, punycode, homoglyphs, suspicious TLDs, URL shorteners, brand mismatches)
4. Domain relationships & false-positive mitigation

The server-side Tier 1 engine is authoritative: client-reported Tier 1 signals
are advisory and cannot suppress or downgrade a server-verified risk finding.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------- Keyword & Heuristic Rules ----------
KEYWORD_RULES: List[Dict[str, Any]] = [
    {"pattern": re.compile(r"\burgent\b", re.IGNORECASE), "points": 10, "kind": "urgency"},
    {"pattern": re.compile(r"\baction\s+required\b", re.IGNORECASE), "points": 12, "kind": "urgency"},
    {"pattern": re.compile(r"\bverify\b", re.IGNORECASE), "points": 10, "kind": "urgency"},
    {"pattern": re.compile(r"\bsuspend(ed)?\b", re.IGNORECASE), "points": 12, "kind": "urgency"},
    {"pattern": re.compile(r"\b(account|mailbox)\s+(locked|disabled|limited)\b", re.IGNORECASE), "points": 14, "kind": "urgency"},
    {"pattern": re.compile(r"\bpassword\s+reset\b", re.IGNORECASE), "points": 14, "kind": "credential"},
    {"pattern": re.compile(r"\bpassword(s)?\b", re.IGNORECASE), "points": 12, "kind": "credential"},
    {"pattern": re.compile(r"\bcredential(s)?\b", re.IGNORECASE), "points": 14, "kind": "credential"},
    {"pattern": re.compile(r"\bsign\s*in\b", re.IGNORECASE), "points": 8, "kind": "credential"},
    {"pattern": re.compile(r"\blog(in)?\b", re.IGNORECASE), "points": 8, "kind": "credential"},
    {"pattern": re.compile(r"\bsecurity\s+alert\b", re.IGNORECASE), "points": 12, "kind": "urgency"},
    {"pattern": re.compile(r"\bunauthorized\b", re.IGNORECASE), "points": 10, "kind": "urgency"},
    {"pattern": re.compile(r"\bwire\b|\bbank\s+transfer\b", re.IGNORECASE), "points": 16, "kind": "financial"},
    {"pattern": re.compile(r"\bgift\s*card\b", re.IGNORECASE), "points": 18, "kind": "financial"},
    {"pattern": re.compile(r"\bpay(ment)?\b|\binvoice\b", re.IGNORECASE), "points": 10, "kind": "financial"},
]

TRUSTED_BRANDS: List[str] = [
    "google.com",
    "gmail.com",
    "microsoft.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
]

SENDER_DOMAIN_ALLOWLIST: Set[str] = set(TRUSTED_BRANDS)

# Known-good relationships (e.g. gmail.com is Google; youtube.com is Google).
KNOWN_RELATIONSHIPS: Dict[str, Set[str]] = {
    "gmail.com": {"google.com", "youtube.com"},
    "google.com": {"gmail.com", "youtube.com"},
    "youtube.com": {"google.com", "gmail.com"},
    "microsoft.com": {"outlook.com", "office.com", "live.com", "onedrive.com"},
    "outlook.com": {"microsoft.com", "office.com", "live.com", "onedrive.com"},
    "apple.com": {"icloud.com"},
    "icloud.com": {"apple.com"},
    "amazon.com": {"amazonaws.com"},
    "amazonaws.com": {"amazon.com"},
}

BRAND_SPOOF_RULES: List[Dict[str, Any]] = [
    {
        "keywords": ["google", "gmail"],
        "domains": ["google.com", "gmail.com"],
    },
    {
        "keywords": ["microsoft", "outlook", "office", "onedrive"],
        "domains": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    },
    {
        "keywords": ["paypal"],
        "domains": ["paypal.com"],
    },
    {
        "keywords": ["apple", "icloud"],
        "domains": ["apple.com", "icloud.com"],
    },
    {
        "keywords": ["amazon", "aws"],
        "domains": ["amazon.com", "amazonaws.com"],
    },
]

URL_SHORTENERS: Set[str] = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}

SUSPICIOUS_TLDS: Set[str] = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "stream",
    "gq",
    "tk",
    "ml",
    "ga",
    "cf",
}

MULTIPART_PUBLIC_SUFFIXES: Set[str] = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
}


# ---------- Helper Functions ----------
def clamp_score(score: float) -> int:
    """Clamp score strictly between 0 and 100."""
    return max(0, min(100, int(round(score))))


def normalize_domain(hostname: Optional[str]) -> str:
    """Normalize hostname to lowercase stripped string without leading www or trailing dots."""
    if not hostname:
        return ""
    h = hostname.strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def base_domain(hostname: Optional[str]) -> str:
    """Extract registrable base domain using basic public suffix rules."""
    host = normalize_domain(hostname)
    if not host:
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in MULTIPART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return last3
    return last2


def extract_domain_tld(domain: str) -> str:
    """Extract the top-level domain suffix."""
    parts = domain.split(".")
    return parts[-1] if len(parts) >= 2 else ""


def is_ip_hostname(hostname: str) -> bool:
    """Return True if hostname is a valid IPv4 or IPv6 address (dotted, numeric integer, or hex)."""
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass

    # Support alternate IP representations (decimal integers, hex, octal)
    try:
        socket.inet_aton(clean)
        if any(c.isdigit() for c in clean) or clean.startswith("0x"):
            return True
    except (OSError, ValueError):
        pass

    return False


def contains_non_ascii(text: str) -> bool:
    """Check if string contains any non-ASCII characters."""
    try:
        text.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def are_related_domains(a: str, b: str) -> bool:
    """Check if domains share base domain or belong to known entity mappings."""
    da = base_domain(a)
    db = base_domain(b)
    if not da or not db:
        return False
    if da == db:
        return True
    if da in KNOWN_RELATIONSHIPS and db in KNOWN_RELATIONSHIPS[da]:
        return True
    if db in KNOWN_RELATIONSHIPS and da in KNOWN_RELATIONSHIPS[db]:
        return True
    return False


def extract_email_address_and_name(sender_raw: Optional[str]) -> Tuple[str, str]:
    """Parse raw sender string into (email_address, display_name)."""
    if not sender_raw:
        return "", ""
    s = str(sender_raw).strip()
    angle_match = re.search(r"^([^<]*)<([^>]+)>", s)
    if angle_match:
        name = angle_match.group(1).strip().strip('"').strip("'")
        email = angle_match.group(2).strip()
        return email, name
    plain_match = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", s, re.IGNORECASE)
    if plain_match:
        return plain_match.group(0).strip(), ""
    return s, ""


def email_domain(email: str) -> str:
    """Extract normalized domain from email address."""
    at = email.rfind("@")
    if at == -1:
        return ""
    return normalize_domain(email[at + 1 :])


def sanitize_client_evidence(evidence: Optional[List[Any]]) -> List[str]:
    """
    Sanitize untrusted client-supplied evidence strings against HTML tags,
    control characters, and excessive length. Tag with [Client Advisory].
    """
    if not evidence:
        return []
    sanitized: List[str] = []
    for item in evidence[:50]:
        if item is None:
            continue
        text = str(item).strip()
        # Remove null bytes, CRLF, and unprintable control characters
        text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
        # Strip potential HTML/script markup
        text = re.sub(r"<[^>]*>", "", text).strip()
        if text:
            sanitized.append(f"[Client Advisory] {text[:120]}")
    return sanitized


def classify_tier1_category(score: int, evidence_checks: Set[str], evidence_kinds: Set[str]) -> str:
    """Determine category: 'phishing', 'spam', or 'safe'."""
    strong_indicators = {
        "brand_mismatch",
        "homograph",
        "punycode",
        "sender_spoof",
        "ip_url",
        "sender_homograph",
        "sender_punycode",
    }
    if evidence_checks.intersection(strong_indicators) or "credential" in evidence_kinds or score >= 50:
        return "phishing"
    if score >= 20:
        return "spam"
    return "safe"


# Unicode lookalike transliteration map for homoglyphic evasion resistance
CYRILLIC_LOOKALIKES = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "і": "i", "ј": "j", "у": "y", "х": "x",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M", "О": "O",
    "Р": "P", "Т": "T", "Х": "X", "Ү": "Y",
})
ZERO_WIDTH_AND_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\xad]")


# ---------- Heuristic Scoring Functions ----------
def score_text_keywords(text: str, evidence: List[str]) -> Tuple[int, Set[str]]:
    """Score text against urgency, credential, and financial keyword regexes with deobfuscation."""
    points = 0
    kinds = set()
    if not text:
        return 0, kinds

    # Normalize Unicode (NFKC) and strip zero-width / invisible formatting characters
    norm_text = unicodedata.normalize("NFKC", text)
    clean_text = ZERO_WIDTH_AND_INVISIBLE_RE.sub("", norm_text)
    deconfused_text = clean_text.translate(CYRILLIC_LOOKALIKES)

    has_invisible = bool(ZERO_WIDTH_AND_INVISIBLE_RE.search(text))
    has_confusables = clean_text != deconfused_text
    if has_invisible or has_confusables:
        points += 8
        kinds.add("obfuscation")
        evidence.append("Obfuscation detected: zero-width or homoglyphic characters in text (+8 pts)")

    for rule in KEYWORD_RULES:
        if rule["pattern"].search(text) or rule["pattern"].search(deconfused_text):
            pts = rule["points"]
            points += pts
            kinds.add(rule["kind"])
            evidence.append(f"Keyword match [{rule['kind']}]: '{rule['pattern'].pattern}' (+{pts} pts)")
    return points, kinds


def score_sender(
    sender_raw: Optional[str],
    evidence: List[str],
) -> Tuple[int, Set[str]]:
    """Score sender characteristics (display name, punycode, homoglyphs, spoofing)."""
    points = 0
    checks = set()
    email, name = extract_email_address_and_name(sender_raw)
    domain = email_domain(email)
    name_lower = name.lower()

    if not email or not domain or domain.lower() in ("unknown", "localhost"):
        points += 4
        checks.add("sender_unavailable")
        evidence.append("Sender address unavailable or invalid (+4 pts)")
        return points, checks

    if "xn--" in domain:
        points += 12
        checks.add("sender_punycode")
        evidence.append(f"Sender domain uses punycode: {domain} (+12 pts)")

    if contains_non_ascii(domain):
        points += 16
        checks.add("sender_homograph")
        evidence.append(f"Sender domain contains non-ASCII characters: {domain} (+16 pts)")

    is_allowlisted = any(domain == d or domain.endswith(f".{d}") for d in SENDER_DOMAIN_ALLOWLIST)
    if is_allowlisted:
        points -= 20
        checks.add("sender_allowlist")
        evidence.append(f"Sender domain is in verified allowlist: {domain} (-20 pts)")

    # Check for brand spoofing in display name
    for rule in BRAND_SPOOF_RULES:
        claims_brand = any(k in name_lower for k in rule["keywords"])
        if claims_brand:
            matches_brand_domain = any(domain == d or domain.endswith(f".{d}") for d in rule["domains"])
            if not matches_brand_domain:
                points += 18
                checks.add("sender_spoof")
                evidence.append(
                    f"Display name suggests {rule['domains'][0]} but actual sender domain is {domain} (+18 pts)"
                )
            break

    return points, checks


def score_links(
    links: List[str],
    evidence: List[str],
) -> Tuple[int, Set[str], List[str]]:
    """Score URLs found in email (IP, punycode, homoglyphs, shorteners, suspicious TLDs)."""
    points = 0
    checks = set()
    link_bases = []

    for link_str in links or []:
        if not link_str or not isinstance(link_str, str):
            continue
        link_str = link_str.strip()
        if not link_str:
            continue

        try:
            parsed = urlparse(link_str)
        except Exception:
            points += 5
            evidence.append(f"Malformed link URL: {link_str[:60]} (+5 pts)")
            continue

        hostname = normalize_domain(parsed.hostname)
        if not hostname:
            continue

        l_base = base_domain(hostname)
        if l_base:
            link_bases.append(l_base)

        tld = extract_domain_tld(hostname)

        if "xn--" in hostname:
            points += 18
            checks.add("punycode")
            evidence.append(f"Punycode domain in link: {hostname} (+18 pts)")

        if contains_non_ascii(hostname):
            points += 22
            checks.add("homograph")
            evidence.append(f"Non-ASCII homoglyph in link: {hostname} (+22 pts)")

        if is_ip_hostname(hostname):
            points += 20
            checks.add("ip_url")
            evidence.append(f"IP-based URL hostname: {hostname} (+20 pts)")

        if hostname in URL_SHORTENERS:
            points += 12
            checks.add("shortener")
            evidence.append(f"URL shortener detected: {hostname} (+12 pts)")

        if tld in SUSPICIOUS_TLDS:
            points += 10
            checks.add("tld")
            evidence.append(f"Suspicious top-level domain: .{tld} (+10 pts)")

        # Check for brand mismatch (e.g. link contains brand name in path/query or subdomain but base domain differs)
        for brand in TRUSTED_BRANDS:
            brand_name = brand.split(".")[0]
            # If path/hostname mentions brand name but base domain is not the brand
            if brand_name in hostname and not are_related_domains(brand, hostname):
                points += 30
                checks.add("brand_mismatch")
                evidence.append(
                    f"Brand mismatch: link references '{brand_name}' but points to external domain '{hostname}' (+30 pts)"
                )
                break

    return points, checks, link_bases


# ---------- Main Analysis Data Structure & Entrypoint ----------
@dataclass
class ServerTier1Result:
    """Authoritative server-side Tier 1 analysis result."""

    score: int
    status: str  # "Clean" or "Suspicious"
    category: str  # "safe", "spam", "phishing", or "error"
    evidence: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    degraded: bool = False


def analyze_tier1_server(
    sender: Optional[str] = None,
    body: Optional[str] = None,
    links: Optional[List[str]] = None,
    subject: Optional[str] = None,
) -> ServerTier1Result:
    """
    Execute authoritative server-side Tier 1 heuristics on email parameters.

    Never fails closed to SAFE on error; returns a fail-safe degraded SUSPICIOUS
    status if an unhandled exception occurs.
    """
    t0 = time.perf_counter()
    evidence: List[str] = []
    checks: Set[str] = set()
    kinds: Set[str] = set()

    try:
        body_text = (body or "").strip()
        subject_text = (subject or "").strip()
        full_text = f"{subject_text}\n{body_text}".strip()
        links_list = links or []

        total_points = 0

        # 1. Keywords & Phrasing
        kw_pts, kw_kinds = score_text_keywords(full_text, evidence)
        total_points += kw_pts
        kinds.update(kw_kinds)

        # 2. Sender Analysis
        sender_pts, sender_checks = score_sender(sender, evidence)
        total_points += sender_pts
        checks.update(sender_checks)

        # 3. Links Analysis
        link_pts, link_checks, link_bases = score_links(links_list, evidence)
        total_points += link_pts
        checks.update(link_checks)

        final_score = clamp_score(total_points)

        # 4. False-Positive Mitigation:
        # If score is elevated (e.g. lots of urgency keywords) but every link belongs to the
        # sender's parent organization, NO deceptive/suspicious checks were triggered,
        # and NO credential harvesting keywords are present.
        sender_email, _ = extract_email_address_and_name(sender)
        sender_domain_name = email_domain(sender_email)
        sender_b = base_domain(sender_domain_name)
        deceptive_indicators = {
            "sender_spoof",
            "brand_mismatch",
            "homograph",
            "punycode",
            "sender_homograph",
            "sender_punycode",
            "ip_url",
            "shortener",
            "tld",
        }

        if (
            final_score > 25
            and link_bases
            and sender_b
            and "credential" not in kinds
            and not checks.intersection(deceptive_indicators)
        ):
            all_links_related = all(are_related_domains(sender_b, lb) for lb in link_bases)
            if all_links_related:
                reduced = 9
                evidence.append(
                    f"False-positive mitigation applied: all {len(link_bases)} links correlate with sender org '{sender_b}'"
                )
                final_score = reduced

        category = classify_tier1_category(final_score, checks, kinds)
        status = "Suspicious" if final_score >= 20 else "Clean"
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        return ServerTier1Result(
            score=final_score,
            status=status,
            category=category,
            evidence=evidence,
            execution_time_ms=elapsed_ms,
            degraded=False,
        )

    except Exception as exc:
        logger.error("Authoritative Tier 1 server-side analysis failed: %s", exc, exc_info=True)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        # Fail-closed / degraded: NEVER default to 0 / SAFE on exception
        return ServerTier1Result(
            score=50,
            status="Suspicious",
            category="error",
            evidence=[f"Tier 1 server-side analysis degraded due to internal error: {type(exc).__name__}"],
            execution_time_ms=elapsed_ms,
            degraded=True,
        )
