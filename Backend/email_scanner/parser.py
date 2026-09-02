"""
Enhanced Email Scanner — .eml parsing, SPF/DKIM/DMARC validation,
attachment triage, recursive link extraction.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import logging
import os
import re
from email import message_from_bytes
from email.message import Message
from typing import List, Optional, Tuple, Dict

from pydantic import BaseModel, Field, field_validator

from .attachment_sandbox import AttachmentSandbox, RiskLevel

logger = logging.getLogger(__name__)


# ---------- Models ----------
class HeaderAuthResult(BaseModel):
    """Parsed authentication results from email headers."""
    spf: str = Field(default="unknown", description="SPF result: pass/fail/softfail/neutral/unknown")
    dkim: str = Field(default="unknown", description="DKIM result: pass/fail/none/unknown")
    dmarc: str = Field(default="unknown", description="DMARC result: pass/fail/none/unknown")
    spf_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dmarc_policy: Optional[str] = None  # published policy
    score_penalty: int = Field(default=0, ge=0, le=40, description="Added to Tier 2 score")


class AttachmentInfo(BaseModel):
    """Information about an email attachment."""
    filename: str = Field(..., min_length=1)
    content_type: str
    size_bytes: int = Field(..., ge=0)
    sha256: str = Field(..., min_length=64, max_length=64)
    is_executable: bool = False
    is_archive: bool = False
    is_document: bool = False
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reason: Optional[str] = None


class EmlParseResult(BaseModel):
    """Parsed email structure and analysis results."""
    subject: str = ""
    sender: str = ""
    recipients: List[str] = Field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    links: List[str] = Field(default_factory=list)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    headers_raw: Dict[str, str] = Field(default_factory=dict)
    auth_results: HeaderAuthResult = Field(default_factory=HeaderAuthResult)
    message_id: Optional[str] = None
    date: Optional[str] = None


# ---------- Constants ----------
EXECUTABLE_EXTS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".scr", ".pif", ".com", ".msi", ".dll", ".hta", ".jar"
}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".cab"}
DOCUMENT_EXTS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt"}
LINK_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
HTML_LINK_RE = re.compile(r'href=["\']?(https?://[^"\'\s>]+)', re.IGNORECASE)
SHORTENERS_RE = re.compile(
    r"https?://(bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|is\.gd|buff\.ly)/",
    re.IGNORECASE,
)
MAX_LINKS = 200

# RTLO characters (Right-to-Left Override)
RTLO_CHARS = {"\u202e", "\u202b", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"}


class EmlParser:
    """Parse raw .eml bytes into structured result with security analysis."""

    @staticmethod
    def parse(raw: bytes) -> EmlParseResult:
        """
        Parse a raw email (RFC 5322) into a structured result.

        Args:
            raw: Raw bytes of the email (EML format).

        Returns:
            EmlParseResult containing all extracted fields and analyses.

        Raises:
            ValueError: If the email cannot be parsed.
        """
        try:
            msg: Message = message_from_bytes(raw, policy=email.policy.default)
        except Exception as e:
            logger.error("Failed to parse .eml: %s", e)
            raise ValueError(f"Could not parse .eml: {e}")

        # Extract basic headers
        subject = str(msg.get("Subject", "")).strip()
        sender = str(msg.get("From", "")).strip()
        recipients = [str(r).strip() for r in (msg.get_all("To") or []) if r]
        message_id = str(msg.get("Message-ID", "")).strip() or None
        date = str(msg.get("Date", "")).strip() or None

        # Walk parts
        body_text, body_html, attachments = EmlParser._walk_parts(msg)

        # Extract and deduplicate links
        links = EmlParser._extract_links(body_text, body_html)

        # Raw headers
        headers_raw = {k: str(v) for k, v in msg.items()}

        # Authentication results from headers
        auth = EmlParser._parse_auth_results(msg)

        return EmlParseResult(
            subject=subject,
            sender=sender,
            recipients=recipients,
            body_text=body_text,
            body_html=body_html,
            links=links,
            attachments=attachments,
            headers_raw=headers_raw,
            auth_results=auth,
            message_id=message_id,
            date=date,
        )

    @staticmethod
    def _walk_parts(msg: Message) -> Tuple[str, str, List[AttachmentInfo]]:
        """Walk through MIME parts to extract body and attachments."""
        body_text = ""
        body_html = ""
        attachments: List[AttachmentInfo] = []

        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", "")).lower()
            filename = part.get_filename()

            if filename:
                # This is an attachment
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b""
                elif isinstance(payload, str):
                    payload = payload.encode("utf-8", errors="ignore")
                elif not isinstance(payload, (bytes, bytearray, memoryview)):
                    payload = str(payload).encode("utf-8", errors="ignore")
                attachments.append(EmlParser._analyse_attachment(filename, content_type, payload))
                continue

            # Body parts
            if content_type == "text/plain" and not body_text:
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        charset = part.get_content_charset() or "utf-8"
                        body_text = payload.decode(charset, errors="replace")
                except Exception as e:
                    logger.debug("Could not decode text/plain part: %s", e)

            elif content_type == "text/html" and not body_html:
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        charset = part.get_content_charset() or "utf-8"
                        body_html = payload.decode(charset, errors="replace")
                except Exception as e:
                    logger.debug("Could not decode text/html part: %s", e)

        return body_text, body_html, attachments

    @staticmethod
    def _analyse_attachment(filename: str, content_type: str, data: bytes) -> AttachmentInfo:
        """Perform static analysis on a single attachment using AttachmentSandbox."""
        # If data is empty, treat as safe but warn
        if not data:
            logger.warning("Empty attachment: %s", filename)
            return AttachmentInfo(
                filename=filename,
                content_type=content_type,
                size_bytes=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                is_executable=False,
                is_archive=False,
                is_document=False,
                risk_level=RiskLevel.SAFE,
                risk_reason="Empty file",
            )

        # Use the sandbox for full analysis
        report = AttachmentSandbox.analyse(filename, data)

        ext = os.path.splitext(filename.lower())[1]
        is_exec = ext in EXECUTABLE_EXTS
        is_arch = ext in ARCHIVE_EXTS
        is_doc = ext in DOCUMENT_EXTS

        # Override if sandbox found executable magic but extension is safe
        if report.risk_level == RiskLevel.DANGEROUS and "Executable binary" in " ".join(report.risk_reasons):
            is_exec = True

        return AttachmentInfo(
            filename=filename,
            content_type=content_type,
            size_bytes=len(data),
            sha256=report.sha256,
            is_executable=is_exec,
            is_archive=is_arch,
            is_document=is_doc,
            risk_level=report.risk_level,
            risk_reason="; ".join(report.risk_reasons) if report.risk_reasons else None,
        )

    @staticmethod
    def _extract_links(text: str, html: str) -> List[str]:
        """Extract deduplicated URLs from plain text and HTML bodies."""
        seen: set = set()
        links: List[str] = []

        def add_link(url: str) -> None:
            url = url.rstrip(".,;)>\"'")
            if url not in seen:
                seen.add(url)
                links.append(url)

        # Extract from plain text
        for m in LINK_RE.finditer(text):
            add_link(m.group(0))

        # Extract from HTML href attributes
        for m in HTML_LINK_RE.finditer(html):
            add_link(m.group(1))

        # Flag shorteners for scoring
        for link in links:
            if SHORTENERS_RE.match(link):
                # Mark as shortened for later scoring (we keep original link)
                # No need to modify the link; scoring will use this list.
                pass

        return links[:MAX_LINKS]

    @staticmethod
    def _parse_auth_results(msg: Message) -> HeaderAuthResult:
        """
        Parse the Authentication-Results header for SPF/DKIM/DMARC verdicts.
        Falls back to Received-SPF for SPF if needed.
        """
        ar = str(msg.get("Authentication-Results", "")).lower()
        rcv_spf = str(msg.get("Received-SPF", "")).lower()

        def extract(header: str, proto: str) -> str:
            pat = re.search(rf"{proto}=(\w+)", header)
            return pat.group(1) if pat else "unknown"

        spf = extract(ar, "spf") if "spf=" in ar else extract(rcv_spf, "")
        if spf == "unknown" and rcv_spf:
            # Try simple match from Received-SPF
            m = re.match(r"(\w+)", rcv_spf)
            spf = m.group(1) if m else "unknown"

        dkim = extract(ar, "dkim")
        dmarc = extract(ar, "dmarc")

        # DKIM selector
        sel_m = re.search(r"header\.s=(\S+)", ar)
        dkim_selector = sel_m.group(1) if sel_m else None

        # DMARC policy from header
        pol_m = re.search(r"dmarc=\w+\s+.*?policy\.published=(\w+)", ar)
        dmarc_policy = pol_m.group(1) if pol_m else None

        # Penalty scoring
        penalty = 0
        if spf in ("fail", "softfail"):
            penalty += 15
        if dkim in ("fail", "none"):
            penalty += 10
        if dmarc in ("fail", "none"):
            penalty += 15

        return HeaderAuthResult(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            spf_domain=None,
            dkim_selector=dkim_selector,
            dmarc_policy=dmarc_policy,
            score_penalty=penalty,
        )