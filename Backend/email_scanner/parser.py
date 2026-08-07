"""
Enhanced Email Scanner — .eml parsing, SPF/DKIM/DMARC validation,
attachment triage, recursive link extraction.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import io
import re
import socket
import urllib.parse
from email import message_from_bytes
from email.message import EmailMessage, Message
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic result models
# ═══════════════════════════════════════════════════════════════════════════════

class HeaderAuthResult(BaseModel):
    spf: str          # "pass" | "fail" | "softfail" | "neutral" | "unknown"
    dkim: str         # "pass" | "fail" | "none" | "unknown"
    dmarc: str        # "pass" | "fail" | "none" | "unknown"
    spf_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dmarc_policy: Optional[str] = None
    score_penalty: int = 0   # 0–40 added to Tier 2 score


class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_executable: bool
    is_archive: bool
    is_document: bool
    risk_level: str   # "safe" | "suspicious" | "dangerous"
    risk_reason: Optional[str] = None


class EmlParseResult(BaseModel):
    subject: str
    sender: str
    recipients: List[str]
    body_text: str
    body_html: str
    links: List[str]         # all links extracted (incl. from HTML)
    attachments: List[AttachmentInfo]
    headers_raw: Dict[str, str]
    auth_results: HeaderAuthResult
    message_id: Optional[str] = None
    date: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# DANGEROUS file extensions
# ═══════════════════════════════════════════════════════════════════════════════

_EXECUTABLE_EXTS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
    ".scr", ".pif", ".com", ".msi", ".dll", ".hta", ".jar",
}
_ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".cab"}
_DOCUMENT_EXTS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt"}
_LINK_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
_HTML_LINK_RE = re.compile(r'href=["\']?(https?://[^"\'\s>]+)', re.IGNORECASE)
_SHORTENERS_RE = re.compile(
    r"https?://(bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|is\.gd|buff\.ly)/",
    re.IGNORECASE,
)
_RCV_SPF_RE = re.compile(r"(\w+)")
_DKIM_SEL_RE = re.compile(r"header\.s=(\S+)")
_DMARC_POL_RE = re.compile(r"dmarc=\w+\s+.*?policy\.published=(\w+)")


class EmlParser:
    """Parse raw .eml bytes into a structured result."""

    @staticmethod
    def parse(raw: bytes) -> EmlParseResult:
        msg: Message = message_from_bytes(raw, policy=email.policy.default)

        subject   = str(msg.get("Subject",""))
        sender    = str(msg.get("From",""))
        recipients = [str(r) for r in (msg.get_all("To") or [])]
        message_id = str(msg.get("Message-ID","")) or None
        date       = str(msg.get("Date","")) or None

        body_text, body_html, attachments = EmlParser._walk_parts(msg)
        links = EmlParser._extract_links(body_text, body_html)
        headers_raw = {k: str(v) for k, v in msg.items()}
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
        body_text = ""
        body_html = ""
        attachments: List[AttachmentInfo] = []

        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition",""))
            filename = part.get_filename()

            if filename:
                payload = part.get_payload(decode=True) or b""
                attachments.append(EmlParser._analyse_attachment(filename, ct, payload))
                continue

            if ct == "text/plain" and not body_text:
                try:
                    body_text = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    pass
            elif ct == "text/html" and not body_html:
                try:
                    body_html = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    pass

        return body_text, body_html, attachments

    @staticmethod
    def _analyse_attachment(filename: str, content_type: str, data: bytes) -> AttachmentInfo:
        import os
        import re
        
        # Check for RTLO (Right-to-Left Override) or bidirectional control chars in filename
        has_rtlo = bool(re.search(r"[\u202e\u202d\u200e\u200f\u202a\u202b\u202c]", filename))
        clean_filename = re.sub(r"[\u202e\u202d\u200e\u200f\u202a\u202b\u202c]", "", filename)
        
        ext = os.path.splitext(clean_filename.lower())[1]
        sha = hashlib.sha256(data).hexdigest()
        is_exec = ext in _EXECUTABLE_EXTS
        is_arch = ext in _ARCHIVE_EXTS
        is_doc  = ext in _DOCUMENT_EXTS

        # MIME vs Extension mismatch check
        mime_lower = (content_type or "").lower()
        is_exec_mime = any(m in mime_lower for m in ("application/x-msdownload", "application/x-executable", "application/x-dosexec", "application/x-sharedlib"))
        
        risk, reason = "safe", None

        if has_rtlo:
            risk, reason = "dangerous", "Filename contains RTLO (Right-to-Left Override) spoofing characters"
        elif is_exec or is_exec_mime:
            risk, reason = "dangerous", f"Executable payload detected (ext: {ext}, mime: {mime_lower})"
        elif is_arch:
            risk, reason = "suspicious", "Archive may contain malicious files"
        elif is_doc:
            risk, reason = "suspicious", "Office/PDF documents may contain macros or exploits"

        return AttachmentInfo(
            filename=filename,
            content_type=content_type,
            size_bytes=len(data),
            sha256=sha,
            is_executable=is_exec or is_exec_mime or has_rtlo,
            is_archive=is_arch,
            is_document=is_doc,
            risk_level=risk,
            risk_reason=reason,
        )

    @staticmethod
    def _extract_links(text: str, html: str) -> List[str]:
        """Extract deduplicated links from both plain-text and HTML bodies."""
        seen: set = set()
        links: List[str] = []

        # From plain text
        for m in _LINK_RE.finditer(text):
            u = m.group(0).rstrip(".,;)>\"'")
            if u not in seen:
                seen.add(u)
                links.append(u)

        # From HTML — also handle href= attributes
        for m in _HTML_LINK_RE.finditer(html):
            u = m.group(1).rstrip(".,;)>\"'")
            if u not in seen:
                seen.add(u)
                links.append(u)

        # Recursive redirect detection — un-wrap known URL shorteners
        expanded: List[str] = []
        for link in links:
            expanded.append(link)
            if _SHORTENERS_RE.match(link):
                expanded.append(f"[SHORTENER:{link}]")  # Flag for scoring

        return expanded[:200]  # cap

    @staticmethod
    def _parse_auth_results(msg: Message) -> HeaderAuthResult:
        """
        Parse the Authentication-Results header for SPF/DKIM/DMARC verdicts.
        Falls back to Received-SPF for SPF if needed.
        """
        ar = str(msg.get("Authentication-Results", "")).lower()
        rcv_spf = str(msg.get("Received-SPF", "")).lower()

        def _extract(header: str, proto: str) -> str:
            pat = re.search(rf"{proto}=(\w+)", header)
            return pat.group(1) if pat else "unknown"

        spf   = _extract(ar, "spf") if "spf=" in ar else _extract(rcv_spf, "")
        if spf == "unknown" and rcv_spf:
            m = _RCV_SPF_RE.match(rcv_spf)
            spf = m.group(1) if m else "unknown"

        dkim  = _extract(ar, "dkim")
        dmarc = _extract(ar, "dmarc")

        # DKIM selector
        sel_m = _DKIM_SEL_RE.search(ar)
        dkim_sel = sel_m.group(1) if sel_m else None

        # DMARC policy
        pol_m = _DMARC_POL_RE.search(ar)
        dmarc_pol = pol_m.group(1) if pol_m else None

        # Penalty scoring
        penalty = 0
        if spf in ("fail", "softfail"):   penalty += 15
        if dkim in ("fail", "none"):      penalty += 10
        if dmarc in ("fail", "none"):     penalty += 15

        return HeaderAuthResult(
            spf=spf, dkim=dkim, dmarc=dmarc,
            spf_domain=None, dkim_selector=dkim_sel,
            dmarc_policy=dmarc_pol, score_penalty=penalty,
        )
