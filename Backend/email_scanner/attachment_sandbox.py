"""
Attachment sandbox — static analysis triage.

This module performs local static analysis of file attachments using:
- Magic byte detection to identify file types
- Shannon entropy to detect packed/encrypted content
- YARA-like signature matching for macros and known patterns
- Heuristic risk scoring based on file type, entropy, and signatures

Full dynamic sandboxing (Cuckoo / ANY.RUN) would require external integrations.
"""

from __future__ import annotations

import hashlib
import math
import os
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator


# ---------- Enums ----------
class RiskLevel(str, Enum):
    """Risk level for an attachment."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


# ---------- Models ----------
class SandboxReport(BaseModel):
    """Static analysis report for an attachment."""
    filename: str = Field(..., min_length=1)
    sha256: str = Field(..., min_length=64, max_length=64)
    size_bytes: int = Field(..., ge=0)
    magic_type: Optional[str] = None
    entropy: float = Field(..., ge=0.0, le=8.0)
    has_macros: bool = False
    signatures_matched: List[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_reasons: List[str] = Field(default_factory=list)
    vt_link: Optional[str] = None  # VirusTotal search URL

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("filename cannot be empty")
        return v


# ---------- Constants ----------
MAGIC_SIGNATURES = {
    b"\x4d\x5a": "Windows PE (EXE/DLL)",
    b"\x7f\x45\x4c\x46": "Linux ELF",
    b"\xca\xfe\xba\xbe": "Java class",
    b"\xd0\xcf\x11\xe0": "MS Office (OLE)",
    b"\x50\x4b\x03\x04": "ZIP archive",
    b"\x52\x61\x72\x21\x1a\x07": "RAR archive",
    b"\x25\x50\x44\x46": "PDF",
    b"\x1f\x8b": "GZIP",
    b"\x89\x50\x4e\x47": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"\x47\x49\x46": "GIF image",
}

MACRO_SIGNATURES = [
    b"VBA",
    b"Word.Basic",
    b"AutoOpen",
    b"Auto_Open",
    b"Document_Open",
    b"Shell(",
    b"WScript",
    b"CreateObject",
    b"GetObject",
]

DANGEROUS_EXTS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".scr", ".pif", ".com", ".msi", ".dll", ".hta", ".jar"}
RTLO_CHARS = {"\u202e", "\u202b", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"}
ENTROPY_HIGH_THRESHOLD = 7.2
ENTROPY_VERY_HIGH_THRESHOLD = 7.8


class AttachmentSandbox:
    """Static analysis engine for file attachments."""

    @staticmethod
    def analyse(filename: str, data: bytes) -> SandboxReport:
        """
        Perform static analysis on the given file data.

        Args:
            filename: Original filename (used for extension and RTLO checks).
            data: Raw file bytes.

        Returns:
            SandboxReport with findings and risk assessment.
        """
        if not data:
            raise ValueError("Cannot analyse empty file data")

        sha = hashlib.sha256(data).hexdigest()
        magic = AttachmentSandbox._detect_magic(data)
        entropy = AttachmentSandbox._shannon_entropy(data)
        has_macros = AttachmentSandbox._scan_macros(data)
        sigs, risk, reasons = AttachmentSandbox._risk_verdict(
            filename, magic, entropy, has_macros, data
        )

        vt_link = f"https://www.virustotal.com/gui/file/{sha}" if sha else None

        return SandboxReport(
            filename=filename,
            sha256=sha,
            size_bytes=len(data),
            magic_type=magic,
            entropy=round(entropy, 3),
            has_macros=has_macros,
            signatures_matched=sigs,
            risk_level=risk,
            risk_reasons=reasons,
            vt_link=vt_link,
        )

    @staticmethod
    def _detect_magic(data: bytes) -> Optional[str]:
        """Detect file type by magic bytes (first few bytes)."""
        for sig, label in MAGIC_SIGNATURES.items():
            if data.startswith(sig):
                return label
        return None

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (0-8) as a measure of randomness."""
        if not data:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        length = len(data)
        entropy = 0.0
        for f in freq:
            if f:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _scan_macros(data: bytes) -> bool:
        """Check for known macro signatures (VBA, AutoOpen, etc.)."""
        for sig in MACRO_SIGNATURES:
            if sig in data:
                return True
        return False

    @staticmethod
    def _risk_verdict(
        filename: str,
        magic: Optional[str],
        entropy: float,
        has_macros: bool,
        data: bytes,
    ) -> Tuple[List[str], RiskLevel, List[str]]:
        """
        Evaluate risk based on multiple heuristics.

        Returns:
            (signatures_matched, risk_level, risk_reasons)
        """
        ext = os.path.splitext(filename.lower())[1]
        sigs: List[str] = []
        reasons: List[str] = []

        # Check for executable magic
        if magic in ("Windows PE (EXE/DLL)", "Linux ELF", "Java class"):
            sigs.append(magic)
            reasons.append(f"Executable binary detected ({magic})")

        # High entropy (packed/encrypted)
        if entropy > ENTROPY_HIGH_THRESHOLD:
            reasons.append(f"High entropy ({entropy:.2f}) — possibly packed or encrypted")
            if entropy > ENTROPY_VERY_HIGH_THRESHOLD:
                reasons.append(f"Very high entropy ({entropy:.2f}) — likely encrypted/compressed")

        # Macro detection
        if has_macros:
            sigs.append("MACRO")
            reasons.append("Macro code detected — may execute on open")

        # RTLO (Right-to-Left Override) in filename
        if any(c in filename for c in RTLO_CHARS):
            sigs.append("RTLO")
            reasons.append("Right-to-Left Override (RTLO) character detected in filename — likely spoofing")

        # Dangerous extension
        if ext in DANGEROUS_EXTS:
            reasons.append(f"Dangerous file extension: {ext}")

        # Determine final risk level
        risk = RiskLevel.SAFE
        if reasons:
            if (magic in ("Windows PE (EXE/DLL)", "Linux ELF") or has_macros or "RTLO" in sigs):
                risk = RiskLevel.DANGEROUS
            else:
                risk = RiskLevel.SUSPICIOUS

        return sigs, risk, reasons