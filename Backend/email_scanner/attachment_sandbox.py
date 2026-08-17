"""
Attachment sandbox — static analysis triage.
Full dynamic sandboxing (Cuckoo / ANY.RUN) requires external integrations;
this module does local static triage: magic bytes, YARA-like signature matching,
entropy scoring, and macro detection in Office documents.
"""
from __future__ import annotations

import hashlib
import struct
from typing import List, Optional

from pydantic import BaseModel


class SandboxReport(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    magic_type: Optional[str] = None     # detected by magic bytes
    entropy: float = 0.0                 # high entropy → packed/encrypted
    has_macros: bool = False
    signatures_matched: List[str] = []
    risk_level: str = "safe"             # "safe" | "suspicious" | "dangerous"
    risk_reasons: List[str] = []
    vt_link: Optional[str] = None        # VirusTotal search URL


# Simple magic byte signatures
_MAGIC = {
    b"\x4d\x5a":                     "Windows PE (EXE/DLL)",
    b"\x7f\x45\x4c\x46":             "Linux ELF",
    b"\xca\xfe\xba\xbe":             "Java class",
    b"\xd0\xcf\x11\xe0":             "MS Office (OLE)",
    b"\x50\x4b\x03\x04":             "ZIP archive",
    b"\x52\x61\x72\x21\x1a\x07":    "RAR archive",
    b"\x25\x50\x44\x46":             "PDF",
    b"\x1f\x8b":                     "GZIP",
}

_MACRO_SIGNATURES = [
    b"VBA",
    b"Word.Basic",
    b"AutoOpen",
    b"Auto_Open",
    b"Document_Open",
    b"Shell(",
    b"WScript",
]


class AttachmentSandbox:

    @staticmethod
    def analyse(filename: str, data: bytes) -> SandboxReport:
        sha = hashlib.sha256(data).hexdigest()
        magic = AttachmentSandbox._detect_magic(data)
        entropy = AttachmentSandbox._shannon_entropy(data)
        has_macros = AttachmentSandbox._scan_macros(data)
        sigs, risk, reasons = AttachmentSandbox._risk_verdict(filename, magic, entropy, has_macros, data)

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
        for sig, label in _MAGIC.items():
            if data[:len(sig)] == sig:
                return label
        return None

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        import math
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
        for sig in _MACRO_SIGNATURES:
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
    ) -> tuple[List[str], str, List[str]]:
        import os
        ext  = os.path.splitext(filename.lower())[1]
        sigs: List[str] = []
        reasons: List[str] = []

        if magic in ("Windows PE (EXE/DLL)", "Linux ELF", "Java class"):
            sigs.append(magic)
            reasons.append(f"Executable binary detected ({magic})")

        if entropy > 7.2:
            reasons.append(f"High entropy ({entropy:.2f}) — possibly packed or encrypted")

        if has_macros:
            sigs.append("MACRO")
            reasons.append("Macro code detected — may execute on open")

        rtlo_chars = {"\u202e", "\u202b", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"}
        if any(c in filename for c in rtlo_chars):
            sigs.append("RTLO")
            reasons.append(f"Right-to-Left Override (RTLO) character detected in filename")

        if ext in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".hta"}:
            reasons.append(f"Dangerous file extension: {ext}")

        if reasons:
            risk = "dangerous" if (magic in ("Windows PE (EXE/DLL)", "Linux ELF") or has_macros or "RTLO" in sigs) else "suspicious"
        else:
            risk = "safe"


        return sigs, risk, reasons
