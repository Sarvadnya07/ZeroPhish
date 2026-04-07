"""
Enhanced Email Scanner FastAPI router.
POST /email/scan-eml   — upload raw .eml file
POST /email/validate    — validate SPF/DKIM/DMARC for a domain
POST /email/attachment  — sandbox a single attachment
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from auth.middleware import require_auth
from auth.models import User

from .attachment_sandbox import AttachmentSandbox
from .dns_validator import DnsValidator
from .parser import EmlParser

router = APIRouter(prefix="/email", tags=["email-scanner"])


@router.post("/scan-eml")
async def scan_eml(
    file: UploadFile = File(..., description="Raw .eml file"),
    current_user: User = Depends(require_auth),
):
    """
    Parse a raw .eml file and return:
    - Full text + HTML body
    - All extracted links (recursive shortener flagging)
    - Attachment triage results
    - SPF/DKIM/DMARC header analysis
    """
    if file.content_type and file.content_type not in ("message/rfc822", "application/octet-stream", "text/plain"):
        # Accept anyway — browsers often send wrong MIME for .eml
        pass
    data = await file.read()
    if len(data) > 10_000_000:  # 10 MB cap
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")
    try:
        result = EmlParser.parse(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse .eml: {exc}")
    return result


@router.post("/validate")
async def validate_domain(
    domain: str = Form(..., max_length=253),
    current_user: User = Depends(require_auth),
):
    """Live DNS lookup for SPF and DMARC records on `domain`."""
    try:
        result = await DnsValidator.validate(domain)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DNS lookup failed: {exc}")
    return result


@router.post("/attachment")
async def sandbox_attachment(
    file: UploadFile = File(...),
    current_user: User = Depends(require_auth),
):
    """Static sandbox analysis for a single uploaded attachment."""
    data = await file.read()
    if len(data) > 50_000_000:  # 50 MB cap
        raise HTTPException(status_code=413, detail="Attachment too large (max 50 MB)")
    return AttachmentSandbox.analyse(file.filename or "unknown", data)
