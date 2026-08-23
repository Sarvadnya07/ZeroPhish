"""
Enhanced Email Scanner FastAPI router.
POST /email/scan-eml   — upload raw .eml file
POST /email/validate    — validate SPF/DKIM/DMARC for a domain
POST /email/attachment  — sandbox a single attachment
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile

from auth.middleware import require_auth
from auth.models import User

from .attachment_sandbox import AttachmentSandbox
from .dns_validator import DnsValidator
from .parser import EmlParser

router = APIRouter(prefix="/email", tags=["email-scanner"])


async def _read_file_with_limit(
    file: UploadFile, request: Request, max_bytes: int = 10_000_000
) -> bytes:
    """Read an uploaded file in chunks, enforcing max_bytes limit."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(
                    status_code=413, detail=f"File exceeds maximum allowed size ({max_bytes} bytes)"
                )
        except ValueError:
            pass

    chunks = []
    total = 0
    chunk_size = 64 * 1024  # 64 KB

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413, detail=f"File exceeds maximum allowed size ({max_bytes} bytes)"
            )
        chunks.append(chunk)

    return b"".join(chunks)


@router.post("/scan-eml")
async def scan_eml(
    request: Request,
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
    data = await _read_file_with_limit(file, request, max_bytes=10_000_000)  # 10 MB cap
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
