"""
Enhanced Email Scanner FastAPI router.

Provides endpoints for:
- Parsing raw .eml files with full analysis
- Live DNS SPF/DMARC validation for a domain
- Static sandbox analysis of a single attachment file
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from auth.middleware import require_auth
from auth.models import User

from .attachment_sandbox import AttachmentSandbox, SandboxReport
from .dns_validator import DnsValidator, DNSAuthRecord
from .parser import EmlParser, EmlParseResult

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/email", tags=["email-scanner"])

# Constants
MAX_EML_SIZE = 10_000_000  # 10 MB
MAX_ATTACHMENT_SIZE = 50_000_000  # 50 MB


async def _read_file_with_limit(
    file: UploadFile,
    request: Request,
    max_bytes: int = MAX_EML_SIZE,
) -> bytes:
    """
    Read an uploaded file in chunks, enforcing a size limit.

    Raises:
        HTTPException (413) if file exceeds max_bytes.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed size ({max_bytes} bytes)",
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
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size ({max_bytes} bytes)",
            )
        chunks.append(chunk)

    return b"".join(chunks)


@router.post(
    "/scan-eml",
    response_model=EmlParseResult,
    summary="Parse and analyze an EML file",
    description="Upload a raw .eml file for full structural and security analysis.",
)
async def scan_eml(
    request: Request,
    file: Annotated[UploadFile, File(description="Raw .eml file")],
    current_user: User = Depends(require_auth),
) -> EmlParseResult:
    """
    Parse a raw .eml file and return:
    - Email structure (subject, sender, recipients, body)
    - All extracted links (shorteners flagged)
    - Attachment triage results (static sandbox)
    - SPF/DKIM/DMARC header analysis
    """
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have .eml extension",
        )

    data = await _read_file_with_limit(file, request, max_bytes=MAX_EML_SIZE)

    try:
        result = EmlParser.parse(data)
        logger.info("EML scan completed for user %s: %s", current_user.id, result.message_id or "unknown")
        return result
    except ValueError as e:
        logger.error("EML parse error for user %s: %s", current_user.id, e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error parsing EML for user %s", current_user.id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal parsing error")


@router.post(
    "/validate",
    response_model=DNSAuthRecord,
    summary="Validate SPF and DMARC via DNS",
    description="Performs live DNS lookups to retrieve and validate SPF and DMARC records for a domain.",
)
async def validate_domain(
    domain: Annotated[str, Form(max_length=253, description="Domain to validate")],
    current_user: User = Depends(require_auth),
) -> DNSAuthRecord:
    """Live DNS lookup for SPF and DMARC records on `domain`."""
    if not domain or not domain.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain is required",
        )

    try:
        result = await DnsValidator.validate(domain.strip())
        logger.info("DNS validation for domain %s by user %s: SPF=%s, DMARC=%s",
                    domain, current_user.id, result.spf_valid, result.dmarc_policy)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("DNS validation failed for %s by user %s", domain, current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"DNS lookup failed: {e}",
        )


@router.post(
    "/attachment",
    response_model=SandboxReport,
    summary="Static sandbox analysis of an attachment",
    description="Upload a single file for static analysis (magic bytes, entropy, macro detection).",
)
async def sandbox_attachment(
    file: Annotated[UploadFile, File(description="File to analyse")],
    current_user: User = Depends(require_auth),
) -> SandboxReport:
    """Static sandbox analysis for a single uploaded attachment."""
    data = await file.read()
    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file",
        )

    if len(data) > MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Attachment too large (max {MAX_ATTACHMENT_SIZE} bytes)",
        )

    try:
        report = AttachmentSandbox.analyse(file.filename or "unknown", data)
        logger.info("Attachment analysis for %s by user %s: risk=%s",
                    file.filename, current_user.id, report.risk_level.value)
        return report
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Attachment analysis failed for user %s", current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Attachment analysis failed",
        )