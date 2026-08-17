"""
Tests for email_scanner — parser attachment triage: RTLO detection,
MIME mismatch, executable extensions, streaming upload size guard.
"""
import io
import pytest
from email_scanner.parser import EmlParser


# ── Attachment triage ──────────────────────────────────────────────────────────

def _triage(filename: str, content_type: str, data: bytes = b"x"):
    return EmlParser._analyse_attachment(filename, content_type, data)


def test_executable_extension_flagged():
    info = _triage("installer.exe", "application/octet-stream")
    assert info.risk_level == "dangerous"
    assert info.is_executable is True


def test_rtlo_in_filename_flagged():
    # RTLO (U+202E) makes "invoice.pdf\u202Eexe" render as "invoicexe.fdp"
    rtlo_name = "invoice.pdf\u202Eexe"
    info = _triage(rtlo_name, "application/pdf")
    assert info.risk_level == "dangerous"
    assert info.is_executable is True
    assert "RTLO" in (info.risk_reason or "")


def test_mime_exec_with_pdf_extension():
    # Content-Type says executable even though extension is .pdf
    info = _triage("report.pdf", "application/x-msdownload")
    assert info.risk_level == "dangerous"
    assert info.is_executable is True


def test_archive_flagged_suspicious():
    info = _triage("payload.zip", "application/zip")
    assert info.risk_level == "suspicious"
    assert info.is_archive is True


def test_office_doc_flagged_suspicious():
    info = _triage("invoice.docx", "application/vnd.openxmlformats")
    assert info.risk_level == "suspicious"
    assert info.is_document is True


def test_plain_image_is_safe():
    info = _triage("photo.jpg", "image/jpeg")
    assert info.risk_level == "safe"
    assert info.is_executable is False


def test_sha256_computed():
    data = b"hello world"
    import hashlib
    info = _triage("test.txt", "text/plain", data)
    assert info.sha256 == hashlib.sha256(data).hexdigest()


# ── Upload size guard (streaming reader) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_upload_size_guard_rejects_oversized():
    """_read_file_with_limit must reject a file that exceeds max_bytes mid-stream."""
    from fastapi.exceptions import HTTPException as FastApiHTTPException
    from email_scanner.router import _read_file_with_limit
    from unittest.mock import AsyncMock, MagicMock

    # Build a fake UploadFile that streams 3 × 1 MB chunks
    one_mb = b"A" * (1024 * 1024)
    chunks = [one_mb, one_mb, one_mb, b""]  # last empty = EOF

    async def fake_read(n):
        return chunks.pop(0)

    upload = MagicMock()
    upload.read = fake_read

    request = MagicMock()
    request.headers = {}  # No Content-Length header

    with pytest.raises(FastApiHTTPException) as exc_info:
        await _read_file_with_limit(upload, request, max_bytes=1_000_000)

    assert exc_info.value.status_code == 413


@pytest.mark.asyncio
async def test_upload_size_guard_accepts_small_file():
    from email_scanner.router import _read_file_with_limit
    from unittest.mock import MagicMock

    small = b"small content"
    chunks = [small, b""]

    async def fake_read(n):
        return chunks.pop(0)

    upload = MagicMock()
    upload.read = fake_read

    request = MagicMock()
    request.headers = {}

    result = await _read_file_with_limit(upload, request, max_bytes=1_000_000)
    assert result == small


@pytest.mark.asyncio
async def test_upload_size_guard_content_length_header_checked():
    """Content-Length header alone should trigger early rejection before any read."""
    from fastapi.exceptions import HTTPException as FastApiHTTPException
    from email_scanner.router import _read_file_with_limit
    from unittest.mock import MagicMock

    upload = MagicMock()
    request = MagicMock()
    request.headers = {"content-length": str(2 * 1024 * 1024)}  # 2 MB header

    with pytest.raises(FastApiHTTPException) as exc_info:
        await _read_file_with_limit(upload, request, max_bytes=1_000_000)

    assert exc_info.value.status_code == 413
    # No reads should have been attempted since header was enough
    upload.read.assert_not_called()

