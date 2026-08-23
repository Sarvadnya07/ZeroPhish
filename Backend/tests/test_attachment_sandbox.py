"""
Unit tests for email_scanner/attachment_sandbox.py.
"""

import os

import pytest

from email_scanner.attachment_sandbox import AttachmentSandbox


def test_attachment_sandbox_safe_pdf():
    """Test standard benign PDF attachment."""
    pdf_header = b"%PDF-1.4\n%Benign document text"
    report = AttachmentSandbox.analyse("document.pdf", pdf_header)

    assert report.filename == "document.pdf"
    assert report.magic_type == "PDF"
    assert report.risk_level == "safe"
    assert report.has_macros is False
    assert len(report.risk_reasons) == 0
    assert report.vt_link.startswith("https://www.virustotal.com/gui/file/")


def test_attachment_sandbox_executable_binary():
    """Test detection of Windows PE executable."""
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    report = AttachmentSandbox.analyse("invoice.pdf.exe", pe_header)

    assert report.magic_type == "Windows PE (EXE/DLL)"
    assert report.risk_level == "dangerous"
    assert "Windows PE (EXE/DLL)" in report.signatures_matched
    assert any("Executable binary" in r for r in report.risk_reasons)
    assert any("Dangerous file extension" in r for r in report.risk_reasons)


def test_attachment_sandbox_office_macro():
    """Test detection of MS Office macro triggers."""
    doc_data = b"\xd0\xcf\x11\xe0 AutoOpen Shell('cmd.exe') VBA"
    report = AttachmentSandbox.analyse("malicious_macro.doc", doc_data)

    assert report.magic_type == "MS Office (OLE)"
    assert report.has_macros is True
    assert report.risk_level == "dangerous"
    assert "MACRO" in report.signatures_matched


def test_attachment_sandbox_rtlo_filename():
    """Test detection of Right-To-Left Override spoofing."""
    rtlo_name = "report\u202eexe.pdf"
    doc_data = b"Plain text content"
    report = AttachmentSandbox.analyse(rtlo_name, doc_data)

    assert "RTLO" in report.signatures_matched
    assert report.risk_level == "dangerous"


def test_attachment_sandbox_high_entropy():
    """Test detection of high-entropy / packed payload."""
    high_entropy_bytes = bytes(range(256)) * 10
    report = AttachmentSandbox.analyse("encrypted.dat", high_entropy_bytes)

    assert report.entropy > 7.2
    assert report.risk_level == "suspicious"
    assert any("High entropy" in r for r in report.risk_reasons)


def test_attachment_sandbox_empty_file():
    """Test zero-byte file analysis."""
    report = AttachmentSandbox.analyse("empty.txt", b"")
    assert report.size_bytes == 0
    assert report.entropy == 0.0
    assert report.risk_level == "safe"
