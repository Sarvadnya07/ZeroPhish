#!/usr/bin/env python3
"""
Test script to verify dashboard data flow.

This script tests the ZeroPhish backend endpoints:
1. Health check (/health)
2. Latest scan retrieval (/tier1/latest)
3. Sending a test report (/tier1/report)
4. Verifying the report was stored

Usage:
    python verify_dashboard_flow.py [--url BASE_URL] [--verbose]

Environment variables:
    ZEROPHISH_BASE_URL: Base URL of the backend (default: http://127.0.0.1:8000)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests

# ---------- Configuration ----------
DEFAULT_BASE_URL = os.getenv("ZEROPHISH_BASE_URL", "http://127.0.0.1:8000")
DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRY_COUNT = 2
DEFAULT_RETRY_DELAY = 1.0

# ---------- Logging Setup ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------- Helpers ----------
def _color_text(text: str, color: str) -> str:
    """Add ANSI color to text for terminal output."""
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "reset": "\033[0m",
    }
    if not sys.stdout.isatty():  # No color if not a TTY
        return text
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def _safe_request(
    method: str,
    url: str,
    json_data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRY_COUNT,
) -> Tuple[bool, Optional[requests.Response], Optional[str]]:
    """
    Make a HTTP request with retries and error handling.

    Returns:
        (success, response, error_message)
    """
    for attempt in range(retries + 1):
        try:
            if method.upper() == "GET":
                resp = requests.get(url, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                resp = requests.post(url, json=json_data, headers=headers, timeout=timeout)
            else:
                return False, None, f"Unsupported method: {method}"
            return True, resp, None
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            if attempt < retries:
                logger.warning("Attempt %d/%d failed: %s. Retrying in %.1fs...",
                               attempt + 1, retries + 1, error_msg, DEFAULT_RETRY_DELAY)
                time.sleep(DEFAULT_RETRY_DELAY)
            else:
                return False, None, error_msg
        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            if attempt < retries:
                logger.warning("Attempt %d/%d timed out. Retrying...", attempt + 1, retries + 1)
                time.sleep(DEFAULT_RETRY_DELAY)
            else:
                return False, None, error_msg
        except Exception as e:
            return False, None, f"Unexpected error: {e}"
    return False, None, "Max retries exceeded"


def _check_response(resp: Optional[requests.Response], endpoint: str) -> bool:
    """Check HTTP response status and log result."""
    if resp is None:
        logger.error("No response received for %s", endpoint)
        return False
    if resp.status_code < 300:
        logger.info("%s %s - %s", _color_text("✅", "green"), endpoint, resp.status_code)
        return True
    else:
        logger.warning("%s %s - %s (response: %s)",
                       _color_text("⚠️", "yellow"), endpoint, resp.status_code, resp.text[:200])
        return False


# ---------- Main Test Functions ----------
def test_health(base_url: str) -> bool:
    """Test backend health endpoint."""
    logger.info("Test 1: Checking backend health...")
    url = f"{base_url}/health"
    success, resp, error = _safe_request("GET", url)
    if not success or resp is None:
        logger.error("%s Backend health check failed: %s", _color_text("❌", "red"), error)
        return False
    try:
        data = resp.json()
        logger.info("  Response: %s", json.dumps(data, indent=2))
        return True
    except json.JSONDecodeError:
        logger.warning("  Response not JSON: %s", resp.text[:100])
        return True  # Health check passed even if response isn't JSON


def test_latest(base_url: str) -> Tuple[bool, Optional[Dict]]:
    """Test /tier1/latest endpoint."""
    logger.info("\nTest 2: Checking /tier1/latest...")
    url = f"{base_url}/tier1/latest"
    success, resp, error = _safe_request("GET", url)
    if not success or resp is None:
        logger.error("%s /tier1/latest failed: %s", _color_text("❌", "red"), error)
        return False, None
    if resp.status_code == 200:
        data = resp.json()
        if data:
            logger.info("  Latest scan: %s", data.get("scan_id", "N/A"))
            return True, data
        else:
            logger.info("  No scans yet (null)")
            return True, None
    else:
        logger.warning("  /tier1/latest returned status %s", resp.status_code)
        return False, None


def test_send_report(base_url: str, scan_id: str) -> Tuple[bool, Optional[Dict]]:
    """Send a test report to /tier1/report."""
    logger.info("\nTest 3: Sending test report to /tier1/report...")
    test_report = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "sender": "test@example.com",
        "subject": "Test Email from Script",
        "final_score": 85,
        "verdict": "SUSPICIOUS",
        "evidence": ["Test evidence 1", "Test evidence 2"],
        "threat_analysis": {"category": "Test"},
        "tier_details": {
            "tier1": {"score": 30, "status": "suspicious"},
            "tier2": {"score": 40, "status": "suspicious"},
            "tier3": {"score": 15, "status": "suspicious"},
        },
    }
    url = f"{base_url}/tier1/report"
    headers = {"Content-Type": "application/json"}
    success, resp, error = _safe_request("POST", url, json_data=test_report, headers=headers)
    if not success or resp is None:
        logger.error("%s Report failed: %s", _color_text("❌", "red"), error)
        return False, None
    if resp.status_code < 300:
        logger.info("%s Report sent: %s", _color_text("✅", "green"), resp.status_code)
        try:
            data = resp.json()
            logger.info("  Response: %s", json.dumps(data, indent=2))
            return True, data
        except json.JSONDecodeError:
            logger.info("  Response: %s", resp.text[:100])
            return True, None
    else:
        logger.warning("  Report failed with status %s: %s", resp.status_code, resp.text[:200])
        return False, None


def test_verify_stored(base_url: str, expected_scan_id: str) -> bool:
    """Verify that the test report was stored."""
    logger.info("\nTest 4: Verifying report was stored...")
    url = f"{base_url}/tier1/latest"
    success, resp, error = _safe_request("GET", url)
    if not success or resp is None:
        logger.error("%s Verification failed: %s", _color_text("❌", "red"), error)
        return False
    if resp.status_code != 200:
        logger.warning("  /tier1/latest returned status %s", resp.status_code)
        return False
    data = resp.json()
    if data and data.get("scan_id") == expected_scan_id:
        logger.info("%s Report stored successfully!", _color_text("✅", "green"))
        logger.info("  Scan ID: %s", data.get("scan_id"))
        logger.info("  Score: %s", data.get("final_score"))
        logger.info("  Verdict: %s", data.get("verdict"))
        return True
    else:
        logger.warning("  Report not found in latest")
        logger.info("  Got: %s", data)
        return False


# ---------- Main ----------
def main() -> int:
    parser = argparse.ArgumentParser(description="Verify ZeroPhish dashboard data flow.")
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of the backend (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    base_url = args.url.rstrip("/")
    logger.info("Using backend URL: %s", base_url)

    # Run tests
    results = []

    # Test 1: Health
    results.append(test_health(base_url))

    # Test 2: Latest (before sending)
    latest_ok, latest_data = test_latest(base_url)
    results.append(latest_ok)

    # Test 3: Send report
    scan_id = f"test-{int(datetime.now().timestamp())}"
    send_ok, send_data = test_send_report(base_url, scan_id)
    results.append(send_ok)

    # Test 4: Verify stored
    verify_ok = False
    if send_ok:
        verify_ok = test_verify_stored(base_url, scan_id)
    results.append(verify_ok)

    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("Test Summary:")
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        logger.info("%s All %d tests passed!", _color_text("✅", "green"), total)
        logger.info("Dashboard should now show the test scan!")
        logger.info("Open: http://localhost:3000")
    else:
        logger.warning("%s %d/%d tests passed.", _color_text("⚠️", "yellow"), passed, total)
        for idx, r in enumerate(results, start=1):
            status = _color_text("PASS", "green") if r else _color_text("FAIL", "red")
            logger.info("  Test %d: %s", idx, status)
    logger.info("=" * 50)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())