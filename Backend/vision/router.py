"""
Vision FastAPI router — /vision/* endpoints.

Provides screenshot analysis for visual phishing detection,
with rate limiting and authentication.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from auth.middleware import require_auth
from auth.models import User
from security.dependencies import limiter

from .models import VisionAnalysisRequest, VisionAnalysisResult
from .service import VisionService

logger = logging.getLogger(__name__)

# Rate limit: configurable via environment (default 10/minute)
RATE_LIMIT = os.getenv("VISION_RATE_LIMIT", "10/minute")

router = APIRouter(prefix="/vision", tags=["vision"])


@router.post(
    "/analyze",
    response_model=VisionAnalysisResult,
    summary="Analyze screenshot for visual phishing cues",
    description=(
        "Submit a base64‑encoded screenshot with optional URL/title context. "
        "Uses Gemini Multimodal Vision if API key is set; otherwise falls back "
        "to local heuristic analysis. Rate‑limited."
    ),
)
@limiter.limit(RATE_LIMIT)
async def analyze_screenshot(
    request: Request,
    response: Response,
    data: VisionAnalysisRequest,
    current_user: User = Depends(require_auth),
) -> dict[str, Any]:
    """
    Endpoint for the Chrome Extension to submit captured screenshots
    for proactive visual heuristics analysis (CNN / Gemini).
    Requires authentication.
    """
    # Validate input
    if not data.image_data_b64 or len(data.image_data_b64) < 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or empty image data",
        )

    if not data.image_data_b64.startswith("data:image"):
        # Allow raw base64 as well, but warn
        logger.debug("Image data did not start with 'data:image'; assuming raw base64.")

    try:
        result = await VisionService.analyze_screenshot(
            image_b64=data.image_data_b64,
            url=data.url,
            title=data.title,
        )
        logger.info(
            "Vision analysis for user %s: is_phishing=%s, score=%.1f",
            current_user.id,
            result.get("is_phishing"),
            result.get("threat_score", 0),
        )
        return result

    except ValueError as e:
        logger.warning("Vision analysis input error for user %s: %s", current_user.id, e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.exception("Vision analysis failed for user %s", current_user.id)
        # Do not expose internal error details to clients
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vision analysis failed",
        )