"""
Vision FastAPI router — /vision/* endpoints.

Provides screenshot analysis for visual phishing detection,
with rate limiting, authentication, and hardened security guards.
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
_vision_service = VisionService()


@router.post(
    "/analyze",
    response_model=VisionAnalysisResult,
    summary="Analyze screenshot for visual phishing cues",
    description=(
        "Submit a base64‑encoded screenshot with optional URL/title context. "
        "Uses Multimodal Vision via Tier3Router if available; otherwise performs "
        "hardened pixel forensic fallback. Rate‑limited."
    ),
)
@limiter.limit(RATE_LIMIT)
async def analyze_screenshot(
    request: Request,
    response: Response,
    data: VisionAnalysisRequest,
    current_user: User = Depends(require_auth),
) -> VisionAnalysisResult:
    """
    Endpoint for client/extension to submit captured screenshots
    for visual forensics analysis.
    Requires authentication.
    """
    if not data.image_data_b64 or len(data.image_data_b64.strip()) < 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or empty image data payload",
        )

    try:
        result = await _vision_service.analyze_screenshot(
            image_b64=data.image_data_b64,
            url=data.url,
            title=data.title,
        )
        logger.info(
            "Vision analysis completed for user %s: status=%s, visual_score=%s, category=%s",
            current_user.id,
            result.status.value,
            result.visual_score,
            result.visual_category,
        )
        return result

    except ValueError as e:
        logger.warning("Vision analysis input validation error for user %s: %s", current_user.id, e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.exception("Vision analysis unexpected failure for user %s", current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vision analysis processing error",
        )