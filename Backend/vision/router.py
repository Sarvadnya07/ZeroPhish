from fastapi import APIRouter, Depends, HTTPException, Request

from auth.middleware import require_auth
from auth.models import User
from security.dependencies import limiter

from .models import VisionAnalysisRequest, VisionAnalysisResult
from .service import VisionService

router = APIRouter(prefix="/vision", tags=["vision"])


@router.post("/analyze", response_model=VisionAnalysisResult)
@limiter.limit("10/minute")
async def analyze_screenshot(
    request: Request,
    data: VisionAnalysisRequest,
    current_user: User = Depends(require_auth),
):
    """
    Endpoint for the Chrome Extension to submit captured screenshots
    for proactive visual heuristics analysis (CNN / Gemini).
    Requires authentication. Rate-limited to 10 requests/minute per IP.
    """
    if not data.image_data_b64.startswith("data:image"):
        raise HTTPException(status_code=400, detail="Invalid image base64 format")

    try:
        res = await VisionService.analyze_screenshot(
            data.image_data_b64, url=data.url, title=data.title
        )
        return res
    except Exception:
        # Do not expose internal error details to clients
        raise HTTPException(status_code=500, detail="Vision analysis failed")
