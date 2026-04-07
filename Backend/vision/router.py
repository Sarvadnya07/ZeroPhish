from fastapi import APIRouter, Depends, HTTPException
from auth.middleware import require_auth
from auth.models import User
from .models import VisionAnalysisRequest, VisionAnalysisResult
from .service import VisionService

router = APIRouter(prefix="/vision", tags=["vision"])

@router.post("/analyze", response_model=VisionAnalysisResult)
async def analyze_screenshot(
    data: VisionAnalysisRequest,
    current_user: User = Depends(require_auth)
):
    """
    Endpoint for the Chrome Extension to submit captured screenshots
    for proactive visual heuristics analysis (CNN / Gemini).
    """
    if not data.image_data_b64.startswith("data:image"):
        # Basic validation for data URL, although we'll process the raw string inside service anyway
        raise HTTPException(status_code=400, detail="Invalid image base64 format")
        
    try:
        res = VisionService.analyze_screenshot(data.image_data_b64, url=data.url, title=data.title)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
