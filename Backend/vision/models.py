from pydantic import BaseModel
from typing import List, Optional

class VisionAnalysisRequest(BaseModel):
    image_data_b64: str
    url: Optional[str] = None
    title: Optional[str] = None

class BoundingBox(BaseModel):
    x: int
    y: int
    width: int
    height: int

class DetectedElement(BaseModel):
    class_name: str
    confidence: float
    box: Optional[BoundingBox] = None

class VisionAnalysisResult(BaseModel):
    is_phishing: bool
    threat_score: float
    detected_elements: List[DetectedElement]
    matched_brand: Optional[str] = None
    reasoning: str
    processing_time_ms: float
    engine_status: str = "heuristic_stub"
