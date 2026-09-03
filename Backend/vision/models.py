"""
Vision models — request/response schemas for visual phishing detection.

Defines data contracts for submitting screenshots and receiving analysis results,
including detected elements, bounding boxes, and threat assessments.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class VisionAnalysisRequest(BaseModel):
    """
    Request payload for vision analysis.

    Attributes:
        image_data_b64: Base64‑encoded image (data‑URL or raw base64).
        url: Optional page URL for context.
        title: Optional page title for context.
    """
    image_data_b64: str = Field(..., min_length=8, description="Base64‑encoded image data")
    url: Optional[str] = Field(None, max_length=2048, description="Page URL")
    title: Optional[str] = Field(None, max_length=512, description="Page title")

    @field_validator("image_data_b64")
    @classmethod
    def validate_image_data(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError("Image data is too short")
        return v


class BoundingBox(BaseModel):
    """
    Bounding box coordinates for a detected element.

    All coordinates are in pixels relative to the image dimensions.
    """
    x: int = Field(..., ge=0, description="Top‑left x coordinate")
    y: int = Field(..., ge=0, description="Top‑left y coordinate")
    width: int = Field(..., gt=0, description="Width in pixels")
    height: int = Field(..., gt=0, description="Height in pixels")


class DetectedElement(BaseModel):
    """
    A visual element detected in the screenshot.

    Attributes:
        class_name: Type of element (e.g., "login_form", "logo", "credential_field").
        confidence: Confidence score (0.0 to 1.0).
        box: Optional bounding box coordinates.
    """
    class_name: str = Field(..., min_length=1, max_length=64, description="Element type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    box: Optional[BoundingBox] = Field(None, description="Bounding box")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return round(v, 4)  # Clamp to 4 decimal places


class VisionAnalysisResult(BaseModel):
    """
    Result of a vision analysis.

    Attributes:
        is_phishing: Whether the screenshot is classified as phishing.
        threat_score: Threat score (0.0 to 100.0).
        detected_elements: List of detected visual elements.
        matched_brand: Brand name if detected (e.g., "Google", "Microsoft").
        reasoning: Human‑readable explanation.
        processing_time_ms: Analysis time in milliseconds.
    """
    is_phishing: bool = Field(..., description="Classification")
    threat_score: float = Field(..., ge=0.0, le=100.0, description="Threat score (0‑100)")
    detected_elements: List[DetectedElement] = Field(default_factory=list, description="Detected visual elements")
    matched_brand: Optional[str] = Field(None, max_length=64, description="Matched brand")
    reasoning: str = Field(..., max_length=1024, description="Explanation")
    processing_time_ms: float = Field(..., ge=0.0, description="Processing time in milliseconds")

    @field_validator("threat_score")
    @classmethod
    def validate_threat_score(cls, v: float) -> float:
        return round(v, 2)  # Clamp to 2 decimal places

    @field_validator("processing_time_ms")
    @classmethod
    def validate_processing_time(cls, v: float) -> float:
        return round(v, 2)