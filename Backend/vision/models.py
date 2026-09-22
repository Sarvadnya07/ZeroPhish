"""
Vision models — data contracts for visual forensic analysis.

Defines schemas for screenshot ingestion, visual element detection,
brand impersonation cues, and canonical vision analysis results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, computed_field


class VisionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    HEURISTIC_FALLBACK = "HEURISTIC_FALLBACK"
    VISUAL_REQUIRED = "VISUAL_REQUIRED"
    INVALID_IMAGE = "INVALID_IMAGE"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_REQUESTED = "NOT_REQUESTED"


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
    """
    class_name: str = Field(..., min_length=1, max_length=64, description="Element type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    box: Optional[BoundingBox] = Field(None, description="Optional bounding box")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return round(v, 4)


class VisionAnalysisRequest(BaseModel):
    """
    Request payload for vision analysis.
    """
    image_data_b64: str = Field(..., min_length=8, description="Base64‑encoded image data")
    url: Optional[str] = Field(None, max_length=2048, description="Page URL")
    title: Optional[str] = Field(None, max_length=512, description="Page title")

    @field_validator("image_data_b64")
    @classmethod
    def validate_image_data(cls, v: str) -> str:
        if not v or len(v.strip()) < 8:
            raise ValueError("Image data is too short")
        return v.strip()


class VisionAnalysisResult(BaseModel):
    """
    Canonical evidence-oriented visual forensic result.
    Evidence-grounded, non-authoritative on failure, with no competing is_phishing boolean.
    """
    status: VisionStatus = Field(..., description="Lifecycle status of vision processing")
    visual_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=100.0,
        description="Visual suspicion contribution (0.0=benign, 100.0=extreme phishing, None=failure)",
    )
    confidence: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Advisory confidence score",
    )
    visual_category: str = Field(
        default="UNKNOWN",
        description="Semantic category (e.g. AUTHENTICATION_PORTAL, PAYMENT_GATEWAY, GENERIC_WEB, UNKNOWN, ERROR)",
    )
    findings: List[str] = Field(
        default_factory=list,
        description="Observable forensic findings from pixels/elements",
    )
    detected_brands: List[str] = Field(
        default_factory=list,
        description="Visual brands identified in screenshot",
    )
    visual_brand_confidence: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Confidence in brand recognition",
    )
    brand_domain_mismatch: bool = Field(
        default=False,
        description="Whether identified brand visually conflicts with declared domain",
    )
    credential_ui_detected: bool = Field(
        default=False,
        description="Presence of password, username, or credential harvesting fields",
    )
    payment_ui_detected: bool = Field(
        default=False,
        description="Presence of credit card or financial entry fields",
    )
    visual_impersonation_signal: bool = Field(
        default=False,
        description="Visual imitation of legitimate interface without authorization",
    )
    requires_followup: bool = Field(
        default=False,
        description="Indicates manual inspection or missing screenshot follow-up needed",
    )
    detected_elements: List[DetectedElement] = Field(
        default_factory=list,
        description="List of detected visual elements",
    )
    provider: Optional[str] = Field(
        default=None,
        description="AI provider executing vision analysis",
    )
    model: Optional[str] = Field(
        default=None,
        description="Specific multimodal model utilized",
    )
    error_category: Optional[str] = Field(
        default=None,
        description="Error classification if status is not SUCCESS or HEURISTIC_FALLBACK",
    )
    processing_time_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Processing latency in milliseconds",
    )
    image_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Validated image metadata (width, height, format, size_bytes)",
    )

    @field_validator("visual_score")
    @classmethod
    def validate_visual_score(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            return round(v, 2)
        return None

    @field_validator("confidence", "visual_brand_confidence")
    @classmethod
    def validate_confidence_fields(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            return round(v, 4)
        return None

    @field_validator("processing_time_ms")
    @classmethod
    def validate_processing_time(cls, v: float) -> float:
        return round(v, 2)

    @computed_field
    @property
    def matched_brand(self) -> Optional[str]:
        """Convenience accessor for primary detected brand."""
        return self.detected_brands[0] if self.detected_brands else None

    @computed_field
    @property
    def threat_score(self) -> Optional[float]:
        """Backward-compatible alias for visual_score."""
        return self.visual_score

    @computed_field
    @property
    def is_phishing(self) -> bool:
        """Backward-compatible flag for phishing threshold (>= 70)."""
        return bool(self.visual_score is not None and self.visual_score >= 70.0)

    @computed_field
    @property
    def reasoning(self) -> str:
        """Backward-compatible reasoning summary."""
        return " ".join(self.findings) if self.findings else ""

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        return self.model_dump()[item]

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item) or item in self.model_dump()

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default