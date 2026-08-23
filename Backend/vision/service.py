"""
Vision Service — Development Simulation & Placeholder Endpoint.
Provides a mock visual artifact inspection pipeline simulating CNN / Multimodal vision models
(YOLO/ResNet or Gemini Vision) for login form brand mismatches during development.
"""
from __future__ import annotations

import asyncio
import time
from typing import List, Optional

from .models import DetectedElement, VisionAnalysisResult


class VisionService:
    """
    Development Placeholder for CNN / Multimodal Vision Analysis.
    Evaluates visual phishing cues from browser screenshots and DOM metadata.
    """

    @staticmethod
    async def analyze_screenshot(
        image_b64: str, url: Optional[str] = None, title: Optional[str] = None
    ) -> dict:
        """
        Analyze screenshot for visual phishing artifacts.
        NOTE: Operates as a development simulation placeholder until dedicated
        model weights / external multimodal vision inference service is mounted.
        """
        start = time.perf_counter()

        is_suspicious = False
        reason = "Page matches standard visual heuristics. No spoofed login portals detected."
        score = 10.0
        brand = None
        elements: List[DetectedElement] = []

        url_lower = (url or "").lower()
        title_lower = (title or "").lower()

        # Visual credential harvest heuristics
        if any(keyword in title_lower for keyword in ["login", "password", "sign in"]):
            if "microsoft" not in url_lower and "google" not in url_lower:
                is_suspicious = True
                score = 85.0
                brand = "Unknown / Generic Corporate"

                if "microsoft" in title_lower:
                    brand = "Microsoft"
                elif "google" in title_lower:
                    brand = "Google"

                reason = (
                    f"Visual elements indicate a {brand} login page, but the URL domain "
                    f"does not match official {brand} infrastructure."
                )
                elements.append(DetectedElement(class_name="login_form", confidence=0.98))
                elements.append(DetectedElement(class_name="credential_field", confidence=0.95))

        # Simulation latency
        await asyncio.sleep(0.3)
        duration_ms = (time.perf_counter() - start) * 1000.0

        res = VisionAnalysisResult(
            is_phishing=is_suspicious,
            threat_score=score,
            detected_elements=elements,
            matched_brand=brand,
            reasoning=reason,
            processing_time_ms=duration_ms,
        )
        return res.model_dump()
