import time
from typing import List
from .models import VisionAnalysisResult, DetectedElement


class VisionService:
    @staticmethod
    def analyze_screenshot(image_b64: str, url: str = None, title: str = None) -> dict:
        """
        Simulate a CNN / Multimodal LLM analyzing the screenshot for visual phishing artifacts.
        In a production environment, this would decode base64, pass to a CNN inference
        server (e.g. YOLO/ResNet) or pass to an API like Gemini 1.5 Pro Vision.
        """
        start = time.perf_counter()

        # Determine if we generate a mock suspicious result
        is_suspicious = False
        reason = "Page matches standard visual heuristics. No spoofed login portals detected."
        score = 10.0
        brand = None
        elements: List[DetectedElement] = []

        url_lower = (url or "").lower()
        title_lower = (title or "").lower()

        # Mock logic based on keywords
        if "login" in title_lower or "password" in title_lower or "sign in" in title_lower:
            # Looks like a login page. Are we on a Microsoft/Google domain?
            if "microsoft" not in url_lower and "google" not in url_lower:
                is_suspicious = True
                score = 85.0
                brand = "Unknown / Generic Corporate"
                if "microsoft" in title_lower:
                    brand = "Microsoft"
                elif "google" in title_lower:
                    brand = "Google"

                reason = (
                    f"Visual elements indicate a {brand} login page, but the URL "
                    f"domain does not match official {brand} infrastructure."
                )
                elements.append(DetectedElement(class_name="login_form", confidence=0.98))
                elements.append(DetectedElement(class_name="credential_field", confidence=0.95))

        # Small artificial delay to simulate CNN inference
        time.sleep(0.3)
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
