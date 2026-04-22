import time
import base64
from typing import List
from .models import VisionAnalysisResult, DetectedElement

class VisionService:
    @staticmethod
    def analyze_screenshot(image_b64: str, url: str = None, title: str = None) -> dict:
        """
        Simulate a Vision Transformer (ViT) analyzing the screenshot for visual phishing artifacts.
        In a production environment, this would use a model like CLIP or a custom ViT to extract 
        embeddings and compare them against known 'high-risk' brand assets.
        """
        start = time.perf_counter()
        
        # 1. Feature Extraction Simulation
        # In reality: model.extract_features(image)
        # Here: Simulate detection of brand assets and UI components
        detected_elements: List[DetectedElement] = []
        
        url_lower = (url or "").lower()
        title_lower = (title or "").lower()
        
        # Define high-risk brands for simulation
        HIGH_RISK_BRANDS = {
            "microsoft": ["office", "outlook", "sharepoint", "live.com"],
            "google": ["gmail", "drive", "account", "google.com"],
            "paypal": ["wallet", "checkout", "paypal.com"],
            "apple": ["icloud", "id.apple", "apple.com"]
        }
        
        matched_brand = None
        similarity_score = 0.0
        
        # Simulate ViT detecting a logo
        for brand, keywords in HIGH_RISK_BRANDS.items():
            if any(k in title_lower or k in url_lower for k in keywords):
                matched_brand = brand.capitalize()
                similarity_score = 0.92 # High similarity to authentic brand logo
                break
        
        is_phishing = False
        threat_score = 10.0
        reasoning = "Visual profile appears consistent with normal web usage. No brand spoofing detected."
        
        if matched_brand:
            # Check for domain mismatch (Visual-Domain Inconsistency)
            official_domain = HIGH_RISK_BRANDS[matched_brand.lower()][-1]
            if official_domain not in url_lower:
                is_phishing = True
                threat_score = 88.5
                reasoning = (
                    f"ViT detected high visual similarity ({similarity_score*100}%) to {matched_brand} branding, "
                    f"but the current domain does not match the official {official_domain} infrastructure. "
                    "This is a classic 'Visual-Domain Inconsistency' signal used in phishing."
                )
                
                # Simulate bounding box detection for UI elements
                detected_elements.append(DetectedElement(
                    class_name="brand_logo", 
                    confidence=similarity_score,
                    box={"x": 20, "y": 20, "width": 150, "height": 50}
                ))
                detected_elements.append(DetectedElement(
                    class_name="login_container", 
                    confidence=0.95,
                    box={"x": 300, "y": 150, "width": 400, "height": 500}
                ))
            else:
                reasoning = f"Visual match for {matched_brand} confirmed on official domain {official_domain}."
                threat_score = 5.0
        
        # Simulate processing time for ViT inference
        time.sleep(0.45) 
        duration_ms = (time.perf_counter() - start) * 1000.0
        
        res = VisionAnalysisResult(
            is_phishing=is_phishing,
            threat_score=threat_score,
            detected_elements=detected_elements,
            matched_brand=matched_brand,
            reasoning=reasoning,
            processing_time_ms=duration_ms
        )
        return res.model_dump()

    @staticmethod
    def analyze_dom_fingerprint(dom_structure: str) -> dict:
        """
        Analyze the DOM for behavioral fingerprints of phishing clones.
        Checks for CSS Obfuscation, Hidden SVGs, and Paste-event interception.
        """
        signals = []
        threat_score = 0
        
        # 1. CSS Obfuscation Check
        if "opacity: 0" in dom_structure or "display: none" in dom_structure:
            if "<input" in dom_structure:
                signals.append("CSS Overlay detected over input fields")
                threat_score += 25
                
        # 2. SVG Logo Spoofing
        if "<svg" in dom_structure and "path" in dom_structure:
            signals.append("Dynamic SVG branding detected")
            threat_score += 15
            
        # 3. Behavioral Inconsistency
        if "addEventListener" in dom_structure and ("paste" in dom_structure or "contextmenu" in dom_structure):
            signals.append("User interaction interception detected")
            threat_score += 20
            
        return {
            "fingerprint_score": min(100, threat_score),
            "signals": signals,
            "complexity": "high" if threat_score > 30 else "standard"
        }
