import asyncio
import os
import sys
from dotenv import load_dotenv
from PIL import Image, ImageDraw
import io

# Load environment from Backend/.env
load_dotenv("Backend/.env")

# Ensure Backend is in sys.path
sys.path.insert(0, "Backend")

from tier_3.providers.gemini_provider import GeminiProvider
from tier_3.base import ProviderExecutionStatus
from vision.service import VisionService
from vision.models import VisionAnalysisRequest

def create_image_a_benign():
    """Benign image: solid green nature landscape/rectangle"""
    img = Image.new("RGB", (300, 200), color=(34, 139, 34))
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 250, 150], fill=(50, 205, 50))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def create_image_b_phishing():
    """Phishing image: fake Microsoft login card with password prompt"""
    img = Image.new("RGB", (400, 300), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    # Draw Microsoft 4-square logo
    draw.rectangle([30, 30, 48, 48], fill=(242, 80, 34))
    draw.rectangle([52, 30, 70, 48], fill=(127, 186, 0))
    draw.rectangle([30, 52, 48, 70], fill=(0, 164, 239))
    draw.rectangle([52, 52, 70, 70], fill=(255, 185, 0))
    # Login card text
    draw.text((80, 40), "Microsoft", fill=(100, 100, 100))
    draw.text((40, 90), "Sign in to your Microsoft Account", fill=(0, 0, 0))
    # Username box
    draw.rectangle([40, 130, 360, 160], outline=(100, 100, 100), fill=(255, 255, 255))
    draw.text((50, 140), "someone@example.com", fill=(150, 150, 150))
    # Password box
    draw.rectangle([40, 180, 360, 210], outline=(100, 100, 100), fill=(255, 255, 255))
    draw.text((50, 190), "Password", fill=(150, 150, 150))
    # Blue Next/Sign in button
    draw.rectangle([260, 230, 360, 260], fill=(0, 103, 184))
    draw.text((290, 240), "Sign in", fill=(255, 255, 255))
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

async def main():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("RESULT: NO_KEY_AVAILABLE")
        return

    provider = GeminiProvider(api_key=api_key)
    print(f"Provider available: {provider.is_available()}")
    print(f"Model name: {provider._model_name}")

    img_a_bytes = create_image_a_benign()
    img_b_bytes = create_image_b_phishing()

    print(f"Image A size: {len(img_a_bytes)} bytes")
    print(f"Image B size: {len(img_b_bytes)} bytes")

    # Prompt for multimodal
    prompt = """Analyze this image for visual phishing, brand impersonation, and credential harvesting forms.
Return valid JSON with:
{
  "matched_brand": "BrandName or null",
  "confidence": 0.0 to 1.0,
  "threat_score": 0.0 to 100.0,
  "credential_ui_detected": true/false,
  "visual_impersonation_signal": true/false,
  "findings": ["finding 1"]
}"""

    print("\n--- SENDING IMAGE A (BENIGN) ---")
    resp_a = await provider.generate_multimodal_analysis(
        image_bytes=img_a_bytes,
        mime_type="image/png",
        prompt=prompt,
        timeout_sec=30.0,
    )
    print(f"Image A Status: {resp_a.status.value}")
    print(f"Image A Latency: {resp_a.latency_ms:.2f}ms")
    if resp_a.error_message:
        print(f"Image A Error: {resp_a.error_message}")
    if resp_a.raw_text:
        print(f"Image A Response: {resp_a.raw_text[:300]}")

    print("\n--- SENDING IMAGE B (PHISHING LOGIN CARD) ---")
    resp_b = await provider.generate_multimodal_analysis(
        image_bytes=img_b_bytes,
        mime_type="image/png",
        prompt=prompt,
        timeout_sec=30.0,
    )
    print(f"Image B Status: {resp_b.status.value}")
    print(f"Image B Latency: {resp_b.latency_ms:.2f}ms")
    if resp_b.error_message:
        print(f"Image B Error: {resp_b.error_message}")
    if resp_b.raw_text:
        print(f"Image B Response: {resp_b.raw_text[:300]}")

if __name__ == "__main__":
    asyncio.run(main())
