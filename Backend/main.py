import google.generativeai as genai
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY or GEMINI_API_KEY == "your_actual_gemini_api_key_here":
    raise ValueError("GEMINI_API_KEY not set in .env file. Please add your actual API key.")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

async def tier_3_ai_analysis(email_body: str):
    # This system prompt is pulled directly from our forensic knowledge base
    system_prompt = """
    You are a Forensic Cybersecurity Analyst. Analyze the following email for 
    Social Engineering, Phishing, or Malicious Intent.
    Return ONLY JSON:
    {
      "threat_level": 0-100,
      "category": "Urgency/Financial/Credential/Safe",
      "reasoning": "1-sentence explanation",
      "flagged_phrases": []
    }
    """
    
    try:
        response = await model.generate_content_async(f"{system_prompt}\n\nEmail: {email_body}")
        # Clean the response to ensure it's pure JSON
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        print(f"AI Error: {e}")
        return {"threat_level": 50, "category": "Scan Error", "reasoning": "AI Analysis timed out."}