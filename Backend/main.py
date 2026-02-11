import google.generativeai as genai
import json

# Replace with your actual Gemini API Key
genai.configure(api_key="YOUR_GEMINI_KEY")
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