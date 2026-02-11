# main.py - Simplified version for Windows
import os
import asyncio
import json
import whois
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import google.generativeai as genai

# Import simplified cache (no Redis dependency)
try:
    from speed_layer import cache, init_cache
except ImportError:
    print("⚠️ speed_layer.py not found, creating simple fallback cache")
    
    # Simple fallback cache if speed_layer.py is missing
    class SimpleCache:
        def __init__(self):
            self.cache = {}
        
        async def get_cached_result(self, sender: str, body: str):
            key = f"{sender}:{hash(body)}"
            return self.cache.get(key)
        
        async def set_cached_result(self, sender: str, body: str, result: dict):
            key = f"{sender}:{hash(body)}"
            self.cache[key] = result
        
        async def get_stats(self):
            return {"status": "simple_cache", "size": len(self.cache)}
        
        async def clear_cache(self):
            self.cache.clear()
        
        async def disconnect(self):
            pass
    
    cache = SimpleCache()
    
    async def init_cache():
        print("✅ Simple cache initialized")
        return cache

# --- INITIALIZATION ---
app = FastAPI(title="ZeroPhish Backend")

# CORS for Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini Flash
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_KEY_HERE")
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

# --- DATA MODELS ---
class ScanRequest(BaseModel):
    sender: str
    body: str
    links: List[str]

class AIAnalysis(BaseModel):
    threat_level: Optional[int] = None
    category: str
    reasoning: str
    flagged_phrases: Optional[List[str]] = []

class ScanResponse(BaseModel):
    final_score: float
    verdict: str
    evidence: List[str]
    tier_details: dict
    ai_analysis: AIAnalysis
    cached: bool = False

# --- LOGIC UTILITIES ---

def get_domain_age(domain: str) -> int:
    """Tier 2: WHOIS Check. Returns age in days."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not creation_date:
            return 0
            
        age = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
        return age
    except Exception:
        return 0

async def tier_3_ai_analysis(email_body: str) -> AIAnalysis:
    """Tier 3: Gemini Semantic Intent Analysis."""
    system_prompt = """You are a Forensic Cybersecurity Analyst. Analyze the following email for 
    Social Engineering, Phishing, or Malicious Intent.
    Return ONLY valid JSON in this exact format:
    {
      "threat_level": 0-100,
      "category": "Urgency/Financial/Credential/Safe/Scan Error",
      "reasoning": "1-sentence explanation",
      "flagged_phrases": ["phrase1", "phrase2"]
    }
    """
    
    try:
        response = await model.generate_content_async(f"{system_prompt}\n\nEmail: {email_body}")
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        
        analysis_data = json.loads(clean_json)
        
        return AIAnalysis(
            threat_level=analysis_data.get("threat_level", 50),
            category=analysis_data.get("category", "Unknown"),
            reasoning=analysis_data.get("reasoning", "No reasoning provided"),
            flagged_phrases=analysis_data.get("flagged_phrases", [])
        )
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
        return AIAnalysis(
            threat_level=50,
            category="Parse Error",
            reasoning="Could not parse AI response",
            flagged_phrases=[]
        )
    except Exception as e:
        print(f"AI Analysis Error: {e}")
        return AIAnalysis(
            threat_level=50,
            category="Scan Error",
            reasoning=f"AI Analysis failed: {str(e)}",
            flagged_phrases=[]
        )

# --- EVENT HANDLERS ---

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    await init_cache()
    print("✅ ZeroPhish Backend started")
    
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await cache.disconnect()

# --- CORE ENDPOINT ---

@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Scan email for phishing."""
    # Check cache first
    cached_result = await cache.get_cached_result(request.sender, request.body)
    
    if cached_result:
        # Remove metadata
        for key in ['_cached_at', '_ttl', '_cache_type']:
            cached_result.pop(key, None)
        
        if 'ai_analysis' in cached_result:
            cached_result['ai_analysis'] = AIAnalysis(**cached_result['ai_analysis'])
        
        if 'evidence' in cached_result:
            cached_result['evidence'].append("⚡ Served from cache")
        
        return ScanResponse(**cached_result, cached=True)
    
    # If not cached, perform full scan
    evidence = []
    t1_status, t2_status, t3_status = "OK", "OK", "OK"
    t1_score, t2_score, t3_score = 0.0, 0.0, 0.0
    
    # 1. Tier 1: Local Heuristics
    high_risk_keywords = ["urgent", "immediately", "verify", "unauthorized", "suspended"]
    medium_risk_keywords = ["password", "login", "account", "security", "confirm"]
    
    body_lower = request.body.lower()
    
    high_risk_count = sum(1 for word in high_risk_keywords if word in body_lower)
    medium_risk_count = sum(1 for word in medium_risk_keywords if word in body_lower)
    
    if high_risk_count > 0:
        t1_score = min(30 + (high_risk_count * 15), 100)
        evidence.append(f"⚠️ High-pressure keywords detected ({high_risk_count} high-risk phrases).")
        t1_status = "SUSPICIOUS"
    
    if medium_risk_count > 0:
        t1_score += min(10 + (medium_risk_count * 5), 40)
        evidence.append(f"⚠️ Suspicious keywords found ({medium_risk_count} medium-risk phrases).")
        t1_status = "SUSPICIOUS" if t1_status == "OK" else t1_status
    
    t1_score = min(t1_score, 100)
    
    # 2. Tier 2: Domain Age
    try:
        domain = request.sender.split("@")[-1]
        age_days = await asyncio.to_thread(get_domain_age, domain)
        
        if age_days == 0:
            t2_score = 70.0
            evidence.append("⚠️ Could not verify domain age.")
            t2_status = "UNKNOWN"
        elif age_days < 30:
            t2_score = 100.0
            evidence.append(f"🚨 Domain is very young ({age_days} days).")
            t2_status = "CRITICAL"
        elif age_days < 365:
            t2_score = 60.0
            evidence.append(f"⚠️ Domain is relatively new ({age_days} days).")
            t2_status = "SUSPICIOUS"
        else:
            t2_score = 10.0
            evidence.append(f"✓ Domain is established ({age_days} days old).")
            t2_status = "OK"
    except Exception as e:
        t2_score = 50.0
        evidence.append("⚠️ Domain analysis failed.")
        t2_status = "ERROR"
        print(f"Domain analysis error: {e}")

    # 3. Tier 3: AI Analysis
    try:
        ai_data = await asyncio.wait_for(tier_3_ai_analysis(request.body), timeout=2.5)
        t3_status = "ANALYZED"
        
        if ai_data.threat_level is not None:
            t3_score = float(ai_data.threat_level)
        else:
            if "Urgency" in ai_data.category or "Financial" in ai_data.category or "Credential" in ai_data.category:
                t3_score = 90.0
            elif "Safe" in ai_data.category:
                t3_score = 10.0
            else:
                t3_score = 50.0
                
        if ai_data.flagged_phrases:
            evidence.append(f"🤖 AI flagged phrases: {', '.join(ai_data.flagged_phrases[:3])}")
        if ai_data.category != "Safe":
            evidence.append(f"🤖 AI Analysis: {ai_data.reasoning}")
            
    except asyncio.TimeoutError:
        ai_data = AIAnalysis(
            threat_level=50,
            category="Unknown", 
            reasoning="Analysis timed out - Proceed with caution.",
            flagged_phrases=[]
        )
        t3_score = 50.0
        t3_status = "TIMEOUT"
        evidence.append("⚠️ AI analysis timed out (2.5s limit).")

    # Final calculation
    final_score = (t1_score * 0.2) + (t2_score * 0.3) + (t3_score * 0.5)
    
    if final_score < 30:
        verdict = "SAFE"
    elif final_score < 70:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CRITICAL"

    tier_details = {
        "t1": {"status": t1_status, "score": round(t1_score, 2)},
        "t2": {"status": t2_status, "score": round(t2_score, 2)},
        "t3": {"status": t3_status, "score": round(t3_score, 2)}
    }

    # Prepare result
    result = {
        "final_score": round(final_score, 2),
        "verdict": verdict,
        "evidence": evidence,
        "tier_details": tier_details,
        "ai_analysis": ai_data.dict()
    }
    
    # Cache the result
    await cache.set_cached_result(request.sender, request.body, result)
    
    return ScanResponse(**result, cached=False)

# --- CACHE MANAGEMENT ENDPOINTS ---

@app.get("/cache/stats")
async def get_cache_stats():
    """Get cache statistics."""
    return await cache.get_stats()

@app.delete("/cache/clear")
async def clear_cache_endpoint():
    """Clear the cache."""
    await cache.clear_cache()
    return {"message": "Cache cleared successfully"}

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "ZeroPhish Backend",
        "cache_stats": await cache.get_stats()
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting ZeroPhish Backend...")
    print("📧 API available at: http://localhost:8000")
    print("📊 Health check: http://localhost:8000/health")
    print("🔧 Cache stats: http://localhost:8000/cache/stats")
    uvicorn.run(app, host="0.0.0.0", port=8000)