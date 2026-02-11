# main.py - Speed Layer + Intent Threat Analysis
import os
import asyncio
import json
import whois
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Redis imports
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("⚠️ Redis not available, using in-memory fallback")

# --- INITIALIZATION ---
app = FastAPI(title="ZeroPhish Backend")

# CORS for Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATA MODELS ---
class ScanRequest(BaseModel):
    sender: str
    body: str
    links: List[str]

class ThreatAnalysis(BaseModel):
    threat_level: int
    category: str
    reasoning: str
    flagged_phrases: List[str]

class ScanResponse(BaseModel):
    final_score: float
    verdict: str
    evidence: List[str]
    tier_details: dict
    threat_analysis: ThreatAnalysis
    cached: bool = False

# --- THREAT ANALYSIS LOGIC ---

class ThreatAnalyzer:
    """Local threat analysis engine (no external AI)"""
    
    # Threat patterns database
    URGENCY_PATTERNS = [
        "urgent", "immediately", "asap", "right away", "deadline", "expire",
        "last chance", "limited time", "act now", "don't delay", "emergency",
        "urgent action", "immediate attention", "time sensitive"
    ]
    
    FINANCIAL_PATTERNS = [
        "money", "payment", "invoice", "bank", "wire", "transfer", "account",
        "fund", "cash", "credit", "debit", "refund", "prize", "lottery",
        "inheritance", "million", "billion", "dollar", "euro", "pound"
    ]
    
    CREDENTIAL_PATTERNS = [
        "password", "login", "verify", "confirm", "account", "security",
        "update", "authenticate", "validate", "credentials", "username",
        "sign in", "log in", "access", "reset", "change password"
    ]
    
    AUTHORITY_PATTERNS = [
        "irs", "tax", "government", "police", "fbi", "court", "legal",
        "official", "authority", "administration", "department", "agency",
        "ceo", "manager", "director", "president", "executive"
    ]
    
    SCARE_TACTICS = [
        "suspend", "terminate", "locked", "blocked", "compromised",
        "unauthorized", "breach", "hacked", "security alert", "warning",
        "violation", "penalty", "fine", "arrest", "lawsuit"
    ]
    
    SUSPICIOUS_URLS = [
        "bit.ly", "tinyurl", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "shorte.st", "bc.vc", "adfly", "bitly", "shorturl"
    ]
    
    @classmethod
    def analyze_threat(cls, email_body: str, sender: str, links: List[str]) -> ThreatAnalysis:
        """Analyze email for threat indicators using local logic."""
        body_lower = email_body.lower()
        
        # Initialize counters
        urgency_score = 0
        financial_score = 0
        credential_score = 0
        authority_score = 0
        scare_score = 0
        link_score = 0
        
        flagged_phrases = []
        
        # Check for urgency patterns
        for pattern in cls.URGENCY_PATTERNS:
            if pattern in body_lower:
                urgency_score += 10
                flagged_phrases.append(pattern)
        
        # Check for financial patterns
        for pattern in cls.FINANCIAL_PATTERNS:
            if pattern in body_lower:
                financial_score += 8
                flagged_phrases.append(pattern)
        
        # Check for credential patterns
        for pattern in cls.CREDENTIAL_PATTERNS:
            if pattern in body_lower:
                credential_score += 7
                flagged_phrases.append(pattern)
        
        # Check for authority impersonation
        for pattern in cls.AUTHORITY_PATTERNS:
            if pattern in body_lower:
                authority_score += 9
                flagged_phrases.append(pattern)
        
        # Check for scare tactics
        for pattern in cls.SCARE_TACTICS:
            if pattern in body_lower:
                scare_score += 8
                flagged_phrases.append(pattern)
        
        # Check for suspicious URLs
        for link in links:
            for suspicious in cls.SUSPICIOUS_URLS:
                if suspicious in link.lower():
                    link_score += 15
                    flagged_phrases.append(f"suspicious_url:{suspicious}")
                    break
        
        # Calculate threat level (0-100)
        base_threat = min(100, urgency_score + financial_score + credential_score + 
                         authority_score + scare_score + link_score)
        
        # Check for combined patterns (higher risk)
        if urgency_score > 0 and (financial_score > 0 or credential_score > 0):
            base_threat = min(100, base_threat + 20)
        
        if authority_score > 0 and (financial_score > 0 or scare_score > 0):
            base_threat = min(100, base_threat + 25)
        
        # Determine category
        categories = []
        if urgency_score >= 20: categories.append("Urgency")
        if financial_score >= 15: categories.append("Financial")
        if credential_score >= 15: categories.append("Credential")
        if authority_score >= 10: categories.append("Authority")
        if scare_score >= 15: categories.append("ScareTactics")
        
        if not categories:
            category = "Safe"
            reasoning = "No significant threat indicators detected"
        else:
            category = "/".join(categories[:3])  # Max 3 categories
            reasoning = f"Detected {len(categories)} threat categories: {', '.join(categories)}"
        
        # Deduplicate flagged phrases
        flagged_phrases = list(set(flagged_phrases))[:10]  # Limit to 10
        
        return ThreatAnalysis(
            threat_level=base_threat,
            category=category,
            reasoning=reasoning,
            flagged_phrases=flagged_phrases
        )

# --- SPEED LAYER (REDIS) ---

class SpeedLayerCache:
    """Speed Layer with Redis for high-performance caching."""
    
    def __init__(self, redis_url: str = None):
        # Load Redis URL from environment or use default
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.client = None
        self.ttl = 300  # 5 minutes cache
        
    async def connect(self):
        """Connect to Redis."""
        if not REDIS_AVAILABLE:
            print("⚠️ Redis client not available, using fallback")
            self.client = None
            return False
        
        try:
            self.client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=2,
                socket_connect_timeout=2
            )
            await self.client.ping()
            print("✅ Redis cache connected")
            return True
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            self.client = None
            return False
    
    async def disconnect(self):
        """Disconnect from Redis."""
        if self.client:
            await self.client.close()
    
    def _generate_key(self, sender: str, body: str) -> str:
        """Generate cache key."""
        import hashlib
        content = f"{sender}:{body[:500]}"  # First 500 chars for hash
        hash_obj = hashlib.md5(content.encode())
        return f"scan:{hash_obj.hexdigest()}"
    
    async def get_cached_result(self, sender: str, body: str) -> Optional[Dict]:
        """Get cached result from Redis."""
        if not self.client:
            return None
        
        try:
            key = self._generate_key(sender, body)
            cached_data = await self.client.get(key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            print(f"Cache read error: {e}")
        
        return None
    
    async def set_cached_result(self, sender: str, body: str, result: Dict):
        """Cache result in Redis."""
        if not self.client:
            return
        
        try:
            key = self._generate_key(sender, body)
            result_with_meta = {
                **result,
                "_cached_at": datetime.now().isoformat(),
                "_ttl": self.ttl
            }
            
            await self.client.setex(
                key,
                self.ttl,
                json.dumps(result_with_meta)
            )
            
            # Update recent scans list
            await self.client.lpush("recent_scans", key)
            await self.client.ltrim("recent_scans", 0, 99)  # Keep last 100
        except Exception as e:
            print(f"Cache write error: {e}")
    
    async def get_stats(self) -> Dict:
        """Get Redis cache statistics."""
        if not self.client:
            return {"status": "disconnected", "backend": "none"}
        
        try:
            info = await self.client.info()
            return {
                "status": "connected",
                "backend": "redis",
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_human": info.get("used_memory_human", "0"),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0)
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def clear_cache(self):
        """Clear all scan cache."""
        if not self.client:
            return {"message": "No Redis connection"}
        
        try:
            keys = await self.client.keys("scan:*")
            if keys:
                await self.client.delete(*keys)
            return {"message": f"Cleared {len(keys)} cache entries"}
        except Exception as e:
            return {"message": f"Cache clear error: {str(e)}"}

# Initialize speed layer
cache = SpeedLayerCache()

# --- DOMAIN ANALYSIS ---

def get_domain_age(domain: str) -> int:
    """Tier 2: WHOIS Check. Returns age in days."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not creation_date:
            return 0
        
        # Handle timezone-aware and timezone-naive datetimes
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            # If creation_date is naive, assume UTC
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        age = (now - creation_date).days
        return age
    except Exception as e:
        # Log the error for debugging but return 0 to continue processing
        print(f"WHOIS lookup failed for {domain}: {e}")
        return 0

# --- EVENT HANDLERS ---

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    await cache.connect()
    print("✅ ZeroPhish Backend started")
    print("📊 Speed Layer: Redis")
    print("🧠 Threat Analysis: Local Engine")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await cache.disconnect()

# --- CORE ENDPOINT ---

@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """Scan email for phishing using speed layer + local threat analysis."""
    # Check cache first (Speed Layer)
    cached_result = await cache.get_cached_result(request.sender, request.body)
    
    if cached_result:
        # Remove metadata before returning
        cached_result.pop("_cached_at", None)
        cached_result.pop("_ttl", None)
        
        # Convert threat_analysis dict to model
        if "threat_analysis" in cached_result:
            cached_result["threat_analysis"] = ThreatAnalysis(**cached_result["threat_analysis"])
        
        cached_result["evidence"].append("⚡ Served from Redis cache")
        
        return ScanResponse(**cached_result, cached=True)
    
    # If not cached, perform full analysis
    evidence = []
    
    # 1. Domain Analysis (Tier 2)
    domain_score = 0
    domain_status = "OK"
    
    try:
        domain = request.sender.split("@")[-1]
        age_days = await asyncio.to_thread(get_domain_age, domain)
        
        if age_days == 0:
            domain_score = 70
            evidence.append("⚠️ Could not verify domain age.")
            domain_status = "UNKNOWN"
        elif age_days < 30:
            domain_score = 100
            evidence.append(f"🚨 Domain is very young ({age_days} days).")
            domain_status = "CRITICAL"
        elif age_days < 365:
            domain_score = 60
            evidence.append(f"⚠️ Domain is relatively new ({age_days} days).")
            domain_status = "SUSPICIOUS"
        else:
            domain_score = 10
            evidence.append(f"✓ Domain is established ({age_days} days old).")
            domain_status = "OK"
    except Exception as e:
        domain_score = 50
        evidence.append("⚠️ Domain analysis failed.")
        domain_status = "ERROR"
    
    # 2. Local Threat Analysis (Tier 3)
    threat_data = ThreatAnalyzer.analyze_threat(
        email_body=request.body,
        sender=request.sender,
        links=request.links
    )
    
    threat_score = threat_data.threat_level
    threat_status = "CRITICAL" if threat_score >= 70 else "SUSPICIOUS" if threat_score >= 40 else "OK"
    
    # Add threat evidence
    if threat_data.category != "Safe":
        evidence.append(f"🔍 Threat detected: {threat_data.category}")
    
    if threat_data.flagged_phrases:
        evidence.append(f"🚩 Flagged phrases: {', '.join(threat_data.flagged_phrases[:3])}")
    
    # 3. Calculate final score (Domain 30%, Threat 70%)
    final_score = (domain_score * 0.3) + (threat_score * 0.7)
    
    # Determine verdict
    if final_score < 30:
        verdict = "SAFE"
    elif final_score < 70:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CRITICAL"
    
    # Prepare tier details
    tier_details = {
        "domain_analysis": {
            "status": domain_status,
            "score": round(domain_score, 2),
            "weight": 0.3
        },
        "threat_analysis": {
            "status": threat_status,
            "score": round(threat_score, 2),
            "weight": 0.7
        }
    }
    
    # Prepare result
    result = {
        "final_score": round(final_score, 2),
        "verdict": verdict,
        "evidence": evidence,
        "tier_details": tier_details,
        "threat_analysis": threat_data.dict()
    }
    
    # Cache the result (Speed Layer)
    await cache.set_cached_result(request.sender, request.body, result)
    
    return ScanResponse(**result, cached=False)

# --- CACHE MANAGEMENT ENDPOINTS ---

@app.get("/cache/stats")
async def get_cache_stats():
    """Get Redis cache statistics."""
    return await cache.get_stats()

@app.delete("/cache/clear")
async def clear_cache_endpoint():
    """Clear the Redis cache."""
    result = await cache.clear_cache()
    return result

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    cache_stats = await cache.get_stats()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "ZeroPhish Backend",
        "version": "1.0.0",
        "features": {
            "speed_layer": "Redis" if cache.client else "None",
            "threat_analysis": "Local Engine",
            "domain_check": "WHOIS"
        },
        "cache": cache_stats
    }

# --- THREAT PATTERN MANAGEMENT ---

@app.get("/threat/patterns")
async def get_threat_patterns():
    """Get all threat patterns used by the analyzer."""
    return {
        "urgency_patterns": ThreatAnalyzer.URGENCY_PATTERNS,
        "financial_patterns": ThreatAnalyzer.FINANCIAL_PATTERNS,
        "credential_patterns": ThreatAnalyzer.CREDENTIAL_PATTERNS,
        "authority_patterns": ThreatAnalyzer.AUTHORITY_PATTERNS,
        "scare_tactics": ThreatAnalyzer.SCARE_TACTICS,
        "suspicious_urls": ThreatAnalyzer.SUSPICIOUS_URLS
    }

# --- RUN SERVER ---

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting ZeroPhish Backend...")
    print("📧 API: http://localhost:8000")
    print("🏥 Health: http://localhost:8000/health")
    print("📊 Cache: http://localhost:8000/cache/stats")
    print("🔧 Threat Patterns: http://localhost:8000/threat/patterns")
    print("=" * 50)
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")