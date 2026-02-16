# main.py - Speed Layer + Intent Threat Analysis + ML Model Integration
import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import whois
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Configure logging FIRST before using logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from security.middleware import (
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    InputValidator,
    sanitize_email_content,
)

# Import ML model and WHOIS client
try:
    from ml_model import get_ml_model
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("⚠️ ML model not available (missing torch/transformers)")

try:
    from whois_client import get_whois_client
    WHOIS_CLIENT_AVAILABLE = True
except ImportError:
    WHOIS_CLIENT_AVAILABLE = False
    logger.warning("⚠️ Enhanced WHOIS client not available")

# Load environment variables
load_dotenv()

# Redis imports
try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("⚠️ Redis not available, using in-memory fallback")

# --- INITIALIZATION ---


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan (startup/shutdown)."""
    # Startup
    await cache.connect()
    
    # Load ML model if available
    if ML_AVAILABLE and os.getenv("ML_ENABLED", "true").lower() == "true":
        try:
            ml_model = await get_ml_model()
            logger.info("✅ ML model loaded successfully")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load ML model: {e}")
    
    # Initialize WHOIS client
    if WHOIS_CLIENT_AVAILABLE:
        try:
            whois_client = await get_whois_client(cache_client=cache.client)
            logger.info("✅ Enhanced WHOIS client initialized")
        except Exception as e:
            logger.warning(f"⚠️ Failed to initialize WHOIS client: {e}")
    
    logger.info("✅ ZeroPhish Backend started")
    logger.info("📊 Speed Layer: Redis")
    logger.info(f"🧠 Threat Analysis: {'ML + Patterns' if ML_AVAILABLE else 'Patterns Only'}")

    yield

    # Shutdown
    await cache.disconnect()
    logger.info("🛑 ZeroPhish Backend shutting down")


app = FastAPI(title="ZeroPhish Backend", lifespan=lifespan)

# Security Middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size=1_000_000)  # 1MB limit

# CORS Configuration - Environment-based
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,chrome-extension://*").split(
    ","
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
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
        "urgent",
        "immediately",
        "asap",
        "right away",
        "deadline",
        "expire",
        "last chance",
        "limited time",
        "act now",
        "don't delay",
        "emergency",
        "urgent action",
        "immediate attention",
        "time sensitive",
    ]

    FINANCIAL_PATTERNS = [
        "money",
        "payment",
        "invoice",
        "bank",
        "wire",
        "transfer",
        "account",
        "fund",
        "cash",
        "credit",
        "debit",
        "refund",
        "prize",
        "lottery",
        "inheritance",
        "million",
        "billion",
        "dollar",
        "euro",
        "pound",
    ]

    CREDENTIAL_PATTERNS = [
        "password",
        "login",
        "verify",
        "confirm",
        "account",
        "security",
        "update",
        "authenticate",
        "validate",
        "credentials",
        "username",
        "sign in",
        "log in",
        "access",
        "reset",
        "change password",
    ]

    AUTHORITY_PATTERNS = [
        "irs",
        "tax",
        "government",
        "police",
        "fbi",
        "court",
        "legal",
        "official",
        "authority",
        "administration",
        "department",
        "agency",
        "ceo",
        "manager",
        "director",
        "president",
        "executive",
    ]

    SCARE_TACTICS = [
        "suspend",
        "terminate",
        "locked",
        "blocked",
        "compromised",
        "unauthorized",
        "breach",
        "hacked",
        "security alert",
        "warning",
        "violation",
        "penalty",
        "fine",
        "arrest",
        "lawsuit",
    ]

    SUSPICIOUS_URLS = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "shorte.st",
        "bc.vc",
        "adfly",
        "bitly",
        "shorturl",
    ]

    @classmethod
    async def analyze_threat(
        cls, email_body: str, sender: str, links: List[str], use_ml: bool = True
    ) -> ThreatAnalysis:
        """Analyze email for threat indicators using patterns + ML."""
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
        base_threat = min(
            100,
            urgency_score
            + financial_score
            + credential_score
            + authority_score
            + scare_score
            + link_score,
        )

        # Check for combined patterns (higher risk)
        if urgency_score > 0 and (financial_score > 0 or credential_score > 0):
            base_threat = min(100, base_threat + 20)

        if authority_score > 0 and (financial_score > 0 or scare_score > 0):
            base_threat = min(100, base_threat + 25)

        # Determine category
        categories = []
        if urgency_score >= 20:
            categories.append("Urgency")
        if financial_score >= 15:
            categories.append("Financial")
        if credential_score >= 15:
            categories.append("Credential")
        if authority_score >= 10:
            categories.append("Authority")
        if scare_score >= 15:
            categories.append("ScareTactics")

        if not categories:
            category = "Safe"
            reasoning = "No significant threat indicators detected"
        else:
            category = "/".join(categories[:3])  # Max 3 categories
            reasoning = f"Detected {len(categories)} threat categories: {', '.join(categories)}"

        # Deduplicate flagged phrases
        flagged_phrases = list(set(flagged_phrases))[:10]  # Limit to 10

        # ML Enhancement (if available and enabled)
        ml_score = None
        ml_confidence = None
        
        if use_ml and ML_AVAILABLE and os.getenv("ML_ENABLED", "true").lower() == "true":
            try:
                ml_model = await get_ml_model()
                if ml_model.is_loaded():
                    ml_score, ml_confidence = await ml_model.predict(email_body)
                    logger.debug(f"ML prediction: score={ml_score:.2f}, confidence={ml_confidence}")
                    
                    # Combine ML score (60%) + pattern score (40%)
                    combined_threat = (ml_score * 0.6) + (base_threat * 0.4)
                    
                    # Update category if ML provides stronger signal
                    if ml_confidence == "phishing" and "ML:Phishing" not in category:
                        category = f"{category}/ML:Phishing" if category != "Safe" else "ML:Phishing"
                    
                    # Update reasoning
                    reasoning = f"{reasoning}. ML confidence: {ml_confidence} ({ml_score:.1f}%)"
                    
                    # Use combined score
                    base_threat = combined_threat
            except Exception as e:
                logger.warning(f"ML inference failed: {e}")

        return ThreatAnalysis(
            threat_level=int(base_threat),
            category=category,
            reasoning=reasoning,
            flagged_phrases=flagged_phrases,
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
                self.redis_url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2
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
        """Generate cache key using SHA-256."""
        import hashlib

        content = f"{sender}:{body[:500]}"  # First 500 chars for hash
        hash_obj = hashlib.sha256(content.encode())
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
            logger.error(f"Cache read error: {e}")

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
                "_ttl": self.ttl,
            }

            await self.client.setex(key, self.ttl, json.dumps(result_with_meta))

            # Update recent scans list
            await self.client.lpush("recent_scans", key)
            await self.client.ltrim("recent_scans", 0, 99)  # Keep last 100
        except Exception as e:
            logger.error(f"Cache write error: {e}")

    async def cache_result(self, sender: str, body: str, result: Dict) -> None:
        """Cache scan result with 24-hour TTL."""
        if not REDIS_AVAILABLE or not self.client:
            return

        try:
            key = self._generate_key(sender, body)
            await self.client.set(
                key,
                json.dumps(result),
                ex=86400  # 24 hour TTL (86400 seconds)
            )

            # Track recent scans
            await self.client.lpush("recent_scans", key)
            await self.client.ltrim("recent_scans", 0, 99)  # Keep last 100
        except Exception as e:
            logger.error(f"Cache write error: {e}")

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
                "keyspace_misses": info.get("keyspace_misses", 0),
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

# Store latest scan for /tier1/latest endpoint
latest_scan_result: Optional[Dict] = None
latest_scan_lock = asyncio.Lock()

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
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return 0


# Event handlers moved to lifespan context manager above

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

    # 1. Domain Analysis (Tier 2) - Use enhanced WHOIS client if available
    domain_score = 0
    domain_status = "OK"

    try:
        domain = request.sender.split("@")[-1]
        
        # Try enhanced WHOIS client first
        if WHOIS_CLIENT_AVAILABLE:
            whois_client = await get_whois_client(cache_client=cache.client)
            age_days, source = await whois_client.get_domain_age(domain)
            logger.debug(f"Domain age from {source}: {age_days} days")
        else:
            # Fallback to basic WHOIS
            age_days = await asyncio.to_thread(get_domain_age, domain)
            source = "library"

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
        logger.error(f"Domain analysis failed: {e}", exc_info=True)
        domain_score = 50
        evidence.append(f"⚠️ Domain analysis failed: {type(e).__name__}")
        domain_status = "ERROR"

    # 2. Local Threat Analysis (Tier 3) - Now with ML enhancement
    threat_data = await ThreatAnalyzer.analyze_threat(
        email_body=request.body, sender=request.sender, links=request.links
    )

    threat_score = threat_data.threat_level
    threat_status = (
        "CRITICAL" if threat_score >= 70 else "SUSPICIOUS" if threat_score >= 40 else "OK"
    )

    # Add threat evidence
    if threat_data.category != "Safe":
        # User-friendly threat category messages
        category_messages = {
            "Credential": "Requests login credentials or personal information",
            "ScareTactics": "Uses urgency or fear to pressure action",
            "Credential/ScareTactics": "Combines credential theft with urgency tactics (high risk)",
            "Financial": "Requests payment or financial information",
            "Impersonation": "Impersonates a trusted organization",
            "Malware": "May contain malicious software or links",
            "Scam": "Appears to be a scam or fraudulent message"
        }
        
        friendly_message = category_messages.get(
            threat_data.category,
            f"Suspicious patterns detected ({threat_data.category})"
        )
        evidence.append(f"🔍 {friendly_message}")

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
            "weight": 0.3,
        },
        "threat_analysis": {
            "status": threat_status,
            "score": round(threat_score, 2),
            "weight": 0.7,
        },
    }

    # Prepare result
    result = {
        "final_score": round(final_score, 2),
        "verdict": verdict,
        "evidence": evidence,
        "tier_details": tier_details,
        "threat_analysis": threat_data.dict(),
    }

    # Store as latest scan for frontend dashboard
    async with latest_scan_lock:
        global latest_scan_result
        latest_scan_result = {
            "scan_id": f"scan_{datetime.now().timestamp()}",
            "timestamp": datetime.now().isoformat(),
            "sender": request.sender,
            "subject": getattr(request, 'subject', 'No Subject'),
            "final_score": round(final_score, 2),
            "verdict": verdict,
            "evidence": evidence,
            "threat_analysis": threat_data.dict(),
            "tier_details": tier_details,
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
            "domain_check": "WHOIS",
        },
        "cache": cache_stats,
    }


# --- FRONTEND DASHBOARD ENDPOINTS ---


@app.get("/tier1/latest")
async def get_latest_scan():
    """Get the latest scan result for frontend dashboard."""
    async with latest_scan_lock:
        if latest_scan_result is None:
            return None
        return latest_scan_result


@app.get("/tier1/stream")
async def stream_scans():
    """Server-Sent Events stream for real-time scan updates."""
    
    async def event_generator():
        """Generate SSE events for scan updates."""
        # Send initial ping
        yield f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
        
        last_scan_id = None
        
        while True:
            try:
                # Check for new scans
                async with latest_scan_lock:
                    if latest_scan_result and latest_scan_result.get("scan_id") != last_scan_id:
                        last_scan_id = latest_scan_result.get("scan_id")
                        # Send new scan data
                        yield f"data: {json.dumps(latest_scan_result)}\n\n"
                
                # Send periodic ping to keep connection alive
                await asyncio.sleep(5)
                yield f"event: ping\ndata: {json.dumps({'status': 'alive'})}\n\n"
                
            except Exception as e:
                logger.error(f"SSE stream error: {e}")
                break
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@app.post("/tier1/report")
async def receive_extension_report(report: Dict):
    """Receive scan reports from Chrome extension."""
    try:
        async with latest_scan_lock:
            global latest_scan_result
            
            # Transform to match frontend Tier1Report format
            latest_scan_result = {
                "version": 1,
                "scan_id": report.get("scan_id", f"ext_{datetime.now().timestamp()}"),
                "created_at": report.get("timestamp", datetime.now().isoformat()),
                "source": "extension",
                "email": {
                    "subject": report.get("subject", "No Subject"),
                    "senderEmail": report.get("sender", "unknown@unknown.com"),
                    "senderName": None
                },
                "links": [],
                "tier1": {
                    "score": report.get("final_score", 0),
                    "category": report.get("verdict", "SAFE").lower(),
                    "summary": f"Scan complete: {report.get('verdict', 'SAFE')}",
                    "evidence": [
                        {"check": "extension", "detail": str(e)} 
                        for e in (report.get("evidence", []) if isinstance(report.get("evidence"), list) else [])
                    ],
                    "reasons": report.get("evidence", []) if isinstance(report.get("evidence"), list) else [],
                    "heuristics_score": report.get("tier_details", {}).get("tier1", {}).get("score"),
                    "ml_enabled": True,
                    "ml_threat_level": report.get("tier_details", {}).get("tier2", {}).get("score"),
                    "ml_category": report.get("verdict", "SAFE").lower(),
                    "ml_confidence": None,
                    "ml_label": report.get("verdict", "SAFE"),
                    "ml_model": "ZeroPhish 3-Tier",
                    "ml_reasoning": report.get("threat_analysis", {}).get("reasoning", "")
                }
            }
        
        logger.info(f"✅ Received extension report: {latest_scan_result['scan_id']}")
        return {"status": "success", "message": "Report received"}
    
    except Exception as e:
        logger.error(f"❌ Failed to process extension report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
        "suspicious_urls": ThreatAnalyzer.SUSPICIOUS_URLS,
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
