# main.py - Speed Layer + Intent Threat Analysis + ML Model Integration
import asyncio
import json
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import whois
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Configure logging FIRST before using logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from security.middleware import (
    InputValidator,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)

# Import ML model and WHOIS client
try:
    from tier_2.ml_model import get_ml_model

    ML_AVAILABLE = True
except ImportError:
    try:
        from ml_model import get_ml_model

        ML_AVAILABLE = True
    except ImportError:
        ML_AVAILABLE = False
        logger.warning("ML model not available (missing torch/transformers)")

try:
    from tier_2.whois_client import get_whois_client

    WHOIS_CLIENT_AVAILABLE = True
except ImportError:
    try:
        from whois_client import get_whois_client

        WHOIS_CLIENT_AVAILABLE = True
    except ImportError:
        WHOIS_CLIENT_AVAILABLE = False
        logger.warning("Enhanced WHOIS client not available")

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
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(
        ","
    )
    if origin.strip() and origin.strip() != "chrome-extension://*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # For security, do not default to allowing all Chrome extensions.
    # To allow a specific extension, set ALLOW_ORIGIN_REGEX to match your
    # extension's origin (e.g., r"chrome-extension://abcdefg...") or add
    # the specific origin to ALLOWED_ORIGINS.
    allow_origin_regex=os.getenv("ALLOW_ORIGIN_REGEX"),
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
    layers_completed: int = 2
    cached: bool = False


def _category_from_verdict(verdict: str | None) -> str:
    value = (verdict or "").strip().upper()
    if value == "CRITICAL":
        return "phishing"
    if value == "SUSPICIOUS":
        return "spam"
    return "safe"


# --- THREAT ANALYSIS LOGIC ---


def _load_threat_patterns() -> Dict[str, List[str]]:
    """Load threat patterns from JSON file."""
    pattern_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_patterns.json")
    try:
        with open(pattern_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load threat patterns from {pattern_file}: {e}")
        return {}


_THREAT_PATTERNS = _load_threat_patterns()


class ThreatAnalyzer:
    """Coordinator engine that delegates to sub-engines (Pattern, OSINT, ML)."""
    
    @classmethod
    async def analyze_threat(
        cls, email_body: str, sender: str, links: List[str], use_ml: bool = True
    ) -> ThreatAnalysis:
        from tier_2.engines import PatternEngine, OSINTEngine, MLEngine
        
        body_lower = email_body.lower()
        sender_lower = (sender or "").lower()

        pattern_engine = PatternEngine(_THREAT_PATTERNS)
        pattern_score, categories, flagged_phrases = pattern_engine.analyze(body_lower, links)
        
        osint_score, osint_flagged = await OSINTEngine.analyze(sender_lower, links)
        flagged_phrases.extend(osint_flagged)
        
        # Base threat from pattern and OSINT
        base_threat = min(100, pattern_score + osint_score)
        
        # Check for combined patterns
        if "Urgency" in categories and ("Financial" in categories or "Credential" in categories):
            base_threat = min(100, base_threat + 20)
        if "Authority" in categories and ("Financial" in categories or "ScareTactics" in categories):
            base_threat = min(100, base_threat + 25)

        if not categories and base_threat < 20:
            category = "Safe"
            reasoning = "No significant threat indicators detected"
        elif not categories:
            category = "GeneralSuspicion"
            reasoning = "Suspicious signals detected but not enough to classify a specific category"
        else:
            category = "/".join(categories[:3])
            reasoning = f"Detected {len(categories)} threat categories: {', '.join(categories)}"

        # Deduplicate phrases
        deduped_phrases = []
        seen = set()
        for phrase in flagged_phrases:
            if phrase not in seen:
                seen.add(phrase)
                deduped_phrases.append(phrase)
        flagged_phrases = deduped_phrases[:10]

        if use_ml:
            base_threat, category, reasoning = await MLEngine.analyze(
                email_body, sender, links, base_threat, category, reasoning
            )

        return ThreatAnalysis(
            threat_level=int(min(100, max(0, round(base_threat)))),
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
            await self.client.set(key, json.dumps(result), ex=86400)  # 24 hour TTL (86400 seconds)

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

# --- WEBSOCKET CONNECTION MANAGER ---

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"🔌 New dashboard connection. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"🔌 Dashboard disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to dashboard: {e}")

manager = ConnectionManager()

# Store latest scan for /tier1/latest endpoint
latest_scan_result: Optional[Dict] = None
latest_scan_lock = asyncio.Lock()

# --- DOMAIN ANALYSIS ---


def analyze_domain_age(age_days: int) -> Tuple[float, str, str]:
    """Analyze domain age and return (score, status, evidence_message)."""
    if age_days == 0:
        return 70.0, "UNKNOWN", "Could not verify domain age."
    elif age_days < 30:
        return 100.0, "CRITICAL", f"Domain is very new ({age_days} days old)."
    elif age_days < 365:
        return 60.0, "SUSPICIOUS", f"Domain is relatively new ({age_days} days old)."
    else:
        return 10.0, "OK", f"Domain is established ({age_days} days old)."


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
    validation = InputValidator.validate_scan_request(
        sender=request.sender,
        body=request.body,
        links=request.links,
    )
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail={"errors": validation["errors"]})

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

        domain_score, domain_status, msg = analyze_domain_age(age_days)
        if domain_status == "UNKNOWN":
            evidence.append(f"⚠️ {msg}")
        elif domain_status == "CRITICAL":
            evidence.append(f"🚨 {msg}")
        elif domain_status == "SUSPICIOUS":
            evidence.append(f"⚠️ {msg}")
        else:
            evidence.append(f"✓ {msg}")
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
            "Scam": "Appears to be a scam or fraudulent message",
        }

        friendly_message = category_messages.get(
            threat_data.category, f"Suspicious patterns detected ({threat_data.category})"
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
            "subject": getattr(request, "subject", "No Subject"),
            "final_score": round(final_score, 2),
            "verdict": verdict,
            "evidence": evidence,
            "threat_analysis": threat_data.dict(),
            "tier_details": tier_details,
        }

    # Cache the result (Speed Layer)
    await cache.set_cached_result(request.sender, request.body, result)

    # Broadcast update to connected dashboards via WebSocket
    await manager.broadcast({
        "type": "scan_update",
        "data": latest_scan_result
    })

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


@app.websocket("/tier1/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await manager.connect(websocket)
    try:
        # Send initial status
        await websocket.send_json({"type": "connection_status", "status": "connected"})
        
        # Send latest scan if available
        async with latest_scan_lock:
            if latest_scan_result:
                await websocket.send_json({
                    "type": "scan_update",
                    "data": latest_scan_result
                })
                
        while True:
            # Keep connection alive and wait for client messages
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                command = msg.get("command")
                
                if command == "resolve_threat":
                    # Mark as false positive or resolved
                    sender = msg.get("sender")
                    body = msg.get("body")
                    if sender and body:
                        key = cache._generate_key(sender, body)
                        # Option 1: Delete from cache to allow re-scan
                        # Option 2: Overwrite with safe status
                        await cache.client.delete(key)
                        logger.info(f"🛡️ Threat resolved by analyst: {sender}")
                        await websocket.send_json({
                            "type": "command_receipt",
                            "status": "success",
                            "message": "Threat resolved and cache cleared."
                        })
            except Exception as e:
                logger.error(f"WebSocket command error: {e}")
                # Simple echo fallback for non-JSON or other errors
                logger.info(f"Received dashboard data: {data}")
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@app.post("/tier1/report")
async def receive_extension_report(report: Dict):
    """Receive scan reports from Chrome extension."""
    try:
        async with latest_scan_lock:
            global latest_scan_result

            verdict = str(report.get("verdict", "SAFE"))
            mapped_category = _category_from_verdict(verdict)
            tier_details = (
                report.get("tier_details", {})
                if isinstance(report.get("tier_details"), dict)
                else {}
            )
            tier1_details = (
                tier_details.get("tier1", {}) if isinstance(tier_details.get("tier1"), dict) else {}
            )
            tier2_details = (
                tier_details.get("tier2", {}) if isinstance(tier_details.get("tier2"), dict) else {}
            )
            nested_threat = (
                tier_details.get("threat_analysis", {})
                if isinstance(tier_details.get("threat_analysis"), dict)
                else {}
            )
            heuristics_score = tier1_details.get("score")
            ml_threat_level = tier2_details.get("score")
            if ml_threat_level is None:
                ml_threat_level = nested_threat.get("score")

            raw_evidence = report.get("evidence", [])
            normalized_evidence = []
            if isinstance(raw_evidence, list):
                for item in raw_evidence:
                    if isinstance(item, dict):
                        normalized_evidence.append(
                            {
                                "check": str(item.get("check", "extension")),
                                "detail": str(item.get("detail", item.get("check", "signal"))),
                                "kind": item.get("kind"),
                                "points": (
                                    item.get("points")
                                    if isinstance(item.get("points"), (int, float))
                                    else None
                                ),
                            }
                        )
                    else:
                        normalized_evidence.append(
                            {
                                "check": "extension",
                                "detail": str(item),
                                "kind": None,
                                "points": None,
                            }
                        )

            raw_links = report.get("links", [])
            normalized_links = []
            if isinstance(raw_links, list):
                for link in raw_links:
                    if isinstance(link, dict):
                        href = str(link.get("href", "")).strip()
                        text = link.get("text")
                    else:
                        href = str(link).strip()
                        text = None

                    if href:
                        normalized_links.append(
                            {"href": href, "text": text if isinstance(text, str) else None}
                        )

            reason_list = report.get("reasons")
            if not isinstance(reason_list, list):
                reason_list = [e.get("detail", "") for e in normalized_evidence if e.get("detail")]

            # --- DEEP FORENSICS ENRICHMENT ---
            from tier_2.engines import EMLEngine
            from vision.service import VisionService
            
            eml_data = await EMLEngine.analyze_eml(report.get("body", ""))
            dom_data = VisionService.analyze_dom_fingerprint(report.get("dom", ""))
            
            # Transform to match frontend Tier1Report format
            latest_scan_result = {
                "version": 1,
                "event_id": report.get("event_id", f"evt_{datetime.now().timestamp()}"),
                "scan_id": report.get("scan_id", f"ext_{datetime.now().timestamp()}"),
                "created_at": report.get("timestamp", datetime.now().isoformat()),
                "source": "extension",
                "email": {
                    "subject": report.get("subject", "No Subject"),
                    "senderEmail": report.get("sender", "unknown@unknown.com"),
                    "senderName": None,
                },
                "links": normalized_links,
                "tier1": {
                    "score": report.get("final_score", 0),
                    "category": mapped_category,
                    "summary": f"Scan complete: {verdict}",
                    "evidence": normalized_evidence,
                    "reasons": reason_list,
                    "heuristics_score": heuristics_score,
                    "ml_enabled": True,
                    "ml_threat_level": ml_threat_level,
                    "ml_category": mapped_category,
                    "ml_confidence": None,
                    "ml_label": verdict,
                    "ml_model": "ZeroPhish 3-Tier",
                    "ml_reasoning": report.get("threat_analysis", {}).get("reasoning", ""),
                    "dom_fingerprint": dom_data,
                    "eml_forensics": eml_data
                },
                "layers_completed": report.get("layers_completed", report.get("layers", 1)),
            }

        logger.info(f"✅ Received extension report: {latest_scan_result['scan_id']}")
        
        # Broadcast via WebSocket
        await manager.broadcast({
            "type": "scan_update",
            "data": latest_scan_result
        })
        
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
