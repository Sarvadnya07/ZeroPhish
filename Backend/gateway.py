"""
ZeroPhish API Gateway
Orchestrates Tier 1 (client), Tier 2 (metadata), and Tier 3 (AI) analysis
with weighted scoring: Final Score = (T1 × 0.2) + (T2 × 0.3) + (T3 × 0.5)
"""

import os
import sys
import asyncio
import time
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import models
from models.gateway_models import (
    GatewayScanRequest,
    GatewayScanResponse,
    ScanStatusResponse,
    Tier1Result,
    Tier2Result,
    Tier3Result,
    ScoringWeights,
    DomainAnalysis,
    Tier2Analysis,
    ThreatAnalysisDetail
)

# Import Tier 2 functions
from tier_2.main import ThreatAnalyzer, get_domain_age

# Import Tier 3 function
from tier_3.main import analyze_email_intent

# Load environment variables
load_dotenv()

# ============================================================================
# INITIALIZATION
# ============================================================================

app = FastAPI(
    title="ZeroPhish API Gateway",
    description="Unified gateway orchestrating 3-tier phishing detection",
    version="1.0.0"
)

# CORS for Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for async scan results
scan_results: Dict[str, GatewayScanResponse] = {}

# Configuration
TIER3_TIMEOUT = int(os.getenv("TIER3_TIMEOUT", "5"))  # seconds
WEIGHTS = ScoringWeights()

# ============================================================================
# TIER 2 INTEGRATION
# ============================================================================

async def execute_tier2(sender: str, body: str, links: list) -> Tier2Result:
    """Execute Tier 2: Metadata and pattern analysis"""
    start_time = time.time()
    
    try:
        # Domain Analysis
        domain = sender.split("@")[-1]
        age_days = await asyncio.to_thread(get_domain_age, domain)
        
        if age_days == 0:
            domain_score = 70
            domain_status = "UNKNOWN"
        elif age_days < 30:
            domain_score = 100
            domain_status = "CRITICAL"
        elif age_days < 365:
            domain_score = 60
            domain_status = "SUSPICIOUS"
        else:
            domain_score = 10
            domain_status = "OK"
        
        # Threat Pattern Analysis
        threat_data = ThreatAnalyzer.analyze_threat(
            email_body=body,
            sender=sender,
            links=links
        )
        
        threat_score = threat_data.threat_level
        threat_status = "CRITICAL" if threat_score >= 70 else "SUSPICIOUS" if threat_score >= 40 else "OK"
        
        # Combined Tier 2 score (Domain 30%, Threat 70%)
        tier2_score = (domain_score * 0.3) + (threat_score * 0.7)
        
        # Evidence
        evidence = []
        if domain_status == "CRITICAL":
            evidence.append(f"🚨 Domain is very young ({age_days} days)")
        elif domain_status == "SUSPICIOUS":
            evidence.append(f"⚠️ Domain is relatively new ({age_days} days)")
        elif domain_status == "OK":
            evidence.append(f"✓ Domain is established ({age_days} days)")
        else:
            evidence.append("⚠️ Could not verify domain age")
        
        if threat_data.category != "Safe":
            evidence.append(f"🔍 Threat detected: {threat_data.category}")
        
        execution_time = (time.time() - start_time) * 1000
        
        return Tier2Result(
            score=tier2_score,
            domain_analysis=DomainAnalysis(
                status=domain_status,
                score=domain_score,
                weight=0.3
            ),
            threat_analysis=Tier2Analysis(
                status=threat_status,
                score=threat_score,
                weight=0.7
            ),
            threat_details=ThreatAnalysisDetail(
                threat_level=threat_data.threat_level,
                category=threat_data.category,
                reasoning=threat_data.reasoning,
                flagged_phrases=threat_data.flagged_phrases
            ),
            evidence=evidence,
            execution_time_ms=execution_time
        )
        
    except Exception as e:
        print(f"Tier 2 error: {e}")
        # Fallback
        return Tier2Result(
            score=50,
            domain_analysis=DomainAnalysis(status="ERROR", score=50),
            threat_analysis=Tier2Analysis(status="ERROR", score=50),
            threat_details=ThreatAnalysisDetail(
                threat_level=50,
                category="Error",
                reasoning="Tier 2 analysis failed",
                flagged_phrases=[]
            ),
            evidence=["⚠️ Tier 2 analysis encountered an error"],
            execution_time_ms=(time.time() - start_time) * 1000
        )

# ============================================================================
# TIER 3 INTEGRATION
# ============================================================================

async def execute_tier3(body: str) -> Tier3Result:
    """Execute Tier 3: AI semantic analysis"""
    start_time = time.time()
    
    try:
        # Check if Gemini API key is configured
        if not os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY") == "your_actual_gemini_api_key_here":
            return Tier3Result(
                score=50,
                category="AI Unavailable",
                reasoning="Gemini API key not configured",
                flagged_phrases=[],
                status="failed",
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        # Execute AI analysis with timeout
        result = await asyncio.wait_for(
            analyze_email_intent(body),
            timeout=TIER3_TIMEOUT
        )
        
        execution_time = (time.time() - start_time) * 1000
        
        return Tier3Result(
            score=int(result.threat_score),
            category=result.category,
            reasoning=result.reasoning,
            flagged_phrases=result.flagged_phrases,
            status="complete",
            execution_time_ms=execution_time
        )
        
    except asyncio.TimeoutError:
        return Tier3Result(
            score=50,
            category="Timeout",
            reasoning="AI analysis timed out",
            flagged_phrases=[],
            status="timeout",
            execution_time_ms=TIER3_TIMEOUT * 1000
        )
    except Exception as e:
        print(f"Tier 3 error: {e}")
        return Tier3Result(
            score=50,
            category="Error",
            reasoning=f"AI analysis failed: {str(e)}",
            flagged_phrases=[],
            status="failed",
            execution_time_ms=(time.time() - start_time) * 1000
        )

# ============================================================================
# SCORING ENGINE
# ============================================================================

def calculate_partial_score(tier1_score: int, tier2_score: float) -> float:
    """Calculate partial score with T1 and T2 only (60% of final)"""
    # Redistribute weights: T1 gets 33%, T2 gets 67% (of the 60%)
    return (tier1_score * 0.33) + (tier2_score * 0.67)

def calculate_final_score(tier1_score: int, tier2_score: float, tier3_score: int) -> float:
    """Calculate final weighted score: T1×0.2 + T2×0.3 + T3×0.5"""
    return (tier1_score * WEIGHTS.tier1) + (tier2_score * WEIGHTS.tier2) + (tier3_score * WEIGHTS.tier3)

def determine_verdict(score: float) -> str:
    """Determine verdict based on score"""
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "CRITICAL"

# ============================================================================
# BACKGROUND TASK FOR TIER 3
# ============================================================================

async def process_tier3_async(scan_id: str, body: str):
    """Background task to process Tier 3 and update scan result"""
    tier3_result = await execute_tier3(body)
    
    # Update scan result with Tier 3 data
    if scan_id in scan_results:
        scan = scan_results[scan_id]
        scan.tier3 = tier3_result
        scan.tier3_status = tier3_result.status
        
        # Calculate final score
        scan.final_score = calculate_final_score(
            scan.tier1.score,
            scan.tier2.score,
            tier3_result.score
        )
        scan.verdict = determine_verdict(scan.final_score)
        scan.complete = True
        
        # Add Tier 3 evidence
        if tier3_result.category != "AI Unavailable":
            scan.combined_evidence.append(f"🤖 AI Analysis: {tier3_result.category}")
            if tier3_result.flagged_phrases:
                scan.combined_evidence.append(f"🚩 AI Flagged: {', '.join(tier3_result.flagged_phrases[:3])}")

# ============================================================================
# GATEWAY ENDPOINTS
# ============================================================================

@app.post("/gateway/scan", response_model=GatewayScanResponse)
async def gateway_scan(request: GatewayScanRequest, background_tasks: BackgroundTasks):
    """
    Main gateway endpoint - orchestrates all three tiers
    Returns immediate response with T1+T2, processes T3 in background
    """
    start_time = time.time()
    scan_id = str(uuid.uuid4())
    
    # Tier 1 Result (from extension)
    tier1 = Tier1Result(
        score=request.tier1_score,
        evidence=request.tier1_evidence,
        status="Suspicious" if request.tier1_score > 0 else "Clean"
    )
    
    # Execute Tier 2 (synchronous, ~300ms)
    tier2 = await execute_tier2(request.sender, request.body, request.links)
    
    # Calculate partial score (T1 + T2)
    partial_score = calculate_partial_score(tier1.score, tier2.score)
    partial_verdict = determine_verdict(partial_score)
    
    # Combine evidence
    combined_evidence = tier1.evidence + tier2.evidence
    
    # Create response
    response = GatewayScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now().isoformat(),
        partial_score=partial_score,
        final_score=None,  # Will be set when T3 completes
        verdict=partial_verdict,
        tier1=tier1,
        tier2=tier2,
        tier3=None,
        tier3_status="processing",
        complete=False,
        combined_evidence=combined_evidence,
        weights=WEIGHTS,
        total_execution_time_ms=(time.time() - start_time) * 1000
    )
    
    # Store for async updates
    scan_results[scan_id] = response
    
    # Start Tier 3 in background
    background_tasks.add_task(process_tier3_async, scan_id, request.body)
    
    return response

@app.get("/gateway/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Poll endpoint to check if Tier 3 analysis is complete"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    scan = scan_results[scan_id]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        complete=scan.complete,
        tier3_status=scan.tier3_status,
        final_score=scan.final_score,
        verdict=scan.verdict,
        tier3=scan.tier3,
        estimated_completion_ms=None if scan.complete else 2000
    )

@app.get("/gateway/result/{scan_id}", response_model=GatewayScanResponse)
async def get_full_result(scan_id: str):
    """Get complete scan result including all tiers"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    return scan_results[scan_id]

@app.get("/gateway/health")
async def gateway_health():
    """Gateway health check"""
    gemini_configured = bool(
        os.getenv("GEMINI_API_KEY") and 
        os.getenv("GEMINI_API_KEY") != "your_actual_gemini_api_key_here"
    )
    
    return {
        "status": "healthy",
        "service": "ZeroPhish API Gateway",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "tiers": {
            "tier1": "client-side",
            "tier2": "operational",
            "tier3": "operational" if gemini_configured else "unavailable (API key not set)"
        },
        "scoring": {
            "formula": "T1×0.2 + T2×0.3 + T3×0.5",
            "weights": WEIGHTS.dict()
        },
        "active_scans": len(scan_results)
    }

@app.delete("/gateway/cleanup")
async def cleanup_old_scans():
    """Clean up old scan results (keep last 100)"""
    if len(scan_results) > 100:
        # Keep only the 100 most recent
        sorted_scans = sorted(
            scan_results.items(),
            key=lambda x: x[1].timestamp,
            reverse=True
        )
        scan_results.clear()
        scan_results.update(dict(sorted_scans[:100]))
        return {"message": f"Cleaned up old scans, kept 100 most recent"}
    return {"message": "No cleanup needed"}

# ============================================================================
# STARTUP
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize gateway on startup"""
    print("=" * 60)
    print("🚀 ZeroPhish API Gateway Starting...")
    print("=" * 60)
    print(f"📊 Scoring Formula: T1×{WEIGHTS.tier1} + T2×{WEIGHTS.tier2} + T3×{WEIGHTS.tier3}")
    print(f"⏱️  Tier 3 Timeout: {TIER3_TIMEOUT}s")
    
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and gemini_key != "your_actual_gemini_api_key_here":
        print("✅ Tier 3 (AI): Enabled")
    else:
        print("⚠️  Tier 3 (AI): Disabled (Gemini API key not set)")
    
    print("=" * 60)
    print("📡 Gateway Endpoints:")
    print("   POST /gateway/scan - Main scan endpoint")
    print("   GET  /gateway/status/{scan_id} - Poll scan status")
    print("   GET  /gateway/result/{scan_id} - Get full result")
    print("   GET  /gateway/health - Health check")
    print("=" * 60)

# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("GATEWAY_PORT", "8000"))
    
    print(f"\n🌐 Starting gateway on http://localhost:{port}")
    print(f"📖 API Docs: http://localhost:{port}/docs\n")
    
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
