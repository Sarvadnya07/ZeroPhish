import sys
from pathlib import Path

BACKEND_DIR = Path("Backend").resolve()
sys.path.insert(0, str(BACKEND_DIR))

from tier_1.engine import analyze_tier1_server
from models.gateway_models import (
    CleanStatus,
    DomainAnalysis,
    DomainStatus,
    ThreatAnalysisDetail,
    Tier1Result,
    Tier2Analysis,
    Tier2Result,
)
from fusion.engine import fuse_detection_results

def make_t1(score: int, evidence: list = None) -> Tier1Result:
    return Tier1Result(
        score=score,
        status=CleanStatus.SUSPICIOUS if score >= 20 else CleanStatus.CLEAN,
        evidence=evidence or [],
        server_score=score,
        execution_time_ms=1.0,
    )

def make_t2(score: float, category: str = "Safe", evidence: list = None) -> Tier2Result:
    return Tier2Result(
        score=score,
        domain_analysis=DomainAnalysis(status=DomainStatus.OK, score=score, weight=0.3),
        threat_analysis=Tier2Analysis(status=DomainStatus.OK, score=score, weight=0.7),
        threat_details=ThreatAnalysisDetail(
            threat_level=int(score),
            category=category,
            reasoning=f"Tier 2 evaluation: {category}",
            flagged_phrases=[],
        ),
        evidence=evidence or [f"Tier 2 score: {score}"],
        execution_time_ms=5.0,
    )

def run_9_cases():
    print("=" * 80)
    print("PHASE 1.8 RUNTIME VERIFICATION MATRIX — 9 SECURITY TEST CASES")
    print("=" * 80)

    results = []

    # Case 1: Credential harvesting
    res1 = analyze_tier1_server(
        sender="notice@service-account.com",
        subject="Password Reset Required",
        body="Please reset your password and login immediately to verify your credentials.",
        links=["https://service-account.com/reset"],
    )
    t1_1 = make_t1(score=res1.score, evidence=res1.evidence)
    fused1 = fuse_detection_results(tier1_result=t1_1, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("1. Credential Harvesting", res1.score, fused1.verdict, res1.evidence[:2]))

    # Case 2: Zero-width urgency / password
    res2 = analyze_tier1_server(
        sender="admin@alert-domain.com",
        subject="U\u200brgent: P\u200bassword Update",
        body="Action needed: reset your p\u200bassword now.",
        links=["https://alert-domain.com/login"],
    )
    t1_2 = make_t1(score=res2.score, evidence=res2.evidence)
    fused2 = fuse_detection_results(tier1_result=t1_2, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("2. Zero-Width Urgency/Password", res2.score, fused2.verdict, res2.evidence[:2]))

    # Case 3: Cyrillic confusable
    # \u0440 is Cyrillic small letter er (looks like 'p')
    # \u0435 is Cyrillic small letter ie (looks like 'e')
    res3 = analyze_tier1_server(
        sender="alert@security-bank.com",
        subject="\u0440assword reset notification",
        body="Please resolve this urg\u0435nt issue immediately.",
        links=["https://security-bank.com/portal"],
    )
    t1_3 = make_t1(score=res3.score, evidence=res3.evidence)
    fused3 = fuse_detection_results(tier1_result=t1_3, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("3. Cyrillic Confusable", res3.score, fused3.verdict, res3.evidence[:2]))

    # Case 4: Decimal IP URL
    res4 = analyze_tier1_server(
        sender="admin@notice.org",
        subject="Server alert",
        body="Access control panel at link below.",
        links=["http://2130706433/login"],
    )
    t1_4 = make_t1(score=res4.score, evidence=res4.evidence)
    fused4 = fuse_detection_results(tier1_result=t1_4, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("4. Decimal IP URL", res4.score, fused4.verdict, res4.evidence[:2]))

    # Case 5: Hex IP URL
    res5 = analyze_tier1_server(
        sender="admin@notice.org",
        subject="Portal access",
        body="Verify your session below.",
        links=["http://0x7f000001/auth"],
    )
    t1_5 = make_t1(score=res5.score, evidence=res5.evidence)
    fused5 = fuse_detection_results(tier1_result=t1_5, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("5. Hex IP URL", res5.score, fused5.verdict, res5.evidence[:2]))

    # Case 6: Trailing-dot domain (FQDN normalization)
    res6 = analyze_tier1_server(
        sender="support@paypal.com.",
        subject="Monthly Account Statement",
        body="Thank you for your transaction. Your monthly account statement is ready.",
        links=["https://paypal.com./receipt"],
    )
    t1_6 = make_t1(score=res6.score, evidence=res6.evidence)
    t2_6 = make_t2(score=0.0, category="Safe", evidence=["Domain age 8000 days (authoritative)"])
    fused6 = fuse_detection_results(tier1_result=t1_6, tier2_result=t2_6, tier3_result=None, vision_result=None)
    results.append(("6. Trailing-Dot Domain Normalization", res6.score, fused6.verdict, res6.evidence[:2]))

    # Case 7: Client tier1_score = 0 override attempt
    server_t1 = analyze_tier1_server(
        sender="security@paypal.phishing.com",
        subject="URGENT: Account Suspension Warning",
        body="Click here to reset your password immediately: http://192.168.1.1/login",
        links=["http://192.168.1.1/login"],
    )
    client_score = 0 # Adversary claims clean
    effective_score = max(server_t1.score, client_score)
    t1_7 = make_t1(score=effective_score, evidence=server_t1.evidence)
    fused7 = fuse_detection_results(tier1_result=t1_7, tier2_result=None, tier3_result=None, vision_result=None)
    results.append(("7. Client Override Attempt (score=0)", effective_score, fused7.verdict, ["[Server Verified] " + e for e in server_t1.evidence[:2]]))

    # Case 8: Suspicious + advisory failure (Tier 3 timeout/failed)
    t1_8 = make_t1(score=45, evidence=["Suspicious sender domain", "Generic urgency"])
    t2_8 = make_t2(score=50.0, category="Suspicious", evidence=["Domain registered 3 days ago"])
    fused8 = fuse_detection_results(tier1_result=t1_8, tier2_result=t2_8, tier3_result=None, vision_result=None)
    results.append(("8. Suspicious + Advisory Failure", fused8.final_score, fused8.verdict, fused8.combined_evidence_strings[:2]))

    # Case 9: Critical + advisory failure (Tier 3 timeout/failed)
    t1_9 = make_t1(score=80, evidence=["Sender domain spoofing", "IP URL detected"])
    t2_9 = make_t2(score=85.0, category="Critical", evidence=["Brand impersonation detected", "Fresh domain (<24h)"])
    fused9 = fuse_detection_results(tier1_result=t1_9, tier2_result=t2_9, tier3_result=None, vision_result=None)
    results.append(("9. Critical + Advisory Failure", fused9.final_score, fused9.verdict, fused9.combined_evidence_strings[:2]))

    for name, score, verdict, ev in results:
        print(f"\n[{name}]")
        print(f"  Score:    {score}")
        print(f"  Verdict:  {verdict}")
        print(f"  Evidence: {ev}")

if __name__ == "__main__":
    run_9_cases()
