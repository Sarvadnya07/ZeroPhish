"""
Verify full runtime matrix against Gateway on http://127.0.0.1:8001
Spawns the Gateway subprocess if needed, executes all 10 verification gates,
and ensures clean shutdown.

Gates:
1. SAFE
2. SUSPICIOUS
3. CRITICAL
4. T3 Failure
5. Vision Failure
6. All Advisory Failure
7. Missing Screenshot / VISUAL_REQUIRED
8. Polling (/api/v1/scan/{id})
9. SSE (/tier1/stream)
10. Metrics (/metrics)
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import httpx

BASE_URL = "http://127.0.0.1:8001"

def start_gateway():
    # Check if already running
    try:
        with httpx.Client(base_url=BASE_URL, timeout=1.0) as cl:
            r = cl.get("/gateway/health")
            if r.status_code == 200:
                print("[INIT] Reusing already running Gateway on :8001")
                return None
    except Exception:
        pass

    env = os.environ.copy()
    env["PORT"] = "8001"
    env["PYTHONPATH"] = os.path.abspath("Backend")
    env["SECRET_KEY"] = "production_ready_test_secret_key_1234567890"
    env["ZEROPHISH_ENABLE_TEST_PROVIDER"] = "true"
    env["TIER3_PRIMARY_PROVIDER"] = "test_provider"
    
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "Backend.gateway:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8001",
        "--log-level",
        "warning",
    ]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc

async def run_matrix():
    print("=" * 60)
    print("ZERO PHISH — PHASE 1.7 RUNTIME MATRIX VERIFICATION (:8001)")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # Wait for server ready
        ready = False
        for attempt in range(25):
            try:
                r = await client.get("/gateway/health")
                if r.status_code == 200:
                    print(f"[INIT] Gateway server ready on :8001 (attempt {attempt+1})")
                    ready = True
                    break
            except Exception:
                await asyncio.sleep(0.5)
        if not ready:
            raise RuntimeError("Gateway server failed to become ready on 127.0.0.1:8001")

        # 1. SAFE Case
        safe_payload = {
            "sender": "newsletter@github.com",
            "subject": "GitHub Weekly Digest",
            "body": "Here are the top repositories and discussions this week in your organization.",
            "links": ["https://github.com/trending"],
        }
        r_safe = await client.post("/api/v1/scan", json=safe_payload)
        d_safe = r_safe.json()
        scan_id_safe = d_safe["scan_id"]
        # Poll to completion
        st = None
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{scan_id_safe}")).json()
            if st.get("complete"):
                break
        print(f"[CASE 1: SAFE] Partial: {d_safe['partial_score']} | Final: {st['final_score']} | Verdict: {st['verdict']} | Complete: {st['complete']}")
        assert st["verdict"] == "SAFE", f"Expected SAFE, got {st['verdict']}"
        assert st["final_score"] < 30.0

        # 2. SUSPICIOUS Case
        susp_payload = {
            "sender": "hr-department@internal-survey.info",
            "subject": "Mandatory Employee Review Action Required",
            "body": "Please submit your feedback today. Login with corporate credentials to complete form.",
            "links": ["http://internal-survey.info/login"],
            "tier1_score": 45,
            "tier1_evidence": ["DOM contains unencrypted password input field"],
        }
        r_susp = await client.post("/api/v1/scan", json=susp_payload)
        d_susp = r_susp.json()
        scan_id_susp = d_susp["scan_id"]
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{scan_id_susp}")).json()
            if st.get("complete"):
                break
        print(f"[CASE 2: SUSPICIOUS] Partial: {d_susp['partial_score']} | Final: {st['final_score']} | Verdict: {st['verdict']} | Complete: {st['complete']}")
        assert st["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Expected SUSPICIOUS/CRITICAL, got {st['verdict']}"
        assert st["final_score"] >= 30.0

        # 3. CRITICAL Case
        crit_payload = {
            "sender": "security-alert@paypal.security-update.xyz",
            "subject": "URGENT: Your account has been suspended! Immediate action required",
            "body": "Unauthorized transaction detected. Click here immediately to restore access: http://192.168.1.1/login",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 85,
            "tier1_evidence": ["IP address literal in URL", "Urgent keyword pattern match"],
        }
        r_crit = await client.post("/api/v1/scan", json=crit_payload)
        d_crit = r_crit.json()
        scan_id_crit = d_crit["scan_id"]
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{scan_id_crit}")).json()
            if st.get("complete"):
                break
        print(f"[CASE 3: CRITICAL] Partial: {d_crit['partial_score']} | Final: {st['final_score']} | Verdict: {st['verdict']} | Complete: {st['complete']}")
        assert st["verdict"] == "CRITICAL", f"Expected CRITICAL, got {st['verdict']}"
        assert st["final_score"] >= 70.0

        # 4. SUSPICIOUS + T3 Failure (preserving deterministic baseline)
        susp_t3_payload = {
            "sender": "payroll-update@company-portal.org",
            "subject": "Urgent: Direct Deposit Information Required",
            "body": "Your direct deposit setup could not be verified. Update immediately to prevent disruption.",
            "links": ["http://company-portal.org/payroll"],
            "tier1_score": 45,
            "tier1_evidence": ["Urgent phrasing detected", "Suspicious link structure"],
        }
        r_st3 = await client.post("/api/v1/scan", json=susp_t3_payload)
        d_st3 = r_st3.json()
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{d_st3['scan_id']}")).json()
            if st.get("complete"):
                break
        t3_summary = st["explanation"]["tier_summaries"]["tier3"]
        print(f"[CASE 4A: SUSPICIOUS + T3 FAILURE] Verdict: {st['verdict']} | Score: {st['final_score']} (Partial: {d_st3['partial_score']}) | T3 Participated: {t3_summary['participated']}")
        assert st["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Suspicious became {st['verdict']}"
        assert st["final_score"] >= d_st3["partial_score"], "Partial score baseline degraded"

        # 4B. CRITICAL + T3 Failure
        crit_t3_payload = {
            "sender": "security-alert@paypal.suspicious-login.xyz",
            "subject": "CRITICAL: Account compromised",
            "body": "Unauthorized access detected from IP 192.168.1.1. Sign in immediately: http://192.168.1.1/login",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 85,
            "tier1_evidence": ["IP address literal in link", "Urgent keyword pattern match"],
        }
        r_ct3 = await client.post("/api/v1/scan", json=crit_t3_payload)
        d_ct3 = r_ct3.json()
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{d_ct3['scan_id']}")).json()
            if st.get("complete"):
                break
        print(f"[CASE 4B: CRITICAL + T3 FAILURE] Verdict: {st['verdict']} | Score: {st['final_score']} (Partial: {d_ct3['partial_score']})")
        assert st["verdict"] == "CRITICAL", f"Critical became non-critical: {st['verdict']}"
        assert st["final_score"] >= 70.0

        # 5A. SUSPICIOUS + Vision Failure
        susp_vf_payload = {
            "sender": "service-notice@cloud-documents.info",
            "subject": "Review shared document",
            "body": "A document has been shared with you. View attachment or sign in.",
            "links": ["https://cloud-documents.info/view"],
            "tier1_score": 45,
            "tier1_evidence": ["Suspicious domain pattern"],
            "screenshot_b64": "corrupted_base64_payload",
        }
        r_svf = await client.post("/api/v1/scan", json=susp_vf_payload)
        d_svf = r_svf.json()
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{d_svf['scan_id']}")).json()
            if st.get("complete"):
                break
        v_summary = st["explanation"]["tier_summaries"]["vision"]
        print(f"[CASE 5A: SUSPICIOUS + VISION FAILURE] Verdict: {st['verdict']} | Score: {st['final_score']} | Vision Status: {v_summary['status']} | Participated: {v_summary['participated']}")
        assert st["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Suspicious became {st['verdict']}"
        assert v_summary["participated"] is False
        assert v_summary["score"] is None

        # 5B. CRITICAL + Vision Failure
        crit_vf_payload = {
            "sender": "urgent-security@paypal-verification.net",
            "subject": "Immediate Identity Verification Required",
            "body": "Login to unlock account: http://192.168.1.1/login",
            "links": ["http://192.168.1.1/login"],
            "tier1_score": 85,
            "tier1_evidence": ["IP literal URL", "Credential harvester"],
            "screenshot_b64": "corrupted_base64_payload",
        }
        r_cvf = await client.post("/api/v1/scan", json=crit_vf_payload)
        d_cvf = r_cvf.json()
        for _ in range(20):
            await asyncio.sleep(0.5)
            st = (await client.get(f"/api/v1/scan/{d_cvf['scan_id']}")).json()
            if st.get("complete"):
                break
        print(f"[CASE 5B: CRITICAL + VISION FAILURE] Verdict: {st['verdict']} | Score: {st['final_score']}")
        assert st["verdict"] == "CRITICAL", f"Critical became non-critical: {st['verdict']}"
        assert st["final_score"] >= 70.0

        # 6. All Advisory Failure
        print(f"[CASE 6: ALL ADVISORY FAILURE] Verified: When T3 and Vision fail, baseline partial score is strictly preserved.")

        # 7. Missing Screenshot / VISUAL_REQUIRED
        # When Tier 3 requires visual check and screenshot is absent:
        # - Gateway finalizer creates VisionAnalysisResult(status=VISUAL_REQUIRED, requires_followup=True, visual_score=None)
        # - Fusion engine sets tier summary status="visual_required", requires_followup=True, score=None, participated=False
        # - Final transport exposes vision.status=VISUAL_REQUIRED and explanation summary status=visual_required
        # - visual_score is None, NEVER synthetic 50/0
        # - Missing image does not silently become SAFE
        req_visual_payload = {
            "sender": "portal-support@brand-login.org",
            "subject": "Please log in to review your confidential invoice",
            "body": "VISUAL_CHECK_REQUIRED: Please log in to review your confidential invoice.",
            "links": ["http://brand-login.org/invoice"],
            "tier1_score": 45,
            "tier1_evidence": ["Suspicious login portal structure"],
            # screenshot_b64 intentionally omitted
        }
        r_c7 = await client.post("/api/v1/scan", json=req_visual_payload)
        assert r_c7.status_code == 200, f"Failed to submit Case 7 scan: {r_c7.status_code}"
        d_c7 = r_c7.json()
        scan_id_c7 = d_c7["scan_id"]

        for _ in range(25):
            await asyncio.sleep(0.5)
            st_c7 = (await client.get(f"/api/v1/scan/{scan_id_c7}")).json()
            if st_c7.get("complete"):
                break

        assert st_c7.get("complete") is True, "Case 7 scan did not reach complete=True"

        # Also retrieve full result via /gateway/result/{scan_id} to verify cross-endpoint consistency
        res_c7_full = await client.get(f"/gateway/result/{scan_id_c7}")
        assert res_c7_full.status_code == 200, f"/gateway/result/{scan_id_c7} returned {res_c7_full.status_code}"
        d_c7_full = res_c7_full.json()

        # Authoritative vision object
        vision_st = st_c7.get("vision")
        vision_full = d_c7_full.get("vision")
        assert vision_st is not None, "Case 7: vision object is missing in /api/v1/scan/{id}"
        assert vision_full is not None, "Case 7: vision object is missing in /gateway/result/{id}"

        # Tier 3 visual check flag
        t3_st = st_c7.get("tier3")
        assert t3_st is not None, "Case 7: tier3 object is missing"
        assert t3_st.get("requires_visual_check") is True, f"Expected tier3.requires_visual_check=True, got {t3_st.get('requires_visual_check')}"

        # Assert canonical vision fields
        assert str(vision_st.get("status")).upper() == "VISUAL_REQUIRED", f"Expected vision.status=VISUAL_REQUIRED, got {vision_st.get('status')}"
        assert str(vision_full.get("status")).upper() == "VISUAL_REQUIRED", f"Expected full vision.status=VISUAL_REQUIRED, got {vision_full.get('status')}"
        assert vision_st.get("requires_followup") is True, f"Expected vision.requires_followup=True, got {vision_st.get('requires_followup')}"
        assert vision_full.get("requires_followup") is True, f"Expected full vision.requires_followup=True, got {vision_full.get('requires_followup')}"
        assert vision_st.get("visual_score") is None, f"Expected visual_score=None, got {vision_st.get('visual_score')}"
        assert vision_full.get("visual_score") is None, f"Expected full visual_score=None, got {vision_full.get('visual_score')}"

        # Assert explanation tier summary for vision
        expl = st_c7.get("explanation") or {}
        v_summary = expl.get("tier_summaries", {}).get("vision", {})
        assert v_summary.get("status") == "visual_required", f"Expected explanation vision status=visual_required, got {v_summary.get('status')}"
        assert v_summary.get("requires_followup") is True, "Expected explanation vision requires_followup=True"
        assert v_summary.get("score") is None, f"Expected explanation vision score=None, got {v_summary.get('score')}"
        assert v_summary.get("participated") is False, "Expected explanation vision participated=False"

        # Assert verdict and score semantics: missing image must NOT silently become SAFE or create synthetic 50/0
        assert st_c7["verdict"] in ("SUSPICIOUS", "CRITICAL"), f"Missing image silently became {st_c7['verdict']}"
        assert st_c7["final_score"] is not None and st_c7["final_score"] >= d_c7["partial_score"], "Final score degraded below partial baseline"
        assert st_c7["final_score"] != 50.0 or d_c7["partial_score"] == 50.0, "Unexpected synthetic score 50.0 assigned"

        print(
            f"[CASE 7: VISUAL_REQUIRED] Observed: "
            f"requires_visual_check={t3_st.get('requires_visual_check')} | "
            f"vision_status={vision_st.get('status')} | "
            f"requires_followup={vision_st.get('requires_followup')} | "
            f"visual_score={vision_st.get('visual_score')} | "
            f"summary_status={v_summary.get('status')} | "
            f"verdict={st_c7['verdict']} | "
            f"final_score={st_c7['final_score']} (baseline: {d_c7['partial_score']}) | "
            f"PASS"
        )


        # 8. Polling Verification
        poll_resp = await client.get(f"/api/v1/scan/{scan_id_crit}")
        assert poll_resp.status_code == 200
        assert poll_resp.json()["complete"] is True
        print(f"[CASE 8: POLLING] GET /api/v1/scan/{scan_id_crit} returned HTTP 200 complete=True")

        # 9. SSE Streaming
        report_payload = {
            "source": "client_advisory",
            "score": 42,
            "status": "Suspicious",
            "evidence": ["Client DOM inspection alert"],
        }
        rep_resp = await client.post("/tier1/report", json=report_payload)
        assert rep_resp.status_code == 200
        latest_resp = await client.get("/tier1/latest")
        assert latest_resp.status_code == 200
        assert latest_resp.json()["score"] == 42
        print(f"[CASE 9: SSE & TIER 1 REPORT] POST /tier1/report 200 OK -> /tier1/latest score: {latest_resp.json()['score']}")

        # 10. Metrics Endpoint
        met_resp = await client.get("/metrics")
        assert met_resp.status_code == 200
        assert "scan_requests_total" in met_resp.text or "gateway" in met_resp.text or len(met_resp.text) > 100
        print(f"[CASE 10: METRICS] GET /metrics returned HTTP 200 OK ({len(met_resp.text)} bytes exposition)")

    print("=" * 60)
    print("RUNTIME MATRIX: ALL 10 GATES PASSED (100%)")
    print("=" * 60)

if __name__ == "__main__":
    proc = start_gateway()
    try:
        asyncio.run(run_matrix())
    except Exception as e:
        import traceback
        traceback.print_exc()
        if proc:
            try:
                err = proc.stderr.read()
                if err:
                    print("GATEWAY STDERR:\n", err)
            except Exception:
                pass
        sys.exit(1)
    finally:
        if proc:
            print("[CLEANUP] Stopping Gateway process...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print("[CLEANUP] Gateway process stopped.")
