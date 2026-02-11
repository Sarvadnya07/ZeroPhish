"""
ZeroPhish Gateway - Test Script
Tests the unified gateway with all three tiers
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"

print("=" * 60)
print("ZeroPhish API Gateway - Test Suite")
print("=" * 60)
print()

# Test 1: Gateway Health Check
print("Test 1: Gateway Health Check")
print("-" * 40)
try:
    response = requests.get(f"{BASE_URL}/gateway/health")
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=2))
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 2: Gateway Scan - Safe Email
print("Test 2: Gateway Scan - Safe Email")
print("-" * 40)
payload = {
    "tier1_score": 10,
    "tier1_evidence": ["✓ No suspicious patterns detected"],
    "sender": "notifications@github.com",
    "body": "Your pull request has been merged successfully.",
    "links": ["https://github.com/user/repo"]
}
try:
    response = requests.post(f"{BASE_URL}/gateway/scan", json=payload)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        scan_id = data['scan_id']
        print(f"Scan ID: {scan_id}")
        print(f"Partial Score: {data['partial_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"Tier 1 Score: {data['tier1']['score']}")
        print(f"Tier 2 Score: {data['tier2']['score']}")
        print(f"Tier 3 Status: {data['tier3_status']}")
        print(f"Complete: {data['complete']}")
        print(f"Evidence: {', '.join(data['combined_evidence'][:3])}")
        
        # Poll for Tier 3 completion
        print("\nPolling for Tier 3 completion...")
        for i in range(10):
            time.sleep(0.5)
            status_response = requests.get(f"{BASE_URL}/gateway/status/{scan_id}")
            status_data = status_response.json()
            print(f"  Poll {i+1}: Tier 3 Status = {status_data['tier3_status']}, Complete = {status_data['complete']}")
            if status_data['complete']:
                print(f"  Final Score: {status_data['final_score']}")
                print(f"  Final Verdict: {status_data['verdict']}")
                break
        
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 3: Gateway Scan - Critical Phishing
print("Test 3: Gateway Scan - Critical Phishing Email")
print("-" * 40)
payload = {
    "tier1_score": 80,
    "tier1_evidence": [
        "🚩 High-pressure keywords detected",
        "🚨 Homograph URL detected"
    ],
    "sender": "urgent@suspicious.xyz",
    "body": """URGENT ACTION REQUIRED! Your bank account will be suspended immediately 
    unless you verify your password and credit card right now. Wire transfer required. 
    This is your last chance to avoid legal action!""",
    "links": ["https://bit.ly/urgent", "https://tinyurl.com/verify"]
}
try:
    response = requests.post(f"{BASE_URL}/gateway/scan", json=payload)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        scan_id = data['scan_id']
        print(f"Scan ID: {scan_id}")
        print(f"Partial Score: {data['partial_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"\nWeighted Scoring:")
        print(f"  T1 ({data['weights']['tier1']}): {data['tier1']['score']}")
        print(f"  T2 ({data['weights']['tier2']}): {data['tier2']['score']}")
        print(f"  T3 ({data['weights']['tier3']}): Pending...")
        print(f"\nTier 2 Details:")
        print(f"  Domain Status: {data['tier2']['domain_analysis']['status']}")
        print(f"  Threat Status: {data['tier2']['threat_analysis']['status']}")
        print(f"  Category: {data['tier2']['threat_details']['category']}")
        print(f"  Flagged Phrases: {', '.join(data['tier2']['threat_details']['flagged_phrases'][:5])}")
        
        # Poll for Tier 3 completion
        print("\nPolling for Tier 3 completion...")
        for i in range(10):
            time.sleep(0.5)
            status_response = requests.get(f"{BASE_URL}/gateway/status/{scan_id}")
            status_data = status_response.json()
            print(f"  Poll {i+1}: Status = {status_data['tier3_status']}")
            if status_data['complete']:
                print(f"\n🎯 Final Results:")
                print(f"  Final Score: {status_data['final_score']}")
                print(f"  Final Verdict: {status_data['verdict']}")
                if status_data['tier3']:
                    print(f"  T3 Score: {status_data['tier3']['score']}")
                    print(f"  T3 Category: {status_data['tier3']['category']}")
                break
        
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 4: Get Full Result
print("Test 4: Get Full Result")
print("-" * 40)
try:
    # Use scan_id from previous test
    response = requests.get(f"{BASE_URL}/gateway/result/{scan_id}")
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Complete: {data['complete']}")
        print(f"Final Score: {data['final_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"All Evidence ({len(data['combined_evidence'])} items):")
        for evidence in data['combined_evidence']:
            print(f"  - {evidence}")
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

print("=" * 60)
print("Gateway Testing Complete!")
print("=" * 60)
