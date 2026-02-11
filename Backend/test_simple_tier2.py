"""
Simple Tier 2 Backend Test Script
"""

import requests
import json

BASE_URL = "http://localhost:8000"

print("=" * 60)
print("ZeroPhish Tier 2 Backend - Simple Test")
print("=" * 60)
print()

# Test 1: Health Check
print("Test 1: Health Check")
print("-" * 40)
try:
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=2))
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 2: Cache Stats
print("Test 2: Cache Statistics")
print("-" * 40)
try:
    response = requests.get(f"{BASE_URL}/cache/stats")
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=2))
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 3: Threat Patterns
print("Test 3: Threat Patterns")
print("-" * 40)
try:
    response = requests.get(f"{BASE_URL}/threat/patterns")
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Urgency Patterns: {len(data['urgency_patterns'])}")
        print(f"Financial Patterns: {len(data['financial_patterns'])}")
        print(f"Credential Patterns: {len(data['credential_patterns'])}")
        print(f"Authority Patterns: {len(data['authority_patterns'])}")
        print(f"Scare Tactics: {len(data['scare_tactics'])}")
        print(f"Suspicious URLs: {len(data['suspicious_urls'])}")
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 4: Scan Safe Email
print("Test 4: Scan Safe Email")
print("-" * 40)
payload = {
    "sender": "notifications@github.com",
    "body": "Your pull request has been merged successfully.",
    "links": ["https://github.com/user/repo"]
}
try:
    response = requests.post(f"{BASE_URL}/scan", json=payload)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Final Score: {data['final_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"Category: {data['threat_analysis']['category']}")
        print(f"Threat Level: {data['threat_analysis']['threat_level']}")
        print(f"Cached: {data['cached']}")
        print("Evidence:")
        for evidence in data['evidence']:
            print(f"  - {evidence}")
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 5: Scan Suspicious Email
print("Test 5: Scan Suspicious Email")
print("-" * 40)
payload = {
    "sender": "security@newdomain.com",
    "body": "URGENT: Please verify your account immediately to avoid suspension!",
    "links": ["https://bit.ly/verify"]
}
try:
    response = requests.post(f"{BASE_URL}/scan", json=payload)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Final Score: {data['final_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"Category: {data['threat_analysis']['category']}")
        print(f"Threat Level: {data['threat_analysis']['threat_level']}")
        print(f"Reasoning: {data['threat_analysis']['reasoning']}")
        print(f"Flagged Phrases: {', '.join(data['threat_analysis']['flagged_phrases'][:5])}")
        print("Evidence:")
        for evidence in data['evidence']:
            print(f"  - {evidence}")
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 6: Scan Critical Threat
print("Test 6: Scan Critical Phishing Email")
print("-" * 40)
payload = {
    "sender": "urgent@suspicious.xyz",
    "body": """URGENT ACTION REQUIRED! Your bank account will be suspended immediately 
    unless you verify your password and credit card right now. Wire transfer required. 
    This is your last chance to avoid legal action!""",
    "links": ["https://bit.ly/urgent", "https://tinyurl.com/verify"]
}
try:
    response = requests.post(f"{BASE_URL}/scan", json=payload)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Final Score: {data['final_score']}")
        print(f"Verdict: {data['verdict']}")
        print(f"Category: {data['threat_analysis']['category']}")
        print(f"Threat Level: {data['threat_analysis']['threat_level']}")
        print(f"Reasoning: {data['threat_analysis']['reasoning']}")
        print(f"Flagged Phrases ({len(data['threat_analysis']['flagged_phrases'])}): {', '.join(data['threat_analysis']['flagged_phrases'][:8])}")
        print("Evidence:")
        for evidence in data['evidence']:
            print(f"  - {evidence}")
        print("✅ PASS\n")
    else:
        print("❌ FAIL\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

# Test 7: Cache Test (scan same email twice)
print("Test 7: Cache Functionality")
print("-" * 40)
payload = {
    "sender": "test@example.com",
    "body": "This is a cache test email",
    "links": []
}
try:
    # First request
    response1 = requests.post(f"{BASE_URL}/scan", json=payload)
    data1 = response1.json()
    print(f"First request - Cached: {data1['cached']}")
    
    # Second request (should be cached)
    response2 = requests.post(f"{BASE_URL}/scan", json=payload)
    data2 = response2.json()
    print(f"Second request - Cached: {data2['cached']}")
    
    if data2['cached']:
        print("✅ PASS - Caching works!\n")
    else:
        print("⚠️  WARNING - Not cached (may be using in-memory cache)\n")
except Exception as e:
    print(f"❌ ERROR: {e}\n")

print("=" * 60)
print("Testing Complete!")
print("=" * 60)
