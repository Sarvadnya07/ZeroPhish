#!/usr/bin/env python3
"""
Test script to verify dashboard data flow
"""
import requests
import json
from datetime import datetime

# Test 1: Check if backend is running
print("Test 1: Checking backend health...")
try:
    response = requests.get("http://127.0.0.1:8000/health")
    print(f"✅ Backend is running: {response.status_code}")
    print(f"   Response: {response.json()}")
except Exception as e:
    print(f"❌ Backend health check failed: {e}")
    exit(1)

# Test 2: Check /tier1/latest endpoint
print("\nTest 2: Checking /tier1/latest...")
try:
    response = requests.get("http://127.0.0.1:8000/tier1/latest")
    print(f"✅ /tier1/latest status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        if data:
            print(f"   Latest scan: {data.get('scan_id', 'N/A')}")
        else:
            print("   No scans yet (null)")
except Exception as e:
    print(f"❌ /tier1/latest failed: {e}")

# Test 3: Send a test report
print("\nTest 3: Sending test report to /tier1/report...")
test_report = {
    "scan_id": "test-" + str(datetime.now().timestamp()),
    "timestamp": datetime.now().isoformat(),
    "sender": "test@example.com",
    "subject": "Test Email from Script",
    "final_score": 85,
    "verdict": "SUSPICIOUS",
    "evidence": ["Test evidence 1", "Test evidence 2"],
    "threat_analysis": {"category": "Test"},
    "tier_details": {
        "tier1": {"score": 30, "status": "suspicious"},
        "tier2": {"score": 40, "status": "suspicious"},
        "tier3": {"score": 15, "status": "suspicious"}
    }
}

try:
    response = requests.post(
        "http://127.0.0.1:8000/tier1/report",
        json=test_report,
        headers={"Content-Type": "application/json"}
    )
    print(f"✅ Report sent: {response.status_code}")
    print(f"   Response: {response.json()}")
except Exception as e:
    print(f"❌ Report failed: {e}")

# Test 4: Check if report was stored
print("\nTest 4: Verifying report was stored...")
try:
    response = requests.get("http://127.0.0.1:8000/tier1/latest")
    if response.status_code == 200:
        data = response.json()
        if data and data.get("scan_id") == test_report["scan_id"]:
            print(f"✅ Report stored successfully!")
            print(f"   Scan ID: {data.get('scan_id')}")
            print(f"   Score: {data.get('final_score')}")
            print(f"   Verdict: {data.get('verdict')}")
        else:
            print(f"⚠️  Report not found in latest")
            print(f"   Got: {data}")
except Exception as e:
    print(f"❌ Verification failed: {e}")

print("\n" + "="*50)
print("Dashboard should now show the test scan!")
print("Open: http://localhost:3000")
print("="*50)
