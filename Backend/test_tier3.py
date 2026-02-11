"""
Test suite for Tier 3 Semantic AI Analysis integration.
"""

import asyncio
import json
import os
from dotenv import load_dotenv

# Setup environment
load_dotenv()

async def test_t3_analysis():
    """Test Tier 3 semantic analysis with sample emails."""
    from tier_3.main import analyze_email_intent, T3Result
    
    test_cases = [
        {
            "name": "Phishing - Urgent Action Required",
            "body": """Subject: URGENT: Confirm Your Account Immediately!

Dear Valued Customer,

Your account has been locked due to suspicious activity. 
You must verify your credentials within 24 hours or lose access permanently.

Click here to update your password: [malicious-link.com]

This is urgent. Act now!

Best regards,
Security Team"""
        },
        {
            "name": "Safe - Legitimate Newsletter",
            "body": """Subject: February Product Updates

Hi there!

We wanted to share some exciting new features coming to our platform:

1. Improved dashboard UI
2. Better performance metrics
3. New API endpoints

Check out the full details on our blog.

Thanks for being a valued customer!

The Team"""
        },
        {
            "name": "Phishing - Financial Pressure",
            "body": """Subject: Payment Failed - Verify Billing Info

Hello,

Your recent payment attempt was declined. We need you to update your 
billing information immediately to avoid service interruption.

Verify Payment Here: https://verify-paypal-confirm.xyz/update

Please complete this within 2 hours.

Regards,
Billing Department"""
        }
    ]
    
    print("=" * 70)
    print("TIER 3 SEMANTIC AI ANALYSIS TEST")
    print("=" * 70)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test_case['name']}")
        print("-" * 70)
        
        try:
            result = await analyze_email_intent(test_case["body"])
            print(f"Threat Score: {result.threat_score:.1f}/100")
            print(f"Category: {result.category}")
            print(f"Reasoning: {result.reasoning}")
            if result.flagged_phrases:
                print(f"Flagged Phrases: {', '.join(result.flagged_phrases[:3])}")
            print("✓ PASS")
        except Exception as e:
            print(f"✗ FAIL: {e}")


async def test_scan_endpoint():
    """Test the unified /scan endpoint (requires server running)."""
    import httpx
    
    client = httpx.AsyncClient(base_url="http://localhost:8000")
    
    scan_request = {
        "sender": "noreply@suspicious-bank.com",
        "subject": "Urgent: Confirm Your Account",
        "body": """Dear Customer,

Your account has been flagged. Confirm your identity now:
Update Password: https://evil-link.com/login

Act immediately or we will close your account!

Banking Team"""
    }
    
    print("\n" + "=" * 70)
    print("UNIFIED /scan ENDPOINT TEST")
    print("=" * 70)
    
    try:
        response = await client.post("/scan", json=scan_request)
        if response.status_code == 200:
            data = response.json()
            print(f"\nFinal Score: {data['final_score']:.1f}/100")
            print(f"Recommendation: {data['recommendation']}")
            print(f"T1 Threat Level: {data['tier1'].get('threat_level', 'N/A')}")
            print(f"T2 Domain: {data['tier2'].get('domain', 'N/A')}")
            print(f"T3 Category: {data['tier3']['category']}")
            print(f"T3 Reasoning: {data['tier3']['reasoning']}")
            print("✓ PASS")
        else:
            print(f"✗ FAIL: HTTP {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"✗ FAIL (Server may not be running): {e}")
    finally:
        await client.aclose()


if __name__ == "__main__":
    print("\nStarting Tier 3 Tests...\n")
    
    # Test T3 analysis directly
    asyncio.run(test_t3_analysis())
    
    # Test full endpoint (optional - requires running server)
    # asyncio.run(test_scan_endpoint())
