"""
ZeroPhish Tier 2 Backend - Comprehensive Test Suite
Tests all endpoints and functionality
"""

import requests
import json
import time
from typing import Dict, Any

# Configuration
BASE_URL = "http://localhost:8000"
TIMEOUT = 10

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}\n")

def print_test(name: str):
    print(f"{Colors.BLUE}🧪 Testing: {name}{Colors.RESET}")

def print_success(message: str):
    print(f"{Colors.GREEN}✅ {message}{Colors.RESET}")

def print_error(message: str):
    print(f"{Colors.RED}❌ {message}{Colors.RESET}")

def print_info(message: str):
    print(f"{Colors.YELLOW}ℹ️  {message}{Colors.RESET}")

def test_health_check() -> bool:
    """Test the health check endpoint"""
    print_test("Health Check Endpoint")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Service: {data.get('service')}")
            print_info(f"Version: {data.get('version')}")
            print_info(f"Speed Layer: {data.get('features', {}).get('speed_layer')}")
            print_info(f"Threat Analysis: {data.get('features', {}).get('threat_analysis')}")
            print_info(f"Domain Check: {data.get('features', {}).get('domain_check')}")
            return True
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_cache_stats() -> bool:
    """Test the cache statistics endpoint"""
    print_test("Cache Statistics Endpoint")
    try:
        response = requests.get(f"{BASE_URL}/cache/stats", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Cache Status: {data.get('status')}")
            print_info(f"Backend: {data.get('backend', 'N/A')}")
            if 'cache_type' in data:
                print_info(f"Cache Type: {data.get('cache_type')}")
            return True
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Cache stats failed: {e}")
        return False

def test_threat_patterns() -> bool:
    """Test the threat patterns endpoint"""
    print_test("Threat Patterns Endpoint")
    try:
        response = requests.get(f"{BASE_URL}/threat/patterns", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Urgency Patterns: {len(data.get('urgency_patterns', []))} patterns")
            print_info(f"Financial Patterns: {len(data.get('financial_patterns', []))} patterns")
            print_info(f"Credential Patterns: {len(data.get('credential_patterns', []))} patterns")
            print_info(f"Authority Patterns: {len(data.get('authority_patterns', []))} patterns")
            print_info(f"Scare Tactics: {len(data.get('scare_tactics', []))} patterns")
            print_info(f"Suspicious URLs: {len(data.get('suspicious_urls', []))} patterns")
            return True
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Threat patterns failed: {e}")
        return False

def test_scan_safe_email() -> bool:
    """Test scanning a safe email"""
    print_test("Scan Safe Email")
    
    payload = {
        "sender": "notifications@github.com",
        "body": "Your pull request #123 has been merged successfully. Great work!",
        "links": ["https://github.com/user/repo/pull/123"]
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json=payload,
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Final Score: {data.get('final_score')}")
            print_info(f"Verdict: {data.get('verdict')}")
            print_info(f"Category: {data.get('threat_analysis', {}).get('category')}")
            print_info(f"Cached: {data.get('cached')}")
            
            if data.get('verdict') == 'SAFE':
                print_success("Correctly identified as SAFE")
                return True
            else:
                print_error(f"Expected SAFE, got {data.get('verdict')}")
                return False
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Safe email scan failed: {e}")
        return False

def test_scan_suspicious_email() -> bool:
    """Test scanning a suspicious email"""
    print_test("Scan Suspicious Email")
    
    payload = {
        "sender": "security@newdomain.com",
        "body": "Please verify your account immediately to avoid suspension.",
        "links": ["https://bit.ly/verify-account"]
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json=payload,
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Final Score: {data.get('final_score')}")
            print_info(f"Verdict: {data.get('verdict')}")
            print_info(f"Category: {data.get('threat_analysis', {}).get('category')}")
            print_info(f"Threat Level: {data.get('threat_analysis', {}).get('threat_level')}")
            print_info(f"Flagged Phrases: {len(data.get('threat_analysis', {}).get('flagged_phrases', []))}")
            
            if data.get('final_score', 0) > 30:
                print_success("Correctly identified as suspicious/critical")
                return True
            else:
                print_error(f"Expected higher threat score, got {data.get('final_score')}")
                return False
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Suspicious email scan failed: {e}")
        return False

def test_scan_critical_threat() -> bool:
    """Test scanning a critical phishing email"""
    print_test("Scan Critical Phishing Email")
    
    payload = {
        "sender": "urgent@suspicious-domain.xyz",
        "body": """URGENT ACTION REQUIRED! Your bank account will be suspended immediately 
        unless you verify your credentials right now. Click here to avoid penalties and 
        legal action. This is your last chance! Wire transfer required to unlock account.""",
        "links": ["https://bit.ly/urgent-verify", "https://tinyurl.com/bank-verify"]
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan",
            json=payload,
            timeout=TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            print_success(f"Status: {response.status_code}")
            print_info(f"Final Score: {data.get('final_score')}")
            print_info(f"Verdict: {data.get('verdict')}")
            print_info(f"Category: {data.get('threat_analysis', {}).get('category')}")
            print_info(f"Threat Level: {data.get('threat_analysis', {}).get('threat_level')}")
            print_info(f"Reasoning: {data.get('threat_analysis', {}).get('reasoning')}")
            
            flagged = data.get('threat_analysis', {}).get('flagged_phrases', [])
            print_info(f"Flagged Phrases ({len(flagged)}): {', '.join(flagged[:5])}")
            
            if data.get('verdict') == 'CRITICAL':
                print_success("Correctly identified as CRITICAL threat")
                return True
            else:
                print_error(f"Expected CRITICAL, got {data.get('verdict')}")
                return False
        else:
            print_error(f"Unexpected status code: {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Critical threat scan failed: {e}")
        return False

def test_cache_functionality() -> bool:
    """Test that caching works correctly"""
    print_test("Cache Functionality")
    
    payload = {
        "sender": "test@example.com",
        "body": "This is a test email for cache testing",
        "links": []
    }
    
    try:
        # First request - should not be cached
        start_time = time.time()
        response1 = requests.post(f"{BASE_URL}/scan", json=payload, timeout=TIMEOUT)
        time1 = time.time() - start_time
        
        if response1.status_code != 200:
            print_error(f"First request failed: {response1.status_code}")
            return False
        
        data1 = response1.json()
        print_info(f"First request time: {time1:.3f}s")
        print_info(f"First request cached: {data1.get('cached')}")
        
        # Second request - should be cached
        time.sleep(0.5)  # Small delay
        start_time = time.time()
        response2 = requests.post(f"{BASE_URL}/scan", json=payload, timeout=TIMEOUT)
        time2 = time.time() - start_time
        
        if response2.status_code != 200:
            print_error(f"Second request failed: {response2.status_code}")
            return False
        
        data2 = response2.json()
        print_info(f"Second request time: {time2:.3f}s")
        print_info(f"Second request cached: {data2.get('cached')}")
        
        # Verify caching worked
        if data2.get('cached'):
            print_success("Cache is working correctly")
            if time2 < time1:
                print_success(f"Cached request was faster ({time2:.3f}s vs {time1:.3f}s)")
            return True
        else:
            print_error("Second request was not cached")
            return False
            
    except Exception as e:
        print_error(f"Cache functionality test failed: {e}")
        return False

def test_invalid_request() -> bool:
    """Test handling of invalid requests"""
    print_test("Invalid Request Handling")
    
    # Missing required fields
    payload = {
        "sender": "test@example.com"
        # Missing 'body' and 'links'
    }
    
    try:
        response = requests.post(f"{BASE_URL}/scan", json=payload, timeout=TIMEOUT)
        
        if response.status_code == 422:  # Validation error
            print_success("Correctly rejected invalid request with 422")
            return True
        else:
            print_error(f"Expected 422, got {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Invalid request test failed: {e}")
        return False

def run_all_tests():
    """Run all tests and report results"""
    print_header("ZeroPhish Tier 2 Backend - Comprehensive Test Suite")
    
    tests = [
        ("Health Check", test_health_check),
        ("Cache Statistics", test_cache_stats),
        ("Threat Patterns", test_threat_patterns),
        ("Safe Email Scan", test_scan_safe_email),
        ("Suspicious Email Scan", test_scan_suspicious_email),
        ("Critical Threat Scan", test_scan_critical_threat),
        ("Cache Functionality", test_cache_functionality),
        ("Invalid Request Handling", test_invalid_request),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
        print()  # Blank line between tests
    
    # Summary
    print_header("Test Results Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Colors.GREEN}✅ PASS{Colors.RESET}" if result else f"{Colors.RED}❌ FAIL{Colors.RESET}"
        print(f"{status} - {test_name}")
    
    print(f"\n{Colors.BOLD}Total: {passed}/{total} tests passed{Colors.RESET}")
    
    if passed == total:
        print(f"{Colors.GREEN}{Colors.BOLD}🎉 All tests passed! Backend is working perfectly!{Colors.RESET}\n")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  Some tests failed. Review the output above.{Colors.RESET}\n")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = run_all_tests()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Tests interrupted by user{Colors.RESET}")
        exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Test suite crashed: {e}{Colors.RESET}")
        exit(1)
