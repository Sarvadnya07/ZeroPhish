"""
Tier 3: Semantic AI Brain for Zero-Day Phishing Detection

This module provides Gemini-powered semantic analysis to catch sophisticated
phishing and social engineering attacks that traditional rules (T1) and 
technical metadata (T2) cannot detect.
"""

from tier_3.main import T3Result, T3Service, analyze_email_intent, get_t3_service

__all__ = [
    "T3Result",
    "T3Service",
    "analyze_email_intent",
    "get_t3_service",
]
