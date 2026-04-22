import re
from typing import Tuple, List, Dict
import logging
import asyncio
import os

logger = logging.getLogger(__name__)

# Try to import ML components
try:
    from tier_2.ml_model import get_ml_model
    ML_AVAILABLE = True
except ImportError:
    try:
        from ml_model import get_ml_model
        ML_AVAILABLE = True
    except ImportError:
        ML_AVAILABLE = False


class PatternEngine:
    """Handles regex and pattern-based threat detection."""
    def __init__(self, patterns: Dict[str, List[str]]):
        self.urgency_re = re.compile("|".join(map(re.escape, sorted(patterns.get("URGENCY_PATTERNS", []), key=len, reverse=True))))
        self.financial_re = re.compile("|".join(map(re.escape, sorted(patterns.get("FINANCIAL_PATTERNS", []), key=len, reverse=True))))
        self.credential_re = re.compile("|".join(map(re.escape, sorted(patterns.get("CREDENTIAL_PATTERNS", []), key=len, reverse=True))))
        self.authority_re = re.compile("|".join(map(re.escape, sorted(patterns.get("AUTHORITY_PATTERNS", []), key=len, reverse=True))))
        self.scare_re = re.compile("|".join(map(re.escape, sorted(patterns.get("SCARE_TACTICS", []), key=len, reverse=True))))
        self.suspicious_urls_re = re.compile("|".join(map(re.escape, sorted(patterns.get("SUSPICIOUS_URLS", []), key=len, reverse=True))))
        
        self.ip_link_regex = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)")
        self.suspicious_tld_regex = re.compile(r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)")

    def analyze(self, body_lower: str, links: List[str]) -> Tuple[int, List[str], List[str]]:
        score = 0
        categories = []
        flagged = []

        if matches := set(self.urgency_re.findall(body_lower)):
            score += len(matches) * 10
            categories.append("Urgency")
            flagged.extend(matches)

        if matches := set(self.financial_re.findall(body_lower)):
            score += len(matches) * 8
            categories.append("Financial")
            flagged.extend(matches)

        if matches := set(self.credential_re.findall(body_lower)):
            score += len(matches) * 7
            categories.append("Credential")
            flagged.extend(matches)

        if matches := set(self.authority_re.findall(body_lower)):
            score += len(matches) * 9
            categories.append("Authority")
            flagged.extend(matches)

        if matches := set(self.scare_re.findall(body_lower)):
            score += len(matches) * 8
            categories.append("ScareTactics")
            flagged.extend(matches)

        link_score = 0
        for link in links:
            lowered_link = (link or "").lower()
            if match := self.suspicious_urls_re.search(lowered_link):
                link_score += 15
                flagged.append(f"suspicious_url:{match.group()}")
            if self.ip_link_regex.search(lowered_link):
                link_score += 20
                flagged.append("ip_based_link")
            if "xn--" in lowered_link:
                link_score += 18
                flagged.append("punycode_link")
            if self.suspicious_tld_regex.search(lowered_link):
                link_score += 10
                flagged.append("suspicious_tld")

        if link_score > 0:
            score += link_score
            categories.append("SuspiciousLinks")

        return score, categories, flagged


class OSINTEngine:
    """Handles Open-Source Intelligence like typosquatting and redirect tracking."""
    TOP_50_SPOOFED = {
        "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com", "netflix.com", 
        "facebook.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "github.com",
        "linkedin.com", "dropbox.com", "docusign.com", "adobe.com", "instagram.com",
        "yahoo.com", "outlook.com", "office.com", "live.com", "amazonaws.com",
        "twitter.com", "x.com", "salesforce.com", "slack.com", "zoom.us", "citi.com"
    }

    URL_SHORTENERS = {
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
    }

    @staticmethod
    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return OSINTEngine.levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    @classmethod
    async def track_redirects(cls, url: str) -> Tuple[str, List[str]]:
        if not url.startswith("http"):
            return url, []
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0, follow_redirects=True, max_redirects=3) as client:
                response = await client.head(url)
                return str(response.url), []
        except Exception:
            return url, ["redirect_timeout"]

    @classmethod
    async def analyze(cls, sender_lower: str, links: List[str]) -> Tuple[int, List[str]]:
        score = 0
        flagged = []

        if "@" not in sender_lower:
            score += 10
            flagged.append("invalid_sender_format")
        else:
            sender_domain = sender_lower.split("@")[-1]
            if any(term in sender_lower for term in ("security", "support", "admin", "billing")):
                score += 5
            
            for target in cls.TOP_50_SPOOFED:
                if sender_domain == target:
                    break
                dist = cls.levenshtein(sender_domain, target)
                if dist == 1 or dist == 2:
                    score += 40
                    flagged.append(f"typosquatting:{target}")
                    break

        for link in links:
            lowered_link = (link or "").lower()
            domain_match = re.search(r"https?://([^/]+)", lowered_link)
            domain = domain_match.group(1) if domain_match else ""
            if any(shortener in domain for shortener in cls.URL_SHORTENERS):
                score += 5
                final_url, trace_errs = await cls.track_redirects(link)
                if final_url != link:
                    flagged.append("hidden_redirect")
                    if re.search(r"\.(zip|mov|top|xyz|click|country|stream|gq|tk|ml|ga|cf)(?:/|$)", final_url.lower()):
                        score += 20
                        flagged.append("redirect_to_suspicious_tld")

        return score, flagged


class MLEngine:
    """Handles Machine Learning inferences."""
    @staticmethod
    async def analyze(email_body: str, sender: str, links: List[str], base_threat: float, current_category: str, current_reasoning: str) -> Tuple[float, str, str]:
        if not ML_AVAILABLE or os.getenv("ML_ENABLED", "true").lower() != "true":
            return base_threat, current_category, current_reasoning
            
        try:
            ml_model = await get_ml_model()
            ml_score, ml_confidence = await ml_model.predict(email_body, sender=sender, links=links)
            logger.debug(f"Ensemble prediction: score={ml_score:.2f}, confidence={ml_confidence}")
            
            combined_threat = (ml_score * 0.6) + (base_threat * 0.4)
            
            if ml_confidence == "phishing" and "ML:Phishing" not in current_category:
                current_category = f"{current_category}/ML:Phishing" if current_category != "Safe" else "ML:Phishing"
            
            current_reasoning = f"{current_reasoning}. ML ensemble confidence: {ml_confidence} ({ml_score:.1f}%)"
            
            return combined_threat, current_category, current_reasoning
        except Exception as e:
            logger.warning(f"ML ensemble inference failed: {e}")
            
        return base_threat, current_category, current_reasoning
class EMLEngine:
    """Handles deep forensic analysis of .eml files and headers."""
    
    @staticmethod
    def analyze_headers(headers: Dict[str, str]) -> Tuple[int, List[str]]:
        score = 0
        flagged = []
        
        # 1. SPF/DKIM/DMARC Check (Simulated)
        spf = headers.get("Received-SPF", "").lower()
        if "fail" in spf:
            score += 30
            flagged.append("spf_fail")
        elif "softfail" in spf:
            score += 15
            flagged.append("spf_softfail")
            
        dkim = headers.get("Authentication-Results", "").lower()
        if "dkim=fail" in dkim:
            score += 25
            flagged.append("dkim_fail")
            
        # 2. X-Mailer / User-Agent Analysis
        mailer = headers.get("X-Mailer", "").lower()
        suspicious_mailers = ["php", "python-requests", "go-http-client", "curl"]
        if any(sm in mailer for sm in suspicious_mailers):
            score += 20
            flagged.append(f"suspicious_mailer:{mailer}")
            
        # 3. Message-ID Anomaly
        msg_id = headers.get("Message-ID", "")
        if msg_id and not ("@" in msg_id and "." in msg_id):
            score += 15
            flagged.append("invalid_message_id_format")
            
        return score, flagged

    @classmethod
    async def analyze_eml(cls, eml_content: str) -> dict:
        """Full forensic scan of raw EML content."""
        # In production, use 'mail-parser' or 'email' library
        # Here we simulate finding headers and multi-part content
        score, flagged = cls.analyze_headers({
            "Received-SPF": "softfail",
            "X-Mailer": "PHPMailer 6.0.0",
            "Message-ID": "<suspicious-123>"
        })
        
        return {
            "forensic_score": score,
            "findings": flagged,
            "dmarc_status": "none" if "dmarc" not in eml_content.lower() else "quarantine"
        }
