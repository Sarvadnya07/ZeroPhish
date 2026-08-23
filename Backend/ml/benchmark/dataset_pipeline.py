"""
ZeroPhish Benchmark Dataset Pipeline & Data-Quality Auditing Module.
Implements URL normalization, parameter stripping, exact & domain-level deduplication,
and produces Stratified Random, Domain-Disjoint, and Adversarial/Edge-Case Splits.
"""

from __future__ import annotations

import logging
import random
import re
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Set, Tuple

from ..url_preprocessor import URLPreprocessor

logger = logging.getLogger(__name__)

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "ref",
    "source",
}


@dataclass
class BenchmarkSample:
    url: str
    label: int  # 1 = Phishing, 0 = Legitimate
    domain: str
    category: str
    is_adversarial: bool = False
    source: str = "curated_benchmark"


@dataclass
class DataQualityReport:
    total_raw_samples: int
    normalized_samples: int
    exact_duplicate_count: int
    duplicate_rate: float
    unique_domains: int
    benign_count: int
    phishing_count: int
    imbalance_ratio: float
    adversarial_sample_count: int
    domain_overlap_between_splits: int = 0


class DatasetPipeline:
    """End-to-end dataset preparation pipeline for reproducible evaluation."""

    @staticmethod
    def extract_root_domain(url: str) -> str:
        """Extract registrable hostname/domain from URL."""
        norm = URLPreprocessor.preprocess(url)
        try:
            parsed = urllib.parse.urlparse(norm)
            host = parsed.hostname or ""
            return host.lower()
        except Exception:
            return ""

    @classmethod
    def strip_tracking_params(cls, url: str) -> str:
        """Remove marketing tracking parameters while preserving functional paths and parameters."""
        try:
            parsed = urllib.parse.urlparse(url)
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            filtered = [(k, v) for k, v in query_tuples if k.lower() not in TRACKING_PARAMS]
            new_query = urllib.parse.urlencode(filtered)
            return urllib.parse.urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )
        except Exception:
            return url

    @classmethod
    def prepare_dataset(
        cls, raw_records: List[Tuple[str, int, str, bool]]
    ) -> Tuple[List[BenchmarkSample], DataQualityReport]:
        """
        Normalize, strip tracking params, deduplicate, and audit raw records.
        Records format: (url, label, category, is_adversarial)
        """
        seen_urls: Set[str] = set()
        samples: List[BenchmarkSample] = []
        exact_duplicates = 0

        for url, label, category, is_adv in raw_records:
            cleaned = URLPreprocessor.preprocess(url)
            stripped = cls.strip_tracking_params(cleaned)

            if not stripped:
                continue

            if stripped in seen_urls:
                exact_duplicates += 1
                continue

            seen_urls.add(stripped)
            domain = cls.extract_root_domain(stripped)
            samples.append(
                BenchmarkSample(
                    url=stripped,
                    label=int(label),
                    domain=domain,
                    category=category,
                    is_adversarial=is_adv,
                )
            )

        total_raw = len(raw_records)
        benign_count = sum(1 for s in samples if s.label == 0)
        phishing_count = sum(1 for s in samples if s.label == 1)
        unique_domains = len({s.domain for s in samples if s.domain})

        report = DataQualityReport(
            total_raw_samples=total_raw,
            normalized_samples=len(samples),
            exact_duplicate_count=exact_duplicates,
            duplicate_rate=round(exact_duplicates / total_raw, 4) if total_raw > 0 else 0.0,
            unique_domains=unique_domains,
            benign_count=benign_count,
            phishing_count=phishing_count,
            imbalance_ratio=round(phishing_count / benign_count, 2) if benign_count > 0 else 0.0,
            adversarial_sample_count=sum(1 for s in samples if s.is_adversarial),
        )

        return samples, report

    @classmethod
    def create_domain_disjoint_split(
        cls,
        samples: List[BenchmarkSample],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.25,
        test_ratio: float = 0.25,
        seed: int = 42,
    ) -> Tuple[List[BenchmarkSample], List[BenchmarkSample], List[BenchmarkSample]]:
        """
        Split dataset such that every unique domain exists EXCLUSIVELY in either
        Train, Calibration, or Test splits. Eliminates cross-split memorization leakage.
        """
        rng = random.Random(seed)

        # Group samples by domain
        domain_to_samples: Dict[str, List[BenchmarkSample]] = {}
        for s in samples:
            domain_to_samples.setdefault(s.domain, []).append(s)

        domains = list(domain_to_samples.keys())
        rng.shuffle(domains)

        n_domains = len(domains)
        n_train = int(n_domains * train_ratio)
        n_cal = int(n_domains * cal_ratio)

        train_domains = set(domains[:n_train])
        cal_domains = set(domains[n_train : n_train + n_cal])
        test_domains = set(domains[n_train + n_cal :])

        train_set = [s for s in samples if s.domain in train_domains]
        cal_set = [s for s in samples if s.domain in cal_domains]
        test_set = [s for s in samples if s.domain in test_domains]

        return train_set, cal_set, test_set

    @classmethod
    def create_stratified_random_split(
        cls,
        samples: List[BenchmarkSample],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.25,
        test_ratio: float = 0.25,
        seed: int = 42,
    ) -> Tuple[List[BenchmarkSample], List[BenchmarkSample], List[BenchmarkSample]]:
        """Standard stratified random row split."""
        rng = random.Random(seed)

        positives = [s for s in samples if s.label == 1]
        negatives = [s for s in samples if s.label == 0]

        rng.shuffle(positives)
        rng.shuffle(negatives)

        def _split_list(lst: List[BenchmarkSample]):
            n = len(lst)
            n_tr = int(n * train_ratio)
            n_ca = int(n * cal_ratio)
            return lst[:n_tr], lst[n_tr : n_tr + n_ca], lst[n_tr + n_ca :]

        p_tr, p_ca, p_te = _split_list(positives)
        n_tr, n_ca, n_te = _split_list(negatives)

        return p_tr + n_tr, p_ca + n_ca, p_te + n_te


def get_curated_benchmark_corpus() -> List[Tuple[str, int, str, bool]]:
    """
    Curated, verified benchmark corpus covering standard legitimate platforms,
    phishing attacks, and adversarial evasion techniques (Punycode, RTLO, IP hosts, obfuscation).
    """
    return [
        # --- Legitimate Standard Top Domains (Label: 0) ---
        ("https://www.google.com/search?q=cybersecurity", 0, "legit_top_domain", False),
        ("https://github.com/ZeroPhish/security-core/commits", 0, "legit_top_domain", False),
        ("https://en.wikipedia.org/wiki/Phishing", 0, "legit_top_domain", False),
        ("https://aws.amazon.com/security/best-practices", 0, "legit_top_domain", False),
        ("https://www.apple.com/support/contact/", 0, "legit_top_domain", False),
        ("https://learn.microsoft.com/en-us/azure/security/", 0, "legit_top_domain", False),
        ("https://stackoverflow.com/questions/tagged/python", 0, "legit_top_domain", False),
        ("https://developer.mozilla.org/en-US/docs/Web/HTTP", 0, "legit_top_domain", False),
        ("https://www.python.org/downloads/release/python-312/", 0, "legit_top_domain", False),
        ("https://pypi.org/project/fastapi/#description", 0, "legit_top_domain", False),
        ("https://www.cloudflare.com/learning/security/", 0, "legit_top_domain", False),
        ("https://slack.com/help/articles/security", 0, "legit_top_domain", False),
        ("https://www.cnn.com/world/security-news", 0, "legit_news", False),
        ("https://www.nytimes.com/section/technology", 0, "legit_news", False),
        ("https://medium.com/topic/cybersecurity", 0, "legit_blog", False),
        ("https://news.ycombinator.com/item?id=38491", 0, "legit_forum", False),
        ("https://reddit.com/r/netsec/comments/security", 0, "legit_forum", False),
        ("https://hub.docker.com/_/python", 0, "legit_dev", False),
        ("https://gitlab.com/gitlab-org/gitlab/-/issues", 0, "legit_dev", False),
        ("https://auth0.com/docs/authenticate/identity-providers", 0, "legit_auth", False),
        # --- Legitimate Complex & Deep Path URLs (Label: 0) ---
        (
            "https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn",
            0,
            "legit_login",
            False,
        ),
        ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", 0, "legit_login", False),
        (
            "https://www.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount",
            0,
            "legit_login",
            False,
        ),
        ("https://sso.okta.com/app/UserHome", 0, "legit_login", False),
        ("https://signin.aws.amazon.com/oauth?client_id=arn%3Aaws", 0, "legit_login", False),
        (
            "https://auth.atlassian.com/login?continue=https%3A%2F%2Fid.atlassian.com",
            0,
            "legit_login",
            False,
        ),
        ("https://id.dropbox.com/oauth2/authorize?client_id=dropbox", 0, "legit_login", False),
        (
            "https://zoom.us/signin?redirect_uri=https%3A%2F%2Fzoom.us%2Fprofile",
            0,
            "legit_login",
            False,
        ),
        ("https://store.steampowered.com/login/?redir=app%2F730", 0, "legit_login", False),
        (
            "https://www.netflix.com/login?nextpage=https%3A%2F%2Fwww.netflix.com%2Fbrowse",
            0,
            "legit_login",
            False,
        ),
        # --- Phishing Credential Harvesting (Label: 1) ---
        ("http://paypa1-account-verification.com/login.php", 1, "phish_typosquat", False),
        ("http://paypal-security-update.center/signin/auth.html", 1, "phish_credential", False),
        ("http://apple-security-id.account-verify.xyz/login", 1, "phish_credential", False),
        ("http://service-paypal.com.account-update.top/auth", 1, "phish_subdomain", False),
        ("http://microsoft-support-alert.com/urgent-reset", 1, "phish_brand", False),
        ("http://verify-bank-credentials.cc/secure/portal.html", 1, "phish_financial", False),
        ("http://netflix-billing-alert.info/payment/update", 1, "phish_billing", False),
        ("http://secure-chase-update.biz/login/auth.do", 1, "phish_financial", False),
        ("http://google-drive-shared-doc.xyz/verify/access.php", 1, "phish_credential", False),
        ("http://wellsfargo-online-secure-auth.top/signin", 1, "phish_financial", False),
        ("http://bankofamerica-login-verify.cc/account", 1, "phish_financial", False),
        ("http://amazon-account-suspension.xyz/restore", 1, "phish_brand", False),
        ("http://dhl-package-tracking-alert.top/delivery", 1, "phish_delivery", False),
        ("http://fedex-parcel-redelivery-fee.info/pay", 1, "phish_delivery", False),
        ("http://office365-urgent-password-expire.net/owa", 1, "phish_credential", False),
        ("http://coinbase-wallet-security-unlock.xyz/auth", 1, "phish_crypto", False),
        ("http://binance-kyc-verification-required.top/verify", 1, "phish_crypto", False),
        ("http://metamask-seed-phrase-sync.biz/recovery", 1, "phish_crypto", False),
        ("http://irs-tax-refund-urgent-claim.cc/forms", 1, "phish_gov", False),
        ("http://usps-failed-address-update.xyz/tracking", 1, "phish_delivery", False),
        # --- Adversarial & Evasion Samples (Label: 1) ---
        ("http://192.168.1.105/auth/bank-update/login.html", 1, "adv_ip_host", True),
        ("http://10.0.0.15:8080/secure-login/oauth", 1, "adv_ip_port", True),
        ("http://xn--pypal-4ve.com/secure-signin/index.html", 1, "adv_punycode", True),
        ("http://xn--microsft-n4a.com/login/auth", 1, "adv_punycode", True),
        ("http://trusted-brand.com@evil-phishing-host.xyz/login", 1, "adv_userinfo", True),
        ("http://paypal.com@192.168.4.1/auth/verify", 1, "adv_userinfo_ip", True),
        ("http://secure-login.com%2eevil.top/session", 1, "adv_encoded_delimiter", True),
        (
            "http://www.google.com.attacker-controlled-subdomain.xyz/login",
            1,
            "adv_nested_subdomain",
            True,
        ),
        ("http://update-account.tk/signin", 1, "adv_suspicious_tld", True),
        ("http://verify-id.gq/auth", 1, "adv_suspicious_tld", True),
        # --- Adversarial Legitimate Samples (Label: 0) (High-Entropy & Non-Standard Benign) ---
        ("https://i.stack.imgur.com/7wKp9.png", 0, "adv_legit_short", True),
        (
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
            0,
            "adv_legit_cdn",
            True,
        ),
        (
            "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js",
            0,
            "adv_legit_cdn",
            True,
        ),
        ("https://raw.githubusercontent.com/psf/black/main/README.md", 0, "adv_legit_raw", True),
        (
            "https://gitlab-ci-token:glpat-12345@gitlab.example.com/api/v4/projects",
            0,
            "adv_legit_userinfo",
            True,
        ),
        ("http://127.0.0.1:8000/docs", 0, "adv_legit_localhost", True),
        ("http://localhost:3000/dashboard", 0, "adv_legit_localhost", True),
        (
            "https://s3.us-west-2.amazonaws.com/my-bucket-archive/logs_2026_08.tar.gz",
            0,
            "adv_legit_s3",
            True,
        ),
        (
            "https://storage.googleapis.com/public-dataset-bucket/index.html",
            0,
            "adv_legit_gcs",
            True,
        ),
        (
            "https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade",
            0,
            "adv_legit_hash_route",
            True,
        ),
    ]
