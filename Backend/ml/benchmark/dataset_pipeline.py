"""
ZeroPhish Benchmark Dataset Pipeline & Data-Quality Auditing Module.
Implements URL normalization, parameter stripping, exact & domain-level deduplication,
and produces Stratified Random, Domain-Disjoint, Temporal, and Adversarial/Edge-Case Splits.
"""

from __future__ import annotations

import logging
import random
import re
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

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

TWO_LEVEL_TLDS = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "com.br",
    "gov.br",
    "co.jp",
    "ne.jp",
    "com.cn",
    "net.cn",
    "co.in",
    "net.in",
    "gov.in",
}


@dataclass
class BenchmarkSample:
    url: str
    label: int  # 1 = Phishing, 0 = Legitimate
    domain: str
    registered_domain: str
    category: str
    is_adversarial: bool = False
    source: str = "curated_benchmark"
    timestamp: str = "2026-08-01"


@dataclass
class DataQualityReport:
    total_raw_samples: int
    normalized_samples: int
    exact_duplicate_count: int
    duplicate_rate: float
    unique_domains: int
    unique_registered_domains: int
    benign_count: int
    phishing_count: int
    imbalance_ratio: float
    adversarial_sample_count: int
    domain_overlap_between_splits: int = 0


class DatasetPipeline:
    """End-to-end dataset preparation pipeline for reproducible evaluation."""

    @staticmethod
    def extract_root_domain(url: str) -> str:
        """Extract hostname from URL."""
        norm = URLPreprocessor.preprocess(url)
        try:
            parsed = urllib.parse.urlparse(norm)
            host = parsed.hostname or ""
            return host.lower()
        except Exception:
            return ""

    @staticmethod
    def extract_registered_domain(host: str) -> str:
        """Extract registrable root domain (e.g. sub.example.co.uk -> example.co.uk)."""
        if not host:
            return ""
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()

        # Check 2-level TLDs
        possible_tld = ".".join(parts[-2:])
        if possible_tld in TWO_LEVEL_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

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
        cls, raw_records: List[Any]
    ) -> Tuple[List[BenchmarkSample], DataQualityReport]:
        """
        Normalize, strip tracking params, deduplicate, and audit raw records.
        Records format: (url, label, category, [source], [is_adversarial], [timestamp])
        """
        seen_urls: Set[str] = set()
        samples: List[BenchmarkSample] = []
        exact_duplicates = 0

        for record in raw_records:
            url = record[0]
            label = int(record[1])
            category = str(record[2])
            source = (
                str(record[3])
                if len(record) > 3
                and isinstance(record[3], str)
                and not isinstance(record[3], bool)
                else "curated_benchmark"
            )
            is_adv = (
                bool(record[4])
                if len(record) > 4 and isinstance(record[4], bool)
                else (bool(record[3]) if len(record) > 3 and isinstance(record[3], bool) else False)
            )
            timestamp = str(record[5]) if len(record) > 5 else "2026-08-01"

            cleaned = URLPreprocessor.preprocess(url)
            stripped = cls.strip_tracking_params(cleaned)

            if not stripped:
                continue

            if stripped in seen_urls:
                exact_duplicates += 1
                continue

            seen_urls.add(stripped)
            domain = cls.extract_root_domain(stripped)
            reg_domain = cls.extract_registered_domain(domain)

            samples.append(
                BenchmarkSample(
                    url=stripped,
                    label=label,
                    domain=domain,
                    registered_domain=reg_domain,
                    category=category,
                    is_adversarial=is_adv,
                    source=source,
                    timestamp=timestamp,
                )
            )

        total_raw = len(raw_records)
        benign_count = sum(1 for s in samples if s.label == 0)
        phishing_count = sum(1 for s in samples if s.label == 1)
        unique_domains = len({s.domain for s in samples if s.domain})
        unique_reg_domains = len({s.registered_domain for s in samples if s.registered_domain})

        report = DataQualityReport(
            total_raw_samples=total_raw,
            normalized_samples=len(samples),
            exact_duplicate_count=exact_duplicates,
            duplicate_rate=round(exact_duplicates / total_raw, 4) if total_raw > 0 else 0.0,
            unique_domains=unique_domains,
            unique_registered_domains=unique_reg_domains,
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
        Split dataset such that every unique registered domain exists EXCLUSIVELY in either
        Train, Calibration, or Test splits. Eliminates cross-split memorization leakage.
        """
        rng = random.Random(seed)

        # Group samples by registered_domain
        domain_to_samples: Dict[str, List[BenchmarkSample]] = {}
        for s in samples:
            key = s.registered_domain or s.domain
            domain_to_samples.setdefault(key, []).append(s)

        domains = list(domain_to_samples.keys())
        rng.shuffle(domains)

        n_domains = len(domains)
        n_train = int(n_domains * train_ratio)
        n_cal = int(n_domains * cal_ratio)

        train_domains = set(domains[:n_train])
        cal_domains = set(domains[n_train : n_train + n_cal])
        test_domains = set(domains[n_train + n_cal :])

        train_set = [s for s in samples if (s.registered_domain or s.domain) in train_domains]
        cal_set = [s for s in samples if (s.registered_domain or s.domain) in cal_domains]
        test_set = [s for s in samples if (s.registered_domain or s.domain) in test_domains]

        return train_set, cal_set, test_set

    @classmethod
    def create_temporal_split(
        cls,
        samples: List[BenchmarkSample],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.25,
        test_ratio: float = 0.25,
    ) -> Tuple[List[BenchmarkSample], List[BenchmarkSample], List[BenchmarkSample]]:
        """
        Chronological temporal split:
        Train: older data (t0)
        Cal: mid period (t1)
        Test: latest holdout (t2)
        """
        sorted_samples = sorted(samples, key=lambda s: s.timestamp)
        n = len(sorted_samples)
        n_tr = int(n * train_ratio)
        n_ca = int(n * cal_ratio)

        return (
            sorted_samples[:n_tr],
            sorted_samples[n_tr : n_tr + n_ca],
            sorted_samples[n_tr + n_ca :],
        )

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
    """Legacy curated benchmark corpus."""
    from .external_dataset import get_multi_source_benchmark_corpus

    multi = get_multi_source_benchmark_corpus()
    return [(r[0], r[1], r[2], r[4]) for r in multi]
