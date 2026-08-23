"""
ZeroPhish Large-Scale URL Dataset Ingestion, Quality Auditing, and Split Pipeline.
Handles raw multi-source ingestion, tracking-parameter normalization, conflicting-label detection,
registered-domain aggregation, and immutable 4-way partitioning (Train / Cal / Val / Final Test).
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
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
class DatasetRecord:
    url: str
    label: int  # 1 = Phishing, 0 = Benign
    registered_domain: str
    domain: str
    source: str
    source_record_id: str
    observed_at: str
    category: str
    is_adversarial: bool = False
    label_conflict: bool = False


@dataclass
class IngestionStatistics:
    total_raw_ingested: int
    cleaned_records: int
    duplicates_removed: int
    conflicting_labels_flagged: int
    unique_domains: int
    unique_registered_domains: int
    benign_count: int
    phishing_count: int
    adversarial_count: int
    dataset_sha256: str


class DataQualityPipeline:
    """Ingests, cleans, audits, and normalizes URL datasets."""

    @staticmethod
    def extract_registered_domain(host: str) -> str:
        if not host:
            return ""
        parts = host.lower().split(".")
        if len(parts) <= 2:
            return host.lower()
        possible_tld = ".".join(parts[-2:])
        if possible_tld in TWO_LEVEL_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @classmethod
    def strip_tracking_parameters(cls, url: str) -> str:
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
    def ingest_and_clean(
        cls, raw_entries: List[Dict[str, Any]]
    ) -> Tuple[List[DatasetRecord], IngestionStatistics]:
        """
        Process raw records into clean, validated, deduped DatasetRecord objects.
        Detects conflicting labels across sources.
        """
        url_label_map: Dict[str, Set[int]] = {}
        cleaned_map: Dict[str, Dict[str, Any]] = {}
        exact_duplicates = 0

        for entry in raw_entries:
            raw_url = entry.get("url", "")
            label = int(entry.get("label", 0))

            cleaned = URLPreprocessor.preprocess(raw_url)
            normalized_url = cls.strip_tracking_parameters(cleaned)

            if not normalized_url:
                continue

            url_label_map.setdefault(normalized_url, set()).add(label)

            if normalized_url in cleaned_map:
                exact_duplicates += 1
                continue

            cleaned_map[normalized_url] = {
                "entry": entry,
                "url": normalized_url,
            }

        conflicting_count = 0
        final_records: List[DatasetRecord] = []
        hasher = hashlib.sha256()

        for norm_url, data in cleaned_map.items():
            entry = data["entry"]
            labels = url_label_map.get(norm_url, {0})
            is_conflict = len(labels) > 1

            if is_conflict:
                conflicting_count += 1

            label = int(entry.get("label", 0))
            parsed = urllib.parse.urlparse(norm_url)
            domain = (parsed.hostname or "").lower()
            reg_domain = cls.extract_registered_domain(domain)

            rec = DatasetRecord(
                url=norm_url,
                label=label,
                domain=domain,
                registered_domain=reg_domain,
                source=entry.get("source", "unknown"),
                source_record_id=entry.get(
                    "source_record_id", hashlib.md5(norm_url.encode()).hexdigest()[:12]
                ),
                observed_at=entry.get("observed_at", "2026-08-01"),
                category=entry.get("category", "general"),
                is_adversarial=bool(entry.get("is_adversarial", False)),
                label_conflict=is_conflict,
            )
            final_records.append(rec)
            hasher.update(norm_url.encode("utf-8"))

        benign_cnt = sum(1 for r in final_records if r.label == 0)
        phish_cnt = sum(1 for r in final_records if r.label == 1)
        unique_doms = len({r.domain for r in final_records if r.domain})
        unique_reg_doms = len({r.registered_domain for r in final_records if r.registered_domain})

        stats = IngestionStatistics(
            total_raw_ingested=len(raw_entries),
            cleaned_records=len(final_records),
            duplicates_removed=exact_duplicates,
            conflicting_labels_flagged=conflicting_count,
            unique_domains=unique_doms,
            unique_registered_domains=unique_reg_doms,
            benign_count=benign_cnt,
            phishing_count=phish_cnt,
            adversarial_count=sum(1 for r in final_records if r.is_adversarial),
            dataset_sha256=hasher.hexdigest(),
        )

        return final_records, stats


class DatasetSplitter:
    """Creates immutable 4-way splits strictly segregated by registered domain."""

    @classmethod
    def create_4way_domain_disjoint_split(
        cls,
        records: List[DatasetRecord],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.15,
        val_ratio: float = 0.15,
        test_ratio: float = 0.20,
        seed: int = 42,
    ) -> Dict[str, List[DatasetRecord]]:
        """
        Partitions records into TRAIN, CALIBRATION, VALIDATION, and FINAL_TEST.
        Zero registered domain overlap across any two splits.
        """
        rng = random.Random(seed)

        # Exclude conflicting labels from supervised splits
        valid_records = [r for r in records if not r.label_conflict]

        # Group by registered domain
        domain_groups: Dict[str, List[DatasetRecord]] = {}
        for r in valid_records:
            key = r.registered_domain or r.domain
            domain_groups.setdefault(key, []).append(r)

        domains = list(domain_groups.keys())
        rng.shuffle(domains)

        n = len(domains)
        n_tr = int(n * train_ratio)
        n_ca = int(n * cal_ratio)
        n_va = int(n * val_ratio)

        train_doms = set(domains[:n_tr])
        cal_doms = set(domains[n_tr : n_tr + n_ca])
        val_doms = set(domains[n_tr + n_ca : n_tr + n_ca + n_va])
        test_doms = set(domains[n_tr + n_ca + n_va :])

        return {
            "TRAIN": [r for r in valid_records if (r.registered_domain or r.domain) in train_doms],
            "CALIBRATION": [
                r for r in valid_records if (r.registered_domain or r.domain) in cal_doms
            ],
            "VALIDATION": [
                r for r in valid_records if (r.registered_domain or r.domain) in val_doms
            ],
            "FINAL_TEST": [
                r for r in valid_records if (r.registered_domain or r.domain) in test_doms
            ],
        }

    @staticmethod
    def compute_split_hash(records: List[DatasetRecord]) -> str:
        """Compute SHA256 signature for a split."""
        h = hashlib.sha256()
        for r in sorted(records, key=lambda x: x.url):
            h.update(f"{r.url}:{r.label}".encode("utf-8"))
        return h.hexdigest()
