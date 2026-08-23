"""
Domain-Disjoint Splitting Module for Phase 5 Benchmark Generation.
Guarantees 100% isolation of registered domains across Train, Calibration, Validation, and Final Test.
"""

from __future__ import annotations

import hashlib
import random
from typing import Dict, List, Set, Tuple

from ..schemas.v3 import DatasetRecordV3, SplitManifestV3


class DomainDisjointSplitter:
    """Enforces zero domain-overlap 4-way partitioning."""

    @classmethod
    def compute_split_sha256(cls, records: List[DatasetRecordV3]) -> str:
        h = hashlib.sha256()
        for r in sorted(records, key=lambda x: x.record_id):
            h.update(f"{r.record_id}:{r.url_model_input}:{r.label}".encode("utf-8"))
        return h.hexdigest()

    @classmethod
    def create_4way_split(
        cls,
        records: List[DatasetRecordV3],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.15,
        val_ratio: float = 0.15,
        test_ratio: float = 0.20,
        seed: int = 42,
    ) -> Tuple[Dict[str, List[DatasetRecordV3]], SplitManifestV3]:
        rng = random.Random(seed)

        # Exclude conflicting labels from supervised splits
        valid_records = [r for r in records if not r.label_conflict]

        # Group by registered domain
        domain_map: Dict[str, List[DatasetRecordV3]] = {}
        for r in valid_records:
            dom = r.registered_domain or r.hostname
            domain_map.setdefault(dom, []).append(r)

        domains = list(domain_map.keys())
        rng.shuffle(domains)

        n = len(domains)
        n_tr = int(n * train_ratio)
        n_ca = int(n * cal_ratio)
        n_va = int(n * val_ratio)

        train_doms = set(domains[:n_tr])
        cal_doms = set(domains[n_tr : n_tr + n_ca])
        val_doms = set(domains[n_tr + n_ca : n_tr + n_ca + n_va])
        test_doms = set(domains[n_tr + n_ca + n_va :])

        train_recs = [r for r in valid_records if (r.registered_domain or r.hostname) in train_doms]
        cal_recs = [r for r in valid_records if (r.registered_domain or r.hostname) in cal_doms]
        val_recs = [r for r in valid_records if (r.registered_domain or r.hostname) in val_doms]
        test_recs = [r for r in valid_records if (r.registered_domain or r.hostname) in test_doms]

        # Disjointness check
        is_disjoint = (
            train_doms.isdisjoint(cal_doms)
            and train_doms.isdisjoint(val_doms)
            and train_doms.isdisjoint(test_doms)
            and cal_doms.isdisjoint(val_doms)
            and cal_doms.isdisjoint(test_doms)
            and val_doms.isdisjoint(test_doms)
        )

        manifest = SplitManifestV3(
            train_count=len(train_recs),
            calibration_count=len(cal_recs),
            validation_count=len(val_recs),
            final_test_count=len(test_recs),
            train_sha256=cls.compute_split_sha256(train_recs),
            calibration_sha256=cls.compute_split_sha256(cal_recs),
            validation_sha256=cls.compute_split_sha256(val_recs),
            final_test_sha256=cls.compute_split_sha256(test_recs),
            final_test_frozen=True,
            disjoint_guarantee_verified=is_disjoint,
        )

        splits = {
            "TRAIN": train_recs,
            "CALIBRATION": cal_recs,
            "VALIDATION": val_recs,
            "FINAL_TEST": test_recs,
        }

        return splits, manifest
