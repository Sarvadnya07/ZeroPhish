"""
Domain-Disjoint Splitting Module for Phase 5 Benchmark Generation.

Guarantees 100% isolation of registered domains across Train, Calibration,
Validation, and Final Test splits to prevent data leakage.

This module ensures that no registered domain appears in more than one split,
enabling unbiased evaluation of machine learning models.
"""

from __future__ import annotations

import hashlib
import logging
import random
from typing import Dict, List, Optional, Set, Tuple

from ..schemas.v3 import DatasetRecordV3, SplitManifestV3

logger = logging.getLogger(__name__)


class DomainDisjointSplitter:
    """
    Enforces zero domain-overlap 4-way partitioning.

    The splitting process:
    1. Excludes records with label conflicts (if any).
    2. Groups records by registered domain.
    3. Shuffles the list of distinct domains.
    4. Allocates domains to Train, Calibration, Validation, and Test splits.
    5. Verifies that no domain appears in more than one split.
    """

    @classmethod
    def compute_split_sha256(cls, records: List[DatasetRecordV3]) -> str:
        """
        Compute a deterministic SHA-256 hash of a list of records.

        The hash is computed from the sorted records by record_id, including
        the record_id, model_input, and label.

        Args:
            records: List of DatasetRecordV3.

        Returns:
            Hexadecimal SHA-256 digest.
        """
        if not records:
            return hashlib.sha256(b"").hexdigest()

        hasher = hashlib.sha256()
        sorted_records = sorted(records, key=lambda x: x.record_id)
        for r in sorted_records:
            line = f"{r.record_id}:{r.url_model_input}:{r.label}".encode("utf-8")
            hasher.update(line)
        return hasher.hexdigest()

    @classmethod
    def create_4way_split(
        cls,
        records: List[DatasetRecordV3],
        train_ratio: float = 0.50,
        cal_ratio: float = 0.15,
        val_ratio: float = 0.15,
        test_ratio: float = 0.20,
        seed: int = 42,
        exclude_conflicts: bool = True,
    ) -> Tuple[Dict[str, List[DatasetRecordV3]], SplitManifestV3]:
        """
        Create a 4-way domain-disjoint split.

        Args:
            records: List of DatasetRecordV3 objects.
            train_ratio: Proportion of domains for training.
            cal_ratio: Proportion for calibration.
            val_ratio: Proportion for validation.
            test_ratio: Proportion for final test.
            seed: Random seed for reproducibility.
            exclude_conflicts: If True, exclude records with label_conflict=True.

        Returns:
            Tuple of (splits_dict, SplitManifestV3).

        Raises:
            ValueError: If ratios don't sum to 1.0, or if records list is empty.
        """
        # Validate ratios
        total_ratio = train_ratio + cal_ratio + val_ratio + test_ratio
        if abs(total_ratio - 1.0) > 1e-6:
            raise ValueError(
                f"Ratios must sum to 1.0, got {train_ratio}+{cal_ratio}+{val_ratio}+{test_ratio}={total_ratio}"
            )

        if not records:
            raise ValueError("Empty records list provided for splitting")

        logger.info(
            "Starting 4-way domain-disjoint split: train=%.2f, cal=%.2f, val=%.2f, test=%.2f (seed=%d)",
            train_ratio, cal_ratio, val_ratio, test_ratio, seed
        )

        # Optionally exclude conflicting labels
        if exclude_conflicts:
            valid_records = [r for r in records if not getattr(r, "label_conflict", False)]
            logger.info("Excluded %d conflicting records, %d remaining",
                        len(records) - len(valid_records), len(valid_records))
        else:
            valid_records = records

        if not valid_records:
            raise ValueError("No valid records remain after excluding conflicts")

        # Group by registered domain
        domain_map: Dict[str, List[DatasetRecordV3]] = {}
        for r in valid_records:
            dom = r.registered_domain or r.hostname
            if not dom:
                logger.warning("Record %s has no registered_domain or hostname; skipping", r.record_id)
                continue
            domain_map.setdefault(dom, []).append(r)

        if not domain_map:
            raise ValueError("No records with valid registered domains")

        domains = list(domain_map.keys())
        rng = random.Random(seed)
        rng.shuffle(domains)

        n = len(domains)
        n_tr = int(n * train_ratio)
        n_ca = int(n * cal_ratio)
        n_va = int(n * val_ratio)
        # n_te = n - n_tr - n_ca - n_va

        train_doms = set(domains[:n_tr])
        cal_doms = set(domains[n_tr:n_tr + n_ca])
        val_doms = set(domains[n_tr + n_ca:n_tr + n_ca + n_va])
        test_doms = set(domains[n_tr + n_ca + n_va:])

        # Verify disjointness
        is_disjoint = (
            train_doms.isdisjoint(cal_doms)
            and train_doms.isdisjoint(val_doms)
            and train_doms.isdisjoint(test_doms)
            and cal_doms.isdisjoint(val_doms)
            and cal_doms.isdisjoint(test_doms)
            and val_doms.isdisjoint(test_doms)
        )

        if not is_disjoint:
            logger.error("Domain-disjoint guarantee violated! Check split logic.")
            raise RuntimeError("Domain-disjoint split failed; overlaps detected.")

        # Build record lists
        def _get_records_for_domains(dom_set: Set[str]) -> List[DatasetRecordV3]:
            result = []
            for d in dom_set:
                result.extend(domain_map.get(d, []))
            return result

        train_recs = _get_records_for_domains(train_doms)
        cal_recs = _get_records_for_domains(cal_doms)
        val_recs = _get_records_for_domains(val_doms)
        test_recs = _get_records_for_domains(test_doms)

        # Create manifest
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

        logger.info(
            "Split complete: train=%d (domains=%d), cal=%d (dom=%d), val=%d (dom=%d), test=%d (dom=%d)",
            len(train_recs), len(train_doms),
            len(cal_recs), len(cal_doms),
            len(val_recs), len(val_doms),
            len(test_recs), len(test_doms)
        )

        splits = {
            "TRAIN": train_recs,
            "CALIBRATION": cal_recs,
            "VALIDATION": val_recs,
            "FINAL_TEST": test_recs,
        }

        return splits, manifest