"""
Multi-Level URL Deduplication and Conflicting-Label Detection Module.

Provides deterministic 4-level deduplication statistics:
- Level 1: Exact raw URL match.
- Level 2: Normalized (model-input) form match.
- Level 3: Canonical form after stripping tracking parameters.
- Level 4 (conflict detection): Different labels for the same canonical URL.

This module ensures data quality by identifying duplicates and label conflicts
across multiple URL representations, which is critical for benchmark integrity.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple, Optional

from ..normalization.url_normalizer import URLNormalizer

logger = logging.getLogger(__name__)

# Constants
VALID_LABELS = {0, 1}
LABEL_BENIGN = 0
LABEL_PHISHING = 1


@dataclass
class DeduplicationResult:
    """
    Result of the multi-level deduplication process.

    Attributes:
        unique_records: List of deduplicated records (with conflict flag).
        level1_exact_duplicates: Count of exact raw URL duplicates.
        level2_normalized_duplicates: Count of normalized-form duplicates.
        level3_tracking_duplicates: Count of canonical-form duplicates.
        conflicting_labels_count: Number of records with conflicting labels.
        conflict_records: List of records that have label conflicts.
    """
    unique_records: List[Dict[str, Any]]
    level1_exact_duplicates: int
    level2_normalized_duplicates: int
    level3_tracking_duplicates: int
    conflicting_labels_count: int
    conflict_records: List[Dict[str, Any]]


class MultiLevelDeduplicator:
    """
    Deduplicates raw threat records through sequential multi-tier filters.

    The deduplication process:
    1. Exact URL deduplication (case‑sensitive).
    2. Normalized (model‑input) URL deduplication.
    3. Canonical URL deduplication (tracking parameters stripped).
    4. Label conflict detection across canonical URLs.
    """

    @classmethod
    def process_records(cls, raw_records: List[Dict[str, Any]]) -> DeduplicationResult:
        """
        Process a list of raw records through the multi‑level deduplicator.

        Args:
            raw_records: List of dictionaries, each containing at least "url" and "label".

        Returns:
            DeduplicationResult with deduplicated records and statistics.

        Raises:
            ValueError: If a record is missing "url" or has an invalid label.
        """
        if not raw_records:
            return DeduplicationResult([], 0, 0, 0, 0, [])

        # Track URLs at each level
        seen_exact_urls: Set[str] = set()
        seen_normalized_urls: Set[str] = set()
        seen_canonical_urls: Set[str] = set()

        # Track label sets per canonical URL for conflict detection
        canonical_label_map: Dict[str, Set[int]] = {}

        # Store the first occurrence of each canonical URL
        canonical_entry_map: Dict[str, Dict[str, Any]] = {}

        l1_dupes = 0
        l2_dupes = 0
        l3_dupes = 0
        total_records = len(raw_records)

        for idx, record in enumerate(raw_records):
            # Validate record
            if not isinstance(record, dict):
                logger.warning("Skipping non-dict record at index %d", idx)
                continue

            url_raw = record.get("url")
            if not url_raw or not isinstance(url_raw, str):
                logger.warning("Skipping record %d: missing or invalid 'url'", idx)
                continue

            url_raw = url_raw.strip()
            if not url_raw:
                logger.warning("Skipping record %d: empty URL", idx)
                continue

            label = record.get("label")
            if label is None:
                logger.warning("Record %d missing 'label'; defaulting to 0", idx)
                label = 0
            try:
                label_int = int(label)
                if label_int not in VALID_LABELS:
                    raise ValueError(f"Invalid label {label_int}, must be 0 or 1")
            except (ValueError, TypeError):
                logger.warning("Record %d has invalid label '%s'; defaulting to 0", idx, label)
                label_int = 0

            # Level 1: Exact raw URL
            if url_raw in seen_exact_urls:
                l1_dupes += 1
            else:
                seen_exact_urls.add(url_raw)

            # Level 2: Model input normalized form
            model_form = URLNormalizer.to_model_input_form(url_raw)
            if model_form in seen_normalized_urls:
                l2_dupes += 1
            else:
                seen_normalized_urls.add(model_form)

            # Level 3: Canonical form (tracking params stripped)
            canon_form = URLNormalizer.to_dedupe_canonical_form(url_raw)
            if canon_form in seen_canonical_urls:
                l3_dupes += 1
            else:
                seen_canonical_urls.add(canon_form)

            # Track labels for conflict detection
            canonical_label_map.setdefault(canon_form, set()).add(label_int)

            # Keep the first occurrence for each canonical URL
            if canon_form not in canonical_entry_map:
                canonical_entry_map[canon_form] = {
                    "raw_entry": record,
                    "canon_url": canon_form,
                    "model_url": model_form,
                    "original_url": url_raw,
                }

        # Build deduplicated records and conflict list
        conflict_list: List[Dict[str, Any]] = []
        clean_entries: List[Dict[str, Any]] = []

        for canon_url, entry_data in canonical_entry_map.items():
            labels = canonical_label_map.get(canon_url, {0})
            is_conflict = len(labels) > 1

            base_entry = entry_data["raw_entry"].copy()
            enriched_entry = {
                **base_entry,
                "url_original": entry_data["original_url"],
                "url_dedupe_canonical": canon_url,
                "url_model_input": entry_data["model_url"],
                "label_conflict": is_conflict,
                "label_set": sorted(labels) if is_conflict else list(labels),
            }
            # Ensure label is set to the most common or first label if conflict
            if is_conflict:
                # Keep the original label but flag conflict
                enriched_entry["label"] = base_entry.get("label", 0)
            else:
                enriched_entry["label"] = next(iter(labels))

            if is_conflict:
                conflict_list.append(enriched_entry)

            clean_entries.append(enriched_entry)

        # Log summary
        logger.info(
            "Deduplication complete: %d raw records → %d unique (L1 dupes: %d, L2: %d, L3: %d, conflicts: %d)",
            total_records,
            len(clean_entries),
            l1_dupes,
            l2_dupes,
            l3_dupes,
            len(conflict_list),
        )

        return DeduplicationResult(
            unique_records=clean_entries,
            level1_exact_duplicates=l1_dupes,
            level2_normalized_duplicates=l2_dupes,
            level3_tracking_duplicates=l3_dupes,
            conflicting_labels_count=len(conflict_list),
            conflict_records=conflict_list,
        )

    @classmethod
    def get_duplicate_summary(cls, result: DeduplicationResult) -> Dict[str, Any]:
        """
        Generate a human‑readable summary of the deduplication result.

        Args:
            result: DeduplicationResult from process_records().

        Returns:
            Dictionary with summary statistics.
        """
        return {
            "unique_records": len(result.unique_records),
            "level1_exact_duplicates": result.level1_exact_duplicates,
            "level2_normalized_duplicates": result.level2_normalized_duplicates,
            "level3_tracking_duplicates": result.level3_tracking_duplicates,
            "conflicting_labels_count": result.conflicting_labels_count,
            "total_duplicates_removed": (
                result.level1_exact_duplicates
                + result.level2_normalized_duplicates
                + result.level3_tracking_duplicates
            ),
        }