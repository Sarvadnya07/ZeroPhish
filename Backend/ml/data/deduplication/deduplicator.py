"""
Multi-Level URL Deduplication and Conflicting-Label Detection Module.
Provides deterministic 4-level deduplication statistics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from ..normalization.url_normalizer import URLNormalizer


@dataclass
class DeduplicationResult:
    unique_records: List[Dict[str, Any]]
    level1_exact_duplicates: int
    level2_normalized_duplicates: int
    level3_tracking_duplicates: int
    conflicting_labels_count: int
    conflict_records: List[Dict[str, Any]]


class MultiLevelDeduplicator:
    """Deduplicates raw threat records through sequential multi-tier filters."""

    @classmethod
    def process_records(cls, raw_records: List[Dict[str, Any]]) -> DeduplicationResult:
        seen_exact_urls: Set[str] = set()
        seen_normalized_urls: Set[str] = set()
        seen_tracking_clean: Dict[str, Dict[str, Any]] = {}
        url_labels_map: Dict[str, Set[int]] = {}

        l1_dupes = 0
        l2_dupes = 0
        l3_dupes = 0

        for r in raw_records:
            url_raw = r.get("url", "").strip()
            label = int(r.get("label", 0))

            if not url_raw:
                continue

            # Level 1: Exact Raw URL
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

            # Level 3: Dedupe Canonical form (tracking param stripped)
            canon_form = URLNormalizer.to_dedupe_canonical_form(url_raw)
            url_labels_map.setdefault(canon_form, set()).add(label)

            if canon_form in seen_tracking_clean:
                l3_dupes += 1
            else:
                seen_tracking_clean[canon_form] = {
                    "raw_entry": r,
                    "canon_url": canon_form,
                    "model_url": model_form,
                }

        # Analyze conflicts
        conflict_list: List[Dict[str, Any]] = []
        clean_entries: List[Dict[str, Any]] = []

        for canon_url, data in seen_tracking_clean.items():
            labels = url_labels_map.get(canon_url, {0})
            is_conflict = len(labels) > 1

            entry = data["raw_entry"]
            entry_dict = {
                **entry,
                "url_original": entry.get("url", ""),
                "url_dedupe_canonical": canon_url,
                "url_model_input": data["model_url"],
                "label_conflict": is_conflict,
            }

            if is_conflict:
                conflict_list.append(entry_dict)

            clean_entries.append(entry_dict)

        return DeduplicationResult(
            unique_records=clean_entries,
            level1_exact_duplicates=l1_dupes,
            level2_normalized_duplicates=l2_dupes,
            level3_tracking_duplicates=l3_dupes,
            conflicting_labels_count=len(conflict_list),
            conflict_records=conflict_list,
        )
