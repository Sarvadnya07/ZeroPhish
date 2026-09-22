"""
Evidence Normalizer for Detection Fusion
========================================
Normalizes raw strings, telemetry, and structured outputs from all tiers
into typed, deduplicated CanonicalEvidence objects with explicit provenance.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    AuthorityLevel,
    CanonicalEvidence,
    EvidenceSeverity,
    EvidenceSource,
)


class EvidenceNormalizer:
    """
    Transforms multi-tier scan findings into normalized CanonicalEvidence items.
    """

    @classmethod
    def normalize_tier1(
        cls,
        evidence_list: Optional[List[str]],
        source_label: str = "server_verified",
        server_score: Optional[int] = None,
    ) -> List[CanonicalEvidence]:
        """Normalize Tier 1 heuristic evidence."""
        if not evidence_list:
            return []

        results: List[CanonicalEvidence] = []
        seen_keys: Set[str] = set()

        for raw_item in evidence_list:
            item_str = str(raw_item).strip()
            if not item_str:
                continue

            # Detect advisory client tag vs authoritative server tag
            is_client = "[Client Advisory]" in item_str or source_label == "client"
            cleaned_desc = (
                item_str.replace("[Server Verified]", "")
                .replace("[Client Advisory]", "")
                .strip()
            )

            # Signal classification
            lower = cleaned_desc.lower()
            if lower.startswith("no ") or lower.startswith("valid ") or "clean" in lower:
                sig_type = "BENIGN_SIGNAL"
                sev = EvidenceSeverity.INFO
            elif "link" in lower or "url" in lower or "mismatch" in lower or "punycode" in lower:
                sig_type = "LINK_ANOMALY"
                sev = EvidenceSeverity.CRITICAL if ("punycode" in lower or "mismatch" in lower) else EvidenceSeverity.HIGH
            elif "sender" in lower or "display name" in lower or "spoof" in lower:
                sig_type = "SENDER_ANOMALY"
                sev = EvidenceSeverity.HIGH if "spoof" in lower else EvidenceSeverity.MEDIUM
            elif "keyword" in lower or "urgent" in lower or "action" in lower or "password" in lower:
                sig_type = "URGENCY_KEYWORD"
                sev = EvidenceSeverity.HIGH if ("password" in lower or "urgent" in lower) else EvidenceSeverity.MEDIUM
            elif "degraded" in lower or "internal error" in lower:
                sig_type = "TIER1_DEGRADED"
                sev = EvidenceSeverity.LOW
            else:
                sig_type = "HEURISTIC_MATCH"
                sev = EvidenceSeverity.LOW

            dedup_key = f"tier1:{sig_type}:{cleaned_desc.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.CLIENT_ADVISORY if is_client else EvidenceSource.TIER1,
                    signal_type=sig_type,
                    description=cleaned_desc,
                    severity=sev,
                    confidence=0.8 if is_client else 1.0,
                    authoritative=not is_client,
                    provenance="client_heuristic" if is_client else "server_heuristic",
                    metadata={"raw_entry": item_str},
                )
            )

        return results

    @classmethod
    def normalize_tier2(
        cls,
        evidence_list: Optional[List[str]],
        domain_age_days: Optional[int] = None,
        domain_status: Optional[str] = None,
        category: Optional[str] = None,
        flagged_phrases: Optional[List[str]] = None,
    ) -> List[CanonicalEvidence]:
        """Normalize Tier 2 domain, threat pattern, and ML evidence."""
        results: List[CanonicalEvidence] = []
        seen_keys: Set[str] = set()

        # 1. Domain Age Signal (Authoritative) - Strictly adheres to Phase 1.4 semantics:
        # Verified new (< 30 days) -> CRITICAL
        # Verified relatively new (< 365 days) -> SUSPICIOUS
        # Verified established (>= 365 days) -> OK
        # Missing / lookup failed -> UNKNOWN / ERROR
        effective_domain_status = domain_status
        if not effective_domain_status and domain_age_days is not None:
            if domain_age_days < 30:
                effective_domain_status = "CRITICAL"
            elif domain_age_days < 365:
                effective_domain_status = "SUSPICIOUS"
            else:
                effective_domain_status = "OK"

        if effective_domain_status == "CRITICAL":
            age_info = f" ({domain_age_days} days old)" if domain_age_days is not None else ""
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER2,
                    signal_type="NEW_DOMAIN",
                    description=f"Domain is newly registered (< 30 days old){age_info}.",
                    severity=EvidenceSeverity.CRITICAL,
                    confidence=1.0,
                    authoritative=True,
                    provenance="rdap_whois",
                    metadata={"status": effective_domain_status, "age_days": domain_age_days},
                )
            )
            seen_keys.add("NEW_DOMAIN")
        elif effective_domain_status == "SUSPICIOUS":
            age_info = f" ({domain_age_days} days old)" if domain_age_days is not None else ""
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER2,
                    signal_type="RECENT_DOMAIN",
                    description=f"Domain is relatively new (< 365 days old){age_info}.",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=1.0,
                    authoritative=True,
                    provenance="rdap_whois",
                    metadata={"status": effective_domain_status, "age_days": domain_age_days},
                )
            )
            seen_keys.add("RECENT_DOMAIN")
        elif effective_domain_status in ("UNKNOWN", "ERROR"):
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER2,
                    signal_type="DOMAIN_LOOKUP_INCOMPLETE",
                    description="Domain registration date could not be verified (lookup timed out or provider unavailable).",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.5,
                    authoritative=True,
                    provenance="rdap_whois",
                    metadata={"lookup_status": effective_domain_status},
                )
            )
            seen_keys.add("DOMAIN_LOOKUP_INCOMPLETE")

        # 2. ML Threat Category Signal (Advisory)
        if category and category.lower() not in ("safe", "ok", "processing", "unknown"):
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER2,
                    signal_type="ML_THREAT_PATTERN",
                    description=f"Threat intelligence detected pattern: {category}.",
                    severity=EvidenceSeverity.HIGH if category.lower() in ("phishing", "credential", "bec") else EvidenceSeverity.MEDIUM,
                    confidence=0.85,
                    authoritative=False,
                    provenance="tier2_ml_analyzer",
                    metadata={"category": category},
                )
            )

        # 3. Flagged phrases
        for phrase in flagged_phrases or []:
            phrase_clean = str(phrase).strip()
            if phrase_clean and phrase_clean.lower() not in seen_keys:
                seen_keys.add(phrase_clean.lower())
                results.append(
                    CanonicalEvidence(
                        source_tier=EvidenceSource.TIER2,
                        signal_type="THREAT_PHRASE",
                        description=f"Suspicious phrase identified: '{phrase_clean}'",
                        severity=EvidenceSeverity.MEDIUM,
                        confidence=0.9,
                        authoritative=True,
                        provenance="tier2_lexical_patterns",
                        metadata={"phrase": phrase_clean},
                    )
                )

        # 4. Process any extra evidence strings
        for raw_item in evidence_list or []:
            item_str = str(raw_item).strip()
            if not item_str:
                continue
            lower = item_str.lower()
            if "domain" in lower and ("new" in lower or "age" in lower or "lookup" in lower):
                continue  # Already captured in structured domain signal
            if "threat indicators detected" in lower or "flagged phrases" in lower:
                continue  # Already captured
            dedup_key = f"tier2:{item_str.lower()}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER2,
                    signal_type="INTEL_NOTE",
                    description=item_str,
                    severity=EvidenceSeverity.LOW,
                    confidence=1.0,
                    authoritative=True,
                    provenance="tier2_intel",
                )
            )

        return results

    @classmethod
    def normalize_tier3(
        cls,
        tier3_obj: Any,
    ) -> List[CanonicalEvidence]:
        """Normalize Tier 3 AI semantic findings (Advisory)."""
        if not tier3_obj:
            return []

        results: List[CanonicalEvidence] = []
        provider = getattr(tier3_obj, "provider", None) or "ai"
        model = getattr(tier3_obj, "model", None) or "llm"
        prov_str = f"{provider}:{model}"

        category = getattr(tier3_obj, "category", "")
        if category and category.lower() not in ("safe", "ok", "processing", "unknown", "ai_unavailable", "ai_timeout"):
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.TIER3,
                    signal_type="AI_SEMANTIC_INTENT",
                    description=f"AI identified high-risk intent: {category}",
                    severity=EvidenceSeverity.HIGH if category.lower() in ("credential harvesting", "bec", "phishing") else EvidenceSeverity.MEDIUM,
                    confidence=float(getattr(tier3_obj, "confidence", 0.9) or 0.9),
                    authoritative=False,
                    provenance=prov_str,
                    metadata={"category": category},
                )
            )

        for phrase in getattr(tier3_obj, "flagged_phrases", []) or []:
            phrase_str = str(phrase).strip()
            if phrase_str:
                results.append(
                    CanonicalEvidence(
                        source_tier=EvidenceSource.TIER3,
                        signal_type="AI_FLAGGED_PHRASE",
                        description=f"AI flagged semantic phrase: '{phrase_str}'",
                        severity=EvidenceSeverity.MEDIUM,
                        confidence=0.85,
                        authoritative=False,
                        provenance=prov_str,
                        metadata={"phrase": phrase_str},
                    )
                )

        return results

    @classmethod
    def normalize_vision(
        cls,
        vision_obj: Any,
    ) -> List[CanonicalEvidence]:
        """Normalize Vision visual findings (Advisory)."""
        if not vision_obj:
            return []

        results: List[CanonicalEvidence] = []
        status = getattr(vision_obj, "status", None)
        status_val = status.value if hasattr(status, "value") else str(status)

        # Brand mismatch is a CRITICAL visual signal
        if getattr(vision_obj, "brand_domain_mismatch", False):
            brands = getattr(vision_obj, "detected_brands", [])
            brand_str = ", ".join(brands) if brands else "known brand"
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.VISION,
                    signal_type="VISUAL_BRAND_DOMAIN_MISMATCH",
                    description=f"Visual brand/domain mismatch detected: UI displays {brand_str} on non-authoritative domain.",
                    severity=EvidenceSeverity.CRITICAL,
                    confidence=float(getattr(vision_obj, "confidence", 0.9) or 0.9),
                    authoritative=False,
                    provenance="vision_multimodal",
                    metadata={"brands": brands},
                )
            )
        elif getattr(vision_obj, "detected_brands", None):
            brands = getattr(vision_obj, "detected_brands", [])
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.VISION,
                    signal_type="VISUAL_BRAND_DETECTED",
                    description=f"Visual brand mark identified: {', '.join(brands)}.",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=float(getattr(vision_obj, "confidence", 0.8) or 0.8),
                    authoritative=False,
                    provenance="vision_multimodal",
                    metadata={"brands": brands},
                )
            )

        # Credential Harvesting UI
        if getattr(vision_obj, "credential_ui_detected", False):
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.VISION,
                    signal_type="VISUAL_CREDENTIAL_FORM",
                    description="Visual credential input form detected in screenshot.",
                    severity=EvidenceSeverity.HIGH,
                    confidence=float(getattr(vision_obj, "confidence", 0.85) or 0.85),
                    authoritative=False,
                    provenance="vision_multimodal",
                )
            )

        # Visual Impersonation Signal
        if getattr(vision_obj, "visual_impersonation_signal", False):
            results.append(
                CanonicalEvidence(
                    source_tier=EvidenceSource.VISION,
                    signal_type="VISUAL_IMPERSONATION_SIGNAL",
                    description="Visual layout strongly mimics a standard authentication portal.",
                    severity=EvidenceSeverity.HIGH,
                    confidence=float(getattr(vision_obj, "confidence", 0.85) or 0.85),
                    authoritative=False,
                    provenance="vision_multimodal",
                )
            )

        # Findings text
        for f in getattr(vision_obj, "findings", []) or []:
            f_str = str(f).strip()
            if f_str and not f_str.startswith("Vision finalizer error"):
                results.append(
                    CanonicalEvidence(
                        source_tier=EvidenceSource.VISION,
                        signal_type="VISUAL_OBSERVATION",
                        description=f_str,
                        severity=EvidenceSeverity.MEDIUM,
                        confidence=0.8,
                        authoritative=False,
                        provenance="vision_pixel_analysis",
                    )
                )

        return results

    @classmethod
    def deduplicate_and_merge(
        cls,
        evidence_items: List[CanonicalEvidence],
    ) -> Tuple[List[CanonicalEvidence], List[str]]:
        """
        Deduplicate evidence items while preserving highest severity and provenance.
        Returns (canonical_evidence_list, backward_compatible_string_list).
        """
        dedup_map: Dict[str, CanonicalEvidence] = {}
        for item in evidence_items:
            raw_text = item.description.lower()
            m = re.search(r"['\"](.*?)['\"]", raw_text)
            extracted_phrase = m.group(1).strip() if m else raw_text
            core_phrase = re.sub(r"[^\w\s]", "", extracted_phrase).strip()

            # Cross-tier phrase matching if phrase is significant
            matched_key = None
            if len(core_phrase) >= 10:
                for existing_key, existing_item in dedup_map.items():
                    m2 = re.search(r"['\"](.*?)['\"]", existing_item.description.lower())
                    existing_core = re.sub(
                        r"[^\w\s]", "", m2.group(1).strip() if m2 else existing_item.description.lower()
                    ).strip()
                    if existing_core and (core_phrase in existing_core or existing_core in core_phrase):
                        matched_key = existing_key
                        break

            use_key = matched_key or f"{item.source_tier.value}:{item.signal_type}:{core_phrase[:40]}"
            if use_key not in dedup_map:
                dedup_map[use_key] = item
            else:
                existing = dedup_map[use_key]
                if not existing.authoritative and item.authoritative:
                    dedup_map[use_key] = item
                elif item.severity.value == "CRITICAL" and existing.severity.value != "CRITICAL":
                    dedup_map[use_key] = item

        canonical_list = list(dedup_map.values())

        # Sort: Authoritative first, then CRITICAL > HIGH > MEDIUM > LOW > INFO
        severity_order = {
            EvidenceSeverity.CRITICAL: 0,
            EvidenceSeverity.HIGH: 1,
            EvidenceSeverity.MEDIUM: 2,
            EvidenceSeverity.LOW: 3,
            EvidenceSeverity.INFO: 4,
        }
        canonical_list.sort(key=lambda x: (not x.authoritative, severity_order.get(x.severity, 5)))

        # Format backward-compatible strings
        strings: List[str] = []
        seen_strings: Set[str] = set()
        for ev in canonical_list:
            prefix = ""
            if ev.source_tier == EvidenceSource.TIER3:
                prefix = "AI: "
            elif ev.source_tier == EvidenceSource.VISION:
                prefix = "[Vision] "
            elif ev.source_tier == EvidenceSource.CLIENT_ADVISORY:
                prefix = "[Client Advisory] "

            formatted = f"{prefix}{ev.description}".strip()
            if formatted.lower() not in seen_strings:
                seen_strings.add(formatted.lower())
                strings.append(formatted)

        return canonical_list, strings
