"""
Versioned Pydantic Data Schemas for Threat-Feed Ingestion and Benchmark v3.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SourceApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class FeedIngestionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


class SourceGovernance(BaseModel):
    source_name: str
    source_url: str
    provider: str
    license_type: str
    allowed_use: str
    redistribution_allowed: bool
    commercial_use_allowed: bool
    status: SourceApprovalStatus = SourceApprovalStatus.APPROVED
    collection_method: str = "offline_feed"
    collection_timestamp: str = "2026-08-24"
    retention_policy: str = "standard_research_archive"


class DatasetRecordV3(BaseModel):
    record_id: str
    url_original: str
    url_dedupe_canonical: str
    url_model_input: str
    label: int = Field(..., description="0 = Benign, 1 = Phishing")
    registered_domain: str
    hostname: str
    tld: str
    source: str
    source_record_id: str
    observed_at: str
    first_seen: str
    last_seen: str
    category: str = "general"
    brand: Optional[str] = None
    is_adversarial: bool = False
    label_conflict: bool = False
    schema_version: str = "v3"


class DataQualityReportV3(BaseModel):
    benchmark_id: str = "url_benchmark_v3"
    schema_version: str = "v3"
    total_raw_ingested: int
    valid_records_accepted: int
    malformed_rejected: int
    level1_exact_duplicates_removed: int
    level2_normalized_duplicates_removed: int
    level3_tracking_duplicates_removed: int
    conflicting_labels_detected: int
    unique_hostnames: int
    unique_registered_domains: int
    unique_tlds: int
    unique_brands: int
    benign_count: int
    phishing_count: int
    adversarial_count: int
    cloud_cdn_count: int
    source_status_summary: Dict[str, FeedIngestionStatus]
    dataset_sha256: str
    generation_timestamp: str


class SplitManifestV3(BaseModel):
    benchmark_id: str = "url_benchmark_v3"
    split_strategy: str = "4-Way Domain-Disjoint (Registered Domain Partitioning)"
    train_count: int
    calibration_count: int
    validation_count: int
    final_test_count: int
    train_sha256: str
    calibration_sha256: str
    validation_sha256: str
    final_test_sha256: str
    final_test_frozen: bool = True
    disjoint_guarantee_verified: bool = True


class ThroughputMetricsV3(BaseModel):
    total_samples: int
    preprocessing_records_per_sec: float
    urlbert_inference_records_per_sec: float
    onnx_inference_records_per_sec: float
    hybrid_pipeline_records_per_sec: float
    warm_memory_rss_mb: float
