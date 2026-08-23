"""
Analytics models — heatmaps, threat feed, model metrics, false-positive records.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ThreatHeatmapEntry(BaseModel):
    hour: int  # 0-23
    day: int  # 0 = Monday
    count: int
    avg_score: float


class ThreatFeedItem(BaseModel):
    id: str
    timestamp: str
    sender_domain: str
    subject_snippet: str
    final_score: float
    verdict: str
    category: str
    tier1_score: Optional[float] = None
    tier2_score: Optional[float] = None
    tier3_score: Optional[float] = None


class ModelMetrics(BaseModel):
    model_id: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    total_inferences: int
    avg_latency_ms: float
    false_positive_rate: float
    false_negative_rate: float
    last_evaluated: str


class FalsePositiveReport(BaseModel):
    id: str
    scan_id: str
    reporter_id: str
    reason: str
    original_score: float
    original_verdict: str
    created_at: str
    reviewed: bool = False
    reviewer_id: Optional[str] = None
    resolution: Optional[str] = None


class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    condition_type: str  # "score_threshold" | "sender_domain" | "keyword"
    condition_value: str
    action: str  # "block" | "quarantine" | "alert" | "allow"
    created_by: str
    created_at: str


class PolicyRuleCreate(BaseModel):
    name: str
    description: str = ""
    condition_type: str
    condition_value: str
    action: str
    enabled: bool = True


class AdminDashboardSummary(BaseModel):
    total_scans_today: int
    total_scans_week: int
    critical_today: int
    suspicious_today: int
    safe_today: int
    avg_score_today: float
    false_positives_pending: int
    open_incidents: int
    circuit_breaker_state: str
    top_malicious_domains: List[Dict[str, Any]]
    top_senders: List[Dict[str, Any]]
    model_accuracy: float
