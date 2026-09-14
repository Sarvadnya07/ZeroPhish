"""
Prometheus Metrics for ZeroPhish Gateway
"""
from __future__ import annotations
from fastapi import Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST, REGISTRY

HTTP_REQUESTS_TOTAL = Counter(
    "zerophish_http_requests_total",
    "HTTP requests processed",
    ["method", "endpoint", "status_code"],
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "zerophish_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
SCANS_TOTAL = Counter(
    "zerophish_scans_total",
    "Total scans",
    ["verdict", "threat_level"],
)
TIER_DURATION_SECONDS = Histogram(
    "zerophish_tier_duration_seconds",
    "Tier duration",
    ["tier"],
    buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0),
)
CIRCUIT_BREAKER_STATE = Gauge(
    "zerophish_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["name"],
)
CIRCUIT_BREAKER_FAILURES_TOTAL = Counter(
    "zerophish_circuit_breaker_failures_total",
    "Circuit breaker failures",
    ["name"],
)
CACHE_OPERATIONS_TOTAL = Counter(
    "zerophish_cache_operations_total",
    "Cache operations",
    ["backend", "operation", "result"],
)
SSE_ACTIVE_SUBSCRIBERS = Gauge(
    "zerophish_sse_active_subscribers",
    "Active SSE subscribers",
)
SSE_EVENTS_DROPPED_TOTAL = Counter(
    "zerophish_sse_events_dropped_total",
    "Dropped SSE events",
)

def record_http_request(method: str, endpoint: str, status_code: int, duration_sec: float) -> None:
    norm = endpoint
    if "/status/" in endpoint: norm = "/gateway/status/{id}"
    elif "/result/" in endpoint: norm = "/gateway/result/{id}"
    elif "/incidents/" in endpoint: norm = "/api/v1/incidents/{id}"
    elif "/webhooks/" in endpoint: norm = "/api/v1/webhooks/{id}"
    HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=norm, status_code=str(status_code)).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=norm).observe(duration_sec)

def get_metrics_response() -> Response:
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
