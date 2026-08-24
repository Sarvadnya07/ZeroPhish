"""
ZeroPhish ML Shadow Evaluation Package.
"""

from ml.shadow.config import RolloutStage, ShadowConfig, ShadowMode
from ml.shadow.manager import (
    DisagreementCategory,
    ShadowCascadeManager,
    ShadowCascadeObservation,
    ShadowStatus,
)
from ml.shadow.metrics import ShadowMetricsAggregator
from ml.shadow.models import DisagreementTaxonomy, ExtendedShadowObservation, RolloutGateResult
from ml.shadow.real_staging import RealStagingTelemetryValidator
from ml.shadow.retention import ShadowRetentionBuffer
from ml.shadow.service import ExtendedShadowService
from ml.shadow.staging import StagingShadowEngine

__all__ = [
    "ShadowConfig",
    "ShadowMode",
    "RolloutStage",
    "DisagreementCategory",
    "DisagreementTaxonomy",
    "ShadowCascadeObservation",
    "ExtendedShadowObservation",
    "RolloutGateResult",
    "ShadowStatus",
    "ShadowMetricsAggregator",
    "ShadowRetentionBuffer",
    "ShadowCascadeManager",
    "ExtendedShadowService",
    "StagingShadowEngine",
    "RealStagingTelemetryValidator",
]
