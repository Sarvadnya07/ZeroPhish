"""
ZeroPhish Tier 2 - Deprecated Legacy Entrypoint Shim.

DEPRECATION NOTICE:
`Backend/gateway.py` is the CANONICAL application entry point for ZeroPhish (Port 8001).
All Tier 2 detection logic (domain intelligence, ML model inference, threat analysis)
is modularized in `Backend/tier_2/analyzer.py`, `Backend/tier_2/domain_intel.py`, and `Backend/tier_2/ml_model.py`.
This module is preserved solely as a backwards-compatibility delegation shim and will be removed in v3.0.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from gateway import app as gateway_app

logger = logging.getLogger(__name__)
logger.warning(
    "DEPRECATION WARNING: Backend/tier_2/main.py is deprecated. "
    "Use Backend/gateway.py (Port 8001). This shim delegates to the canonical gateway app."
)

# Re-export canonical gateway app
app = gateway_app
