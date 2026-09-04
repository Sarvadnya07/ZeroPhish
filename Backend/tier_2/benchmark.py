#!/usr/bin/env python3
"""
ZeroPhish URL ML Benchmark Suite (Compatibility Alias).

This module forwards all operations to tier_2.benchmark_url_ml to eliminate
accidental byte-for-byte code duplication while preserving CLI and import compatibility.
"""

from __future__ import annotations

import sys
from .benchmark_url_ml import *  # noqa: F401, F403
from .benchmark_url_ml import main as _main


if __name__ == "__main__":
    sys.exit(_main() or 0)
