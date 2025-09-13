# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Core data processing and configuration components.

This module contains the foundational classes and utilities for audit log analysis, including base classes for all analysis modules (`AuditAnalyzer`, `AuditConfig`), centralized output formatting, and display utilities.
"""  # noqa: D212, D415, W505

from __future__ import annotations

from .audit_analyzer import AuditAnalyzer, AuditConfig
from .output_formatter import OutputFormatter
