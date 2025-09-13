# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Exchange and Outlook activity analysis.

This module provides functionality for analyzing email-related audit events from Exchange and Outlook, including message operations, mailbox access, and email security events.
"""  # noqa: D212, D415, W505

from __future__ import annotations

from .exchange_ops import ExchangeOperations
