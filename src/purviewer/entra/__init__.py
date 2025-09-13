# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Sign-in analysis module for Microsoft Entra audit logs.

This module provides functionality for analyzing sign-in data from Microsoft Entra audit logs, including authentication failures, device types, and location tracking.
"""  # noqa: D212, D415, W505

from __future__ import annotations

from .entra_ops import EntraSignInOperations
