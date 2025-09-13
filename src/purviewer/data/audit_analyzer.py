# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from logging import Logger

    from purviewer.data import OutputFormatter


@dataclass
class AuditAnalyzer:
    """Base class for all analyzers with common attributes."""

    config: AuditConfig
    out: OutputFormatter
    logger: Logger

    @property
    def user_mapping(self) -> dict[str, str]:
        """Map user IDs to names."""
        return self.config.user_mapping


@dataclass
class AuditConfig:
    """Configuration settings for the application."""

    # SharePoint and email domains
    sharepoint_domains: list[str] | None = None
    email_domain: str | None = None

    # File settings and data
    default_log_file: str = "logs/log.csv"
    output_directory: str = "output"
    excluded_file_types: list[str] = field(
        default_factory=lambda: [
            ".aspx",
            ".heic",
            ".jfif",
            ".jpeg",
            ".jpg",
            ".mov",
            ".mp4",
            ".png",
            ".spcolor",
            ".sptheme",
            ".themedjpg",
        ]
    )
    user_mapping: dict[str, str] = field(default_factory=dict)
    max_users: int = 20
    max_files: int = 20

    # Metadata and file actions to exclude
    excluded_actions: list[str] = field(default_factory=list)

    # Exchange fields to extract
    exchange_fields: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "ClientIP": {"skip_value": None},
            "ClientInfoString": {"skip_value": None},
            "MailboxOwnerUPN": {"skip_value": None},
            "ExternalAccess": {"skip_value": None},
            "LogonType": {"skip_value": None},
        }
    )

    # Security-relevant fields to analyze
    security_fields: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "ClientIP": {"skip_value": None},
            "UserAgent": {"skip_value": None},
            "DeviceDisplayName": {"skip_value": None},
            "Platform": {"skip_value": None},
            "GeoLocation": {"skip_value": None},
            "IsManagedDevice": {"skip_value": None},
            "AuthenticationType": {"skip_value": None},
        }
    )

    # Suspicious patterns
    suspicious_patterns: dict[str, str] = field(
        default_factory=lambda: {
            "unusual_hours": "18:00-06:00",  # After hours activity
            "mass_downloads": "10",  # Threshold for bulk downloads (number of downloads)
            "mass_deletions": "5",  # Threshold for bulk deletions (minutes)
            "sensitive_extensions": ".pdf,.doc,.docx,.xls,.xlsx",  # Sensitive file types
        }
    )

    # Known good patterns (to reduce noise)
    known_good: dict[str, list[str]] = field(
        default_factory=lambda: {
            "ip_addresses": [],  # Known good IPs
            "user_agents": [],  # Known good user agents
            "platforms": [],  # Known good platforms
        }
    )

    # Sign-in analysis settings from Entra ID
    entra_columns: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "User agent": {"skip_value": None},
            "User": {"skip_value": None},
            "Username": {"skip_value": None},
            "Application": {"skip_value": None},
            "Resource": {"skip_value": "None"},
            "IP address": {"skip_value": None},
            "Location": {"skip_value": None},
            "Status": {"skip_value": None},
            "Sign-in error code": {"skip_value": "None"},
            "Failure reason": {"skip_value": "Other."},
            "Client app": {"skip_value": None},
            "Device ID": {"skip_value": None},
            "Browser": {"skip_value": None},
            "Operating System": {"skip_value": None},
            "Managed": {"skip_value": None},
            "Join Type": {"skip_value": "None"},
            "Multifactor authentication result": {"skip_value": "None"},
        }
    )

    # Columns that should only be shown if a failure is detected
    entra_failures_only: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "Status": {"fail_value": "Failure"},
            "Sign-in error code": {
                "fail_value": "None",
                "invert": True,
            },  # Show if not "None"
            "Failure reason": {
                "fail_value": "Other",
                "invert": True,
            },  # Show if not "Other"
        }
    )
