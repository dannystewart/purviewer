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
