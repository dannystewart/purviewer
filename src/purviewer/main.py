#!/usr/bin/env python3
# type: ignore[reportAssignmentType]
"""Analyze SharePoint file actions taken based on a CSV audit log export from Microsoft 365."""

from __future__ import annotations

import json
import operator
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pandas as pd
from pandas import DataFrame
from polykit import PolyLog, Text
from polykit.cli import PolyArgs, halo_progress
from polykit.text import color, print_color

from purviewer.data import AuditConfig, OutputFormatter
from purviewer.exchange import ExchangeOperations
from purviewer.files import FileOperations
from purviewer.network import NetworkOperations
from purviewer.users import UserActions

if TYPE_CHECKING:
    import argparse

# Set up the logger
logger = PolyLog.get_logger("purviewer", simple=True)

# Load runtime config
config = AuditConfig()

# Create the output formatter and analyzers
with halo_progress(
    start_message="Importing data...",
    end_message=None,
    fail_message="Failed to import data",
):
    out = OutputFormatter(config, logger)
    users = UserActions(config, out, logger)
    network = NetworkOperations(config, out, logger)
    files = FileOperations(config, out, logger, users)
    exchange = ExchangeOperations(config, out, logger)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = PolyArgs(
        description="Analyze SharePoint and Exchange actions based on Purview audit logs.",
        arg_width=40,
    )
    parser.add_argument("log_file", help="CSV audit log exported from Purview")
    parser.add_argument(
        "--actions", type=str, help="specific actions to analyze, comma-separated (default: all)"
    )
    parser.add_argument("--list", type=str, help="print list of filenames containing keyword")
    parser.add_argument(
        "--file", type=str, default="", help="show actions performed on files containing keyword"
    )
    parser.add_argument("--user", type=str, help="filter actions by specific user")
    parser.add_argument(
        "--users-list",
        type=str,
        metavar="FILE",
        help="optional CSV with user mappings (UPN, display name)",
    )
    parser.add_argument("--start-date", type=str, help="start date for analysis (YYYY-MM-DD)")
    parser.add_argument("--end-date", type=str, help="end date for analysis (YYYY-MM-DD)")
    parser.add_argument(
        "--sort-by",
        choices=["filename", "username", "date"],
        default="date",
        help="sort results by filename, username, or date (default: date)",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="show detailed file lists in operation summaries",
    )
    parser.add_argument(
        "--ips", type=str, help="filter by individual IPs (comma-separated, supports wildcards)"
    )
    parser.add_argument(
        "--exclude-ips", type=str, help="exclude specific IPs (comma-separated, supports wildcards)"
    )
    parser.add_argument(
        "--with-lookups",
        action="store_true",
        help="perform detailed IP lookups (takes several seconds per IP)",
    )
    parser.add_argument(
        "--timeline", action="store_true", help="print a full timeline of file access"
    )
    parser.add_argument("--urls", action="store_true", help="export full URLs of accessed files")
    parser.add_argument(
        "--exchange", action="store_true", help="output only Exchange activity in table format"
    )
    parser.add_argument(
        "--exchange-csv",
        type=str,
        metavar="FILE",
        help="export Exchange activity to specified CSV file",
    )

    return parser.parse_args()


def detect_sharepoint_domains(df: DataFrame) -> list[str]:
    """Detect SharePoint domains from ObjectId URLs in the audit data."""
    domains = set()

    # Look for SharePoint URLs in ObjectId column
    for object_id in df["ObjectId"].dropna():
        if isinstance(object_id, str):
            # Match SharePoint URLs (both http and https)
            matches = re.findall(r"https?://([^/]+\.sharepoint\.com)/", object_id)
            domains.update(matches)

    # Convert to full URLs
    full_domains = []
    for domain in domains:
        full_domains.extend([f"https://{domain}/", f"http://{domain}/"])

    return full_domains


def detect_email_domain(df: DataFrame) -> str:
    """Detect the primary email domain from UserId values in the audit data."""
    domains = set()

    # Extract domains from UserId column
    for user_id in df["UserId"].dropna():
        if isinstance(user_id, str) and "@" in user_id:
            domain = user_id.split("@")[1]
            domains.add(domain)

    # Return the most common domain, or empty string if none found
    if domains:
        # Count occurrences of each domain
        domain_counts = {}
        for user_id in df["UserId"].dropna():
            if isinstance(user_id, str) and "@" in user_id:
                domain = user_id.split("@")[1]
                domain_counts[domain] = domain_counts.get(domain, 0) + 1

        # Return the most frequent domain
        return max(domain_counts.items(), key=operator.itemgetter(1))[0]

    return ""


def should_exclude_file(filename: str | None) -> bool:
    """Check if the file should be excluded based on its extension or if it starts with a dot."""
    if filename is None:
        return False
    if filename.startswith("."):
        return True
    if filename.startswith("~"):
        return True
    if filename.startswith("$"):
        return True
    return any(filename.lower().endswith(ext) for ext in config.excluded_file_types)


def prepare_dataframe(log_file: Path) -> DataFrame:
    """Load and prepare the DataFrame from the CSV audit log file."""
    df = load_csv_data(log_file)
    df = extract_basic_fields(df)

    # Detect domains and update the config
    sharepoint_domains = detect_sharepoint_domains(df)
    email_domain = detect_email_domain(df)
    config.sharepoint_domains = sharepoint_domains
    config.email_domain = email_domain

    if sharepoint_domains:
        logger.debug("Detected SharePoint domains: %s", ", ".join(sharepoint_domains))
    if email_domain:
        logger.debug("Detected email domain: %s", email_domain)

    df = extract_path_information(df)
    return extract_security_information(df)


def load_csv_data(log_file: Path) -> DataFrame:
    """Load CSV data and handle possible exceptions.

    Raises:
        FileNotFoundError: If the file is not found.
        EmptyDataError: If the file is empty.
        ParserError: If the file is not a valid CSV file.
    """
    try:
        df: DataFrame = pd.read_csv(log_file)
    except FileNotFoundError:
        logger.error("Error: File '%s' not found.", log_file)
        raise
    except pd.errors.EmptyDataError:
        logger.error("Error: File '%s' is empty.", log_file)
        raise
    except pd.errors.ParserError:
        logger.error("Error: Unable to parse '%s'. Make sure it's a valid CSV file.", log_file)
        raise
    return df


def extract_basic_fields(df: DataFrame) -> DataFrame:
    """Extract primary fields from AuditData."""
    df["AuditData"] = df["AuditData"].apply(json.loads)
    df["Operation"] = df["AuditData"].apply(lambda x: x.get("Operation"))
    df["UserId"] = df["AuditData"].apply(lambda x: x.get("UserId"))
    df["SourceFileName"] = df["AuditData"].apply(lambda x: x.get("SourceFileName"))
    df["ClientIP"] = df["AuditData"].apply(lambda x: x.get("ClientIPAddress") or x.get("ClientIP"))
    df["CreationDate"] = pd.to_datetime(df["CreationDate"])

    # Extract location info
    df["ObjectId"] = df["AuditData"].apply(lambda x: x.get("ObjectId", ""))
    df["SiteUrl"] = df["AuditData"].apply(lambda x: x.get("SiteUrl", ""))

    return df


def extract_path_information(df: DataFrame) -> DataFrame:
    """Extract and clean path information from URLs."""
    df["CleanPath"] = df.apply(clean_path, axis=1)
    return df


def clean_path(row: Any) -> str:
    """Clean the path from a URL, handling both OneDrive and SharePoint paths."""
    if not (object_id := row.get("ObjectId", "")):
        return ""

    # Handle OneDrive paths differently
    if "-my.sharepoint.com/personal/" in object_id:
        return _handle_onedrive_path(object_id)

    # Handle regular SharePoint paths
    path = object_id

    # Remove domain prefix using detected domains or fallback to regex
    if config.sharepoint_domains:
        for domain in config.sharepoint_domains:
            # Handle cases where the domain appears twice
            while domain in path:
                path = path.replace(domain, "/", 1)
    else:
        # Fallback: use regex to remove any SharePoint domain
        path = re.sub(r"https?://[^/]+\.sharepoint\.com/", "/", path)

    # Fix cases with multiple slashes
    while "//" in path:
        path = path.replace("//", "/")

    # Remove leading slashes
    path = path.lstrip("/")

    # Remove the filename from the end if it matches SourceFileName
    filename = row.get("SourceFileName", "")
    if filename and path.endswith(filename):
        path = path[: -len(filename)].rstrip("/")

    return path


def _handle_onedrive_path(object_id: str) -> str:
    # Extract the username
    if "/personal/" in object_id:
        parts = object_id.split("/personal/")
        if len(parts) > 1:
            # Get the username part
            user_and_path = parts[1].split("/", 1)
            username = user_and_path[0]

            # Extract the full folder structure after username
            if len(user_and_path) > 1:
                return f"OneDrive ≫ {username}/{user_and_path[1]}"
            return f"OneDrive ≫ {username}"

    # Fallback if parsing fails
    return "OneDrive"


def extract_security_information(df: DataFrame) -> DataFrame:
    """Extract security-relevant fields from AuditData."""
    # User agent and device info
    df["UserAgent"] = df["AuditData"].apply(lambda x: x.get("UserAgent", ""))
    df["Platform"] = df["AuditData"].apply(lambda x: x.get("Platform", ""))
    df["DeviceDisplayName"] = df["AuditData"].apply(lambda x: x.get("DeviceDisplayName", ""))

    # Security context info
    df["GeoLocation"] = df["AuditData"].apply(lambda x: x.get("GeoLocation", ""))
    df["IsManagedDevice"] = df["AuditData"].apply(lambda x: x.get("IsManagedDevice", ""))
    df["AuthenticationType"] = df["AuditData"].apply(lambda x: x.get("AuthenticationType", ""))
    df["BrowserVersion"] = df["AuditData"].apply(lambda x: x.get("BrowserVersion", ""))
    df["AppAccessContext"] = df["AuditData"].apply(lambda x: x.get("AppAccessContext", {}))

    # Additional fields
    df["MachineId"] = df["AuditData"].apply(lambda x: x.get("MachineId", ""))

    return df


def apply_ip_filtering(args: argparse.Namespace, df: DataFrame) -> DataFrame:
    """Apply IP filtering based on command-line arguments."""
    if args.ips:
        ip_patterns = [ip.strip() for ip in args.ips.split(",")]

        def matches_ip_filter(ip: str) -> bool:
            return network.matches_ip_pattern(ip, ip_patterns)

        df = df[df["ClientIP"].apply(matches_ip_filter)]
        if df.empty:
            logger.warning(
                "No events found for the specified IPs: %s", Text.list_ids(args.ips.split(","))
            )
        else:
            logger.info(
                "Filtered to %d events from IPs: %s", len(df), Text.list_ids(args.ips.split(","))
            )

    if args.exclude_ips:
        exclude_ip_patterns = [ip.strip() for ip in args.exclude_ips.split(",")]

        def matches_exclude_filter(ip: str) -> bool:
            return network.matches_ip_pattern(ip, exclude_ip_patterns)

        df = df[~df["ClientIP"].apply(matches_exclude_filter)]
        if df.empty:
            logger.warning(
                "No events found after excluding IPs: %s",
                Text.list_ids(args.exclude_ips.split(",")),
            )
        else:
            logger.info(
                "Filtered to %d events, excluding IPs: %s",
                len(df),
                Text.list_ids(args.exclude_ips.split(",")),
            )

    return df


def execute_selected_operations(
    args: argparse.Namespace, file_actions: DataFrame, actions_to_analyze: list[str]
) -> None:
    """Run the requested operations based on the command-line arguments."""
    if args.start_date:
        file_actions = file_actions[file_actions["CreationDate"] >= pd.to_datetime(args.start_date)]

    if args.end_date:
        file_actions = file_actions[file_actions["CreationDate"] <= pd.to_datetime(args.end_date)]

    if args.timeline:
        files.print_timeline(file_actions)
        return

    if args.urls:
        files.export_file_urls(file_actions)
        return

    if args.list:
        files.list_files_with_keyword(file_actions, args.list)

    elif args.user:
        user_actions = users.filter_by_user(args.user, file_actions)
        users.get_top_users(user_actions, "action")
        print_color(f"\nActions for user {args.user} (total: {len(user_actions)})", "blue")
        users.get_grouped_actions(user_actions, actions_to_analyze, args.sort_by)

    elif not args.file:
        files.get_overall_statistics(file_actions, actions_to_analyze)
        files.get_most_actioned_files(file_actions, actions_to_analyze)

    if args.file:
        files.get_detailed_file_actions(file_actions, args.file)


def perform_early_operations(
    args: argparse.Namespace, file_actions: DataFrame, exch_events: DataFrame
) -> bool:
    """Perform early operations based on the command-line arguments."""
    if args.with_lookups:
        network.analyze_ip_addresses_with_lookup(file_actions)
        return True

    if args.timeline:
        files.print_timeline(file_actions)
        return True

    if args.urls:
        files.export_file_urls(file_actions)
        return True

    if args.exchange_csv:
        exchange.generate_exchange_activity_csv(exch_events, args.exchange_csv)
        if not args.exchange:
            return True

    if args.exchange:
        exchange.generate_exchange_activity_table(exch_events)
        return True

    if args.exchange:
        exchange.generate_exchange_activity_table(exch_events)
        return True

    return False


def perform_data_analysis(
    args: argparse.Namespace,
    file_actions: DataFrame,
    actions_to_analyze: list[str],
    exch_events: DataFrame,
) -> None:
    """Perform data analysis based on the command-line arguments."""
    # Check for early operations
    if perform_early_operations(args, file_actions, exch_events):
        return

    execute_selected_operations(args, file_actions, actions_to_analyze)

    # Run security analyses
    if not args.file and not args.user:  # Only run for full analysis
        network.analyze_ip_addresses(file_actions)
        network.analyze_user_agents(file_actions)
        files.analyze_accessed_paths(file_actions)
        files.detect_suspicious_patterns(file_actions, show_details=args.details)
        files.analyze_file_operations(file_actions, show_details=args.details)
        exchange.display_exchange_events(exch_events, show_details=args.details)


def main() -> None:
    """Parse a CSV audit log and analyze SharePoint file actions."""
    # Parse command-line arguments
    args = parse_arguments()

    config.user_mapping = users.create_user_mapping(args.users_list)

    log_file = Path(args.log_file)
    print(color("Using log file: ", "green") + str(log_file))

    try:
        df: DataFrame = prepare_dataframe(log_file)
    except FileNotFoundError:
        return
    except pd.errors.EmptyDataError:
        return
    except pd.errors.ParserError:
        return

    # Print the date range
    out.print_date_range(df)

    # Apply IP filtering if specified
    df = apply_ip_filtering(args, df)
    if df.empty:
        return

    # Process Exchange events and SharePoint events separately
    exch_events = exchange.process_exchange_events(df)
    sp_events = df[df["SourceFileName"].notna()]

    # Filter out excluded actions
    sp_events = sp_events[~sp_events["Operation"].isin(config.excluded_actions)]

    # Determine the list of actions to analyze
    actions_to_analyze = (
        [action.strip() for action in args.actions.split(",")]
        if args.actions
        else df["Operation"].unique().tolist()
    )

    if not isinstance(actions_to_analyze, list):
        logger.warning("No actions found to analyze.")
        return

    # Filter the events to the specified actions
    file_actions = df[
        (df["Operation"].isin(actions_to_analyze))
        & (df["UserId"] != "app@sharepoint")
        & (df["SourceFileName"].notna())
        & (~df["SourceFileName"].apply(should_exclude_file))
    ]

    perform_data_analysis(args, file_actions, actions_to_analyze, exch_events)


if __name__ == "__main__":
    main()
