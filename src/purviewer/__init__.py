# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""A powerful command-line tool for analyzing Microsoft Purview audit logs and Entra sign-ins. Extract insights from SharePoint, OneDrive, Exchange activity, and user authentication with comprehensive filtering, security analysis, and detailed reporting.

## Features

### File Operations Analysis

- **File Activity Tracking**: Analyze downloads, uploads, deletions, and other file operations
- **Path Analysis**: Track access patterns across SharePoint sites and OneDrive folders
- **Bulk Operations Detection**: Identify suspicious mass downloads or deletions
- **File Timeline**: Generate chronological timelines of file access events
- **URL Export**: Export full SharePoint/OneDrive URLs for accessed files

### User Activity Insights

- **User Mapping**: Map user emails to display names via CSV import
- **Activity Filtering**: Filter analysis by specific users or user groups
- **Top Users**: Identify most active users by operation type
- **User Statistics**: Detailed breakdown of user activity patterns

### Security Analysis

- **IP Address Analysis**: Track and analyze source IP addresses with optional geolocation lookup
- **User Agent Detection**: Identify unusual or suspicious client applications
- **Suspicious Pattern Detection**: Flag bulk operations, unusual access patterns, and after-hours activity
- **Network Filtering**: Filter by specific IP addresses or exclude known good IPs

### Exchange Activity

- **Email Operations**: Track email sends, moves, deletions, and rule changes
- **Mailbox Access**: Monitor folder access and email reading patterns
- **Client Application Tracking**: Identify which applications accessed Exchange
- **Detailed Email Analysis**: Extract subjects, senders, recipients, and attachments
- **CSV Export**: Export complete Exchange activity to CSV for further analysis

### Advanced Filtering

- **Date Range**: Filter analysis to specific time periods
- **Action Types**: Focus on specific operations (downloads, uploads, etc.)
- **File Keywords**: Search for files containing specific keywords
- **IP Filtering**: Include or exclude specific IP addresses with wildcard support

### Sign-in Analysis (from Entra ID sign-in logs)

- **Authentication Tracking**: Analyze user sign-ins from Microsoft Entra audit logs
- **Failure Detection**: Identify failed sign-ins and authentication errors
- **Device Analysis**: Track device types, operating systems, and client applications
- **Location Monitoring**: Analyze sign-in locations and IP addresses
- **Security Insights**: Detect unusual sign-in patterns and potential security issues

## Arguments

### Purview Log Analysis for SharePoint and Exchange

```text
--actions ACTIONS                     specific actions to analyze, comma-separated
--list-files KEYWORD                  list filenames containing keyword
--list-actions-for-files KEYWORD      list actions performed on files by keyword
--user USERNAME                       filter actions by specific user
--user-map USER_MAP_CSV               optional M365 user export CSV (UPN, display name)
--start-date START_DATE               start date for analysis (YYYY-MM-DD)
--end-date END_DATE                   end date for analysis (YYYY-MM-DD)
--sort-by {filename,username,date}    sort results by filename, username, or date (default: date)
--details                             show detailed file lists in operation summaries
--ips IPS                             filter by individual IPs (comma-separated, supports wildcards)
--exclude-ips IPS                     exclude specific IPs (comma-separated, supports wildcards)
--do-ip-lookups                       perform IP geolocation lookups (takes a few seconds per IP)
--timeline                            print a full timeline of file access events
--full-urls                           print full URLs of accessed files
--exchange                            output only Exchange activity in table format
--export-exchange-csv OUTPUT_FILE     export Exchange activity to specified CSV file
```

### Entra ID Log Analysis for Sign-In Activity

```text
--entra                               analyze sign-in data from an Entra ID CSV audit log
--filter FILTER_TEXT                  filter sign-ins by specified text (case-insensitive)
--exclude EXCLUDE_TEXT                exclude sign-ins with specified text (case-insensitive)
--limit MAX_ROWS                      limit rows shown for each sign-in column
```

## Usage

### Full Comprehensive Analysis

```bash
# Analyze all file operations from a Purview audit log
purviewer audit_log.csv

# Analyze Entra ID sign-in data
purviewer signin_data.csv --entra
```

### Common Workflows

#### Security Investigation

```bash
# Look for suspicious bulk downloads
purviewer audit_log.csv --actions "FileDownloaded" --details

# Analyze IP addresses with geolocation
purviewer audit_log.csv --do-ip-lookups

# Check specific user's activity
purviewer audit_log.csv --user "john.doe@company.com" --timeline
```

#### File Discovery

```bash
# Find files containing sensitive keywords
purviewer audit_log.csv --list-actions-for-files "confidential"

# Export all accessed file URLs
purviewer audit_log.csv --full-urls
```

#### Exchange Analysis

```bash
# Focus on email activity only
purviewer audit_log.csv --exchange

# Export Exchange data for further analysis
purviewer audit_log.csv --export-exchange-csv email_activity.csv
```

#### Sign-in Analysis

```bash
# Filter sign-ins by specific criteria
purviewer signin_data.csv --entra --filter "admin" --exclude "success"
```

## Installation

```bash
pip install purviewer
```

## Requirements

- Python 3.13+
- Microsoft Purview audit log CSV export (for SharePoint/Exchange analysis)
- Microsoft Entra sign-ins CSV export (for sign-in analysis)

**Important Note**: The sign-in analysis feature uses a different data source than the main Purview analysis. While most features analyze data from Microsoft Purview audit logs (SharePoint, OneDrive, Exchange), the `--entra` feature specifically requires a CSV export from Microsoft Entra ID's sign-in logs. These are two separate data sources with different formats and column structures.

The tool automatically detects SharePoint domains and email domains from your audit data, making it work seamlessly with any Microsoft 365 tenant.

## License

Purviewer is released under the MIT License. See the LICENSE file for details.

"""  # noqa: D212, D415, W505
