# Purviewer

A powerful command-line tool for analyzing Microsoft Purview audit logs and Entra sign-ins. Extract insights from SharePoint, OneDrive, Exchange activity, and user authentication with comprehensive filtering, security analysis, and detailed reporting.

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

## Usage

```bash
# Basic analysis
purviewer audit_log.csv

# Filter by specific actions
purviewer audit_log.csv --actions "FileDownloaded,FileUploaded"

# Analyze specific user
purviewer audit_log.csv --user "john.doe@company.com"

# Filter by date range
purviewer audit_log.csv --start-date "2025-01-01" --end-date "2025-01-31"

# Search for files containing keyword
purviewer audit_log.csv --file "confidential"

# Export Exchange activity to CSV
purviewer audit_log.csv --exchange-csv exchange_activity.csv

# Generate timeline view
purviewer audit_log.csv --timeline

# Export file URLs
purviewer audit_log.csv --urls

# IP analysis with geolocation lookup
purviewer audit_log.csv --with-lookups

# Filter by IP addresses
purviewer audit_log.csv --ips "192.168.1.*,10.0.0.0/8"

# Exclude specific IPs
purviewer audit_log.csv --exclude-ips "192.168.1.100"

# Use user mapping file
purviewer audit_log.csv --users-list users.csv

# Show detailed analysis
purviewer audit_log.csv --details

# Analyze sign-in data
purviewer signin_data.csv --entra

# Filter sign-ins by user or text
purviewer signin_data.csv --entra --signin-filter "admin"

# Exclude certain sign-ins and limit results
purviewer signin_data.csv --entra --signin-exclude "success" --signin-limit 10
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
