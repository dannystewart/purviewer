# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Purviewer is a command-line tool for analyzing Microsoft Purview audit logs, specifically focusing on SharePoint, OneDrive, and Exchange activity. It provides comprehensive filtering, security analysis, and detailed reporting capabilities for M365 environments.

## Architecture

The codebase is organized into functional modules under `src/purviewer/`:

- **main.py**: Entry point with CLI argument parsing, data preparation, and orchestration
- **files/**: SharePoint and OneDrive file operations analysis
- **exchange/**: Exchange/Outlook activity analysis
- **users/**: User activity tracking and mapping
- **network/**: IP address and network security analysis
- `tools.py`: Base classes (`AuditAnalyzer`, `AuditConfig`) for all analysis modules and `OutputFormatter` for formatting

Each analysis module inherits from `AuditAnalyzer` and uses the shared `OutputFormatter` for consistent output.

## Commands

### Development Commands

```bash
# Install dependencies
poetry install

# Format code
ruff format

# Lint code
ruff check

# Type checking
mypy src/

# Run the CLI tool
purviewer <audit_log.csv> [options]
```

### Common CLI Usage Examples

```bash
# Basic analysis
purviewer audit_log.csv

# Filter by specific actions
purviewer audit_log.csv --actions "FileDownloaded,FileUploaded"

# Analyze specific user
purviewer audit_log.csv --user "john.doe@company.com"

# Export Exchange activity to CSV
purviewer audit_log.csv --export-exchange-csv exchange_activity.csv

# IP analysis with geolocation lookup
purviewer audit_log.csv --do-ip-lookups

# Generate timeline view
purviewer audit_log.csv --timeline
```

## Key Technical Details

### Data Processing Flow

1. CSV audit log is loaded and parsed via pandas
2. AuditData JSON column is expanded into structured fields
3. SharePoint domains and email domains are auto-detected from the data
4. Path information is cleaned and normalized (handles OneDrive vs SharePoint paths differently)
5. Security information (IP, UserAgent, etc.) is extracted
6. Data is filtered and analyzed by the requested modules

### Configuration System

- `AuditConfig` class manages runtime settings including detected domains, file exclusions, and user mappings
- SharePoint domains and email domains are auto-detected from audit data
- User mappings can be imported from CSV files

### Module Dependencies

- Uses `polykit` for logging, CLI parsing, and text utilities
- Core data processing with `pandas`
- IP geolocation via `iplooker`
- Tabular output with `tabulate`

## Code Style

- Python 3.13+ required
- Uses `from __future__ import annotations` for forward references
- Strict typing with mypy configuration
- Ruff formatting with 100-character line limit
- Google-style docstrings
- No print statements in library code (uses logger)
