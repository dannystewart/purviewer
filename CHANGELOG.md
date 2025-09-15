# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic Versioning].

## [Unreleased]

## [0.2.1] (2025-09-15)

### Fixed

- Fixes Entra sign-in analysis by moving it from the early operations flow into the main function to ensure it bypasses the SharePoint flow.

## [0.2.0] (2025-09-13)

### Added

- Adds Microsoft Entra ID sign-in analysis capabilities with authentication tracking, failure detection, device analysis, location monitoring, and security insights for unusual patterns.
- Adds new command-line options for filtering, excluding, and limiting sign-in data results with validation to ensure correct data source usage.
- Adds documentation to distinguish between Purview audit logs and Entra ID sign-in logs as separate data sources with different formats.
- Adds module documentation with feature overviews and usage examples for `pdoc` parsing and to improve code discoverability.
- Adds `CHANGELOG.md` to track changes for subsequent releases.
- Adds MIT license and `LICENSE` file for proper open source distribution.
- Adds automated GitHub Actions workflows for documentation generation using `pdoc` and PyPI package publishing on version tags.

## [0.1.0] (2025-09-13)

Initial release.

<!-- Links -->
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

<!-- Versions -->
[unreleased]: https://github.com/dannystewart/purviewer/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/dannystewart/purviewer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dannystewart/purviewer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dannystewart/purviewer/releases/tag/v0.1.0
