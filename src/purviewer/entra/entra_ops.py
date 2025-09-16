# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

# type: ignore[reportAssignmentType]

from __future__ import annotations

import csv
import operator
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from polykit.text import color, print_color

from purviewer.tools import AuditAnalyzer

if TYPE_CHECKING:
    from polykit.text.types import TextColor


class EntraSignInOperations(AuditAnalyzer):
    """Analyze sign-ins data from Microsoft Entra audit logs."""

    def _sanitize(self, value: str) -> str:
        """Sanitize a value by removing leading/trailing whitespace and converting to lowercase."""
        value = value.strip()
        value = value.removesuffix(".")
        if not value:
            return "(no value)"
        return value

    def should_skip(self, value: str, skip_value: str | None) -> bool:
        """Determine if a value should be skipped based on the skip_value."""
        if skip_value is None:
            return False
        if skip_value == "None":
            return not value.strip()
        return value == skip_value

    def is_failure(self, value: str, fail_config: dict[str, Any]) -> bool:
        """Determine if a value represents a failure based on the fail_config."""
        sanitized_value = self._sanitize(value)
        fail_value = self._sanitize(fail_config["fail_value"])
        invert = fail_config.get("invert", False)

        if invert:
            return sanitized_value != fail_value
        return sanitized_value == fail_value

    def print_value_with_count(
        self,
        value: str,
        count: int,
        indent: int = 2,
        value_color: TextColor | None = None,
        count_color: TextColor | None = None,
        count_width: int = 3,
    ) -> None:
        """Print a line with the column name and value."""
        value = self._sanitize(value)
        value = color(f"{value}", value_color) if value_color else f"{value}"
        count_str = (
            color(f"{count:{count_width}}", count_color)
            if count_color
            else f"{count:{count_width}}"
        )
        indent_space = " " * indent
        print(f"{indent_space}{count_str} {value}")

    def print_line_with_value(
        self,
        col: str,
        value: str,
        color_name: TextColor | None = None,
        indent: int = 2,
    ) -> None:
        """Print a line with the column name and value."""
        column = f"{col}:"
        value = self._sanitize(value)
        indent_space = " " * indent
        print(f"{indent_space}{color(column, color_name) if color_name else column} {value}")

    def check_missing_columns(self, csv_reader: csv.DictReader[str]) -> set[str]:
        """Check for missing columns and return a set of missing column names.

        Raises:
            ValueError: If the CSV file is not an Entra sign-ins CSV.
        """
        if csv_reader.fieldnames is None:
            self.logger.error("Error: CSV file has no fieldnames.")
            return set(self.config.entra_columns)  # Return all columns as missing

        # Check if this looks like a Purview audit log instead of Entra sign-ins
        purview_columns = {"AuditData", "Operation", "UserId", "SourceFileName", "CreationDate"}
        if purview_columns.issubset(set(csv_reader.fieldnames)):
            self.logger.error(
                "Error: This appears to be a Purview audit log CSV, not an Entra sign-ins CSV."
            )
            self.logger.error(
                "Sign-in analysis requires a CSV export of Entra ID sign-in logs rather than Purview audit data."
            )
            self.logger.error(
                "Please use the --entra argument with a proper Entra sign-ins CSV export."
            )
            msg = "Invalid CSV format: Expected Entra sign-ins data, got Purview audit data"
            raise ValueError(msg)

        missing_columns = set(self.config.entra_columns) - set(csv_reader.fieldnames)
        if missing_columns:
            self.logger.warning("Warning: The following columns are missing from the CSV file:")
            for col in missing_columns:
                print_color(f"  - {col}", "yellow")
            print()
        return missing_columns

    def should_process_row(
        self, row: dict[str, str], filter_text: str | None = None, exclude_text: str | None = None
    ) -> bool:
        """Determine if the row should be processed based on filter and exclude settings."""
        if filter_text and not any(
            filter_text.lower() in str(value).lower() for value in row.values()
        ):
            return False
        return not (
            exclude_text
            and any(exclude_text.lower() in str(value).lower() for value in row.values())
        )

    def process_row(
        self,
        row: dict[str, str],
        counts: defaultdict[str, defaultdict[str, int]],
        failure_detected: dict[str, bool],
        missing_columns: set[str],
    ) -> None:
        """Process a single row of the CSV file."""
        for col, config in self.config.entra_columns.items():
            if col in missing_columns:
                continue
            value = row.get(col, "")
            if not self.should_skip(value, config["skip_value"]):
                counts[col][value] += 1

            if col in self.config.entra_failures_only and self.is_failure(
                value, self.config.entra_failures_only[col]
            ):
                failure_detected[col] = True

    def process_entra_csv(
        self,
        log_file: str,
        filter_text: str | None = None,
        exclude_text: str | None = None,
        limit: int | None = None,
    ) -> None:
        """Process the sign-ins CSV file and display results."""
        counts: defaultdict[str, defaultdict[str, int]] = defaultdict(lambda: defaultdict(int))
        total_rows = 0
        processed_rows = 0
        failure_detected: dict[str, bool] = dict.fromkeys(self.config.entra_failures_only, False)

        encodings = ["utf-8-sig", "utf-8", "iso-8859-1", "cp1252"]
        non_standard_encoding = False

        for encoding in encodings:
            try:
                with Path(log_file).open(encoding=encoding) as file:
                    csv_reader = csv.DictReader(file)
                    missing_columns = self.check_missing_columns(csv_reader)

                    # Reset the file pointer to the beginning
                    file.seek(0)
                    next(csv_reader)  # Skip the header row

                    for row in csv_reader:
                        total_rows += 1
                        if self.should_process_row(row, filter_text, exclude_text):
                            processed_rows += 1
                            self.process_row(row, counts, failure_detected, missing_columns)

                if non_standard_encoding:
                    self.logger.info("Successfully read the file using %s encoding.", encoding)
                break

            except UnicodeDecodeError:
                non_standard_encoding = True
                self.logger.warning(
                    "Failed to read the file using %s encoding. Trying next...", encoding
                )
                continue
            except ValueError as e:
                # Re-raise format validation errors
                raise e
        else:
            self.logger.error("Failed to read the file with any of the attempted encodings.")
            return

        self.print_results(
            total_rows, processed_rows, counts, failure_detected, filter_text, exclude_text, limit
        )

    def categorize_columns(
        self, counts: defaultdict[str, defaultdict[str, int]], failure_detected: dict[str, bool]
    ) -> tuple[list[str], list[str]]:
        """Categorize columns into those with and without variation."""
        columns_with_no_variation = []
        columns_with_variation = []

        for col in self.config.entra_columns:
            if col not in counts:
                continue  # Skip columns that are missing from the CSV
            if col in self.config.entra_failures_only and not failure_detected[col]:
                continue

            filtered_counts = counts[col]
            unique_values = len(filtered_counts)

            if unique_values == 0:
                continue
            if unique_values == 1:
                columns_with_no_variation.append(col)
            else:
                columns_with_variation.append(col)

        return columns_with_no_variation, columns_with_variation

    def print_column_data(
        self, col: str, filtered_counts: dict[str, int], limit: int | None = None
    ) -> None:
        """Print data for a single column."""
        print_color(f"{col}:", "cyan")
        max_count = max(filtered_counts.values())
        count_width = len(str(max_count))
        for value, count in sorted(
            filtered_counts.items(), key=operator.itemgetter(1), reverse=True
        )[:limit]:
            self.print_value_with_count(value, count, count_color="yellow", count_width=count_width)
        print()

    def print_columns_with_no_variation(
        self,
        columns_with_no_variation: list[str],
        counts: defaultdict[str, defaultdict[str, int]],
        failure_detected: dict[str, bool],
    ) -> None:
        """Print columns with no variation."""
        print_color("Columns with no variation:", "green")
        for col in columns_with_no_variation:
            if col not in self.config.entra_failures_only or failure_detected[col]:
                value, _ = next(iter(counts[col].items()))
                self.print_line_with_value(col, value, "green")
        print()

    def print_results(
        self,
        total_rows: int,
        processed_rows: int,
        counts: defaultdict[str, defaultdict[str, int]],
        failure_detected: dict[str, bool],
        filter_text: str | None = None,
        exclude_text: str | None = None,
        limit: int | None = None,
    ) -> None:
        """Print the analysis results."""
        self.out.print_header("Sign-ins Analysis", "blue")

        self.logger.info("Total rows in file: %s", total_rows)
        if filter_text:
            self.logger.info("Filter applied: '%s'", filter_text)
        if exclude_text:
            self.logger.info("Exclusion applied: '%s'", exclude_text)
        self.logger.info("Rows processed: %s", processed_rows)
        print()

        columns_with_no_variation, columns_with_variation = self.categorize_columns(
            counts, failure_detected
        )

        if columns_with_no_variation:
            self.print_columns_with_no_variation(
                columns_with_no_variation, counts, failure_detected
            )

        for col in columns_with_variation:
            self.print_column_data(col, counts[col], limit)
