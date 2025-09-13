# type: ignore[reportAssignmentType]
from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import groupby
from typing import TYPE_CHECKING, Any

from pandas import DataFrame
from polykit.text import color
from polykit.text import print_color as printc
from tabulate import tabulate

from purviewer.data import AuditAnalyzer

if TYPE_CHECKING:
    import numpy as np
    import pandas as pd
    from pandas import DataFrame

    from purviewer.users import UserActions


@dataclass
class FileOperations(AuditAnalyzer):
    """Analyze file actions in SharePoint."""

    users: UserActions

    def __post_init__(self) -> None:
        self.max_files: int = self.config.max_files
        self.suspicious_patterns: dict[str, str] = self.config.suspicious_patterns

    @staticmethod
    def filter_files_by_name(keyword: str, file_actions: DataFrame) -> DataFrame:
        """Filter file actions by keyword in the file name."""
        return file_actions[
            file_actions["SourceFileName"].str.contains(keyword, case=False, na=False)
        ]

    def get_unique_files(self, user_actions: DataFrame) -> None:
        """Get unique files accessed by the user."""
        unique_files = user_actions["SourceFileName"].unique()
        sorted_files = sorted(unique_files)
        self.out.print_header("Unique files accessed")
        for file in sorted_files:
            print(f"{file}")

    def get_most_actioned_files(
        self, file_actions: DataFrame, actions_to_analyze: list[str]
    ) -> None:
        """Get overall statistics for file actions."""
        if len(actions_to_analyze) > 1:
            most_actioned_files = file_actions["SourceFileName"].value_counts().head(self.max_files)

            if most_actioned_files.empty:
                return

            self.out.print_header(f"Top {self.max_files} most frequently actioned files")

            headers = ["File Name", "Count"]
            min_widths = [60, 10]
            col_formats = [f"{{:<{width}}}" for width in min_widths]

            formatted_headers = [
                fmt.format(header) for fmt, header in zip(col_formats, headers, strict=False)
            ]
            formatted_table = [
                [
                    fmt.format(str(cell))
                    for fmt, cell in zip(col_formats, [file, count], strict=False)
                ]
                for file, count in most_actioned_files.items()
            ]

            colored_headers = self.out.color_headers(formatted_headers)

            print(tabulate(formatted_table, headers=colored_headers, tablefmt="plain"))

    def get_detailed_file_actions(self, file_actions: DataFrame, keyword: str) -> None:
        """Get detailed actions for files containing the keyword."""
        filtered_actions = self.filter_files_by_name(keyword, file_actions)

        if filtered_actions.empty:
            printc(f"\nNo files found containing '{keyword}'.", "yellow")
            return

        self.out.print_header(f"Detailed actions for files containing '{keyword}':")

        # Sort actions by timestamp
        filtered_actions = filtered_actions.sort_values("CreationDate")

        # Group by filename to show actions for each file separately
        for filename, group in filtered_actions.groupby("SourceFileName"):
            # Check if any action for this file/folder starts with "Folder"
            is_folder = any(action.startswith("Folder") for action in group["Operation"])

            if is_folder:
                self.out.print_header(f"Folder: {filename}", color="cyan")
            else:
                self.out.print_header(f"File: {filename}", color="cyan")

            table_data = group[["UserId", "Operation", "CreationDate"]].values.tolist()

            # Add Display Name column
            table = []
            for row in table_data:
                user_email = row[0]
                display_name = self.user_mapping.get(str(user_email).lower(), "Unknown")
                # Create a new list with the display name inserted at position 1
                table.append([user_email, display_name, row[1], row[2]])

            # Define minimum column widths
            min_widths = [22, 22, 20, 20]

            headers = ["Username", "Display Name", "Action Performed", "Timestamp (UTC)"]

            # Create a format string for each column
            col_formats = [f"{{:<{width}}}" for width in min_widths]

            # Apply the formats to the headers and data
            formatted_headers = [
                fmt.format(header) for fmt, header in zip(col_formats, headers, strict=False)
            ]
            formatted_table = [
                [fmt.format(str(cell)) for fmt, cell in zip(col_formats, row, strict=False)]
                for row in table
            ]

            # Color the headers
            colored_headers = self.out.color_headers(formatted_headers)

            print(tabulate(formatted_table, headers=colored_headers, tablefmt="plain"))
            print()

        total_actions = len(filtered_actions)
        print(f"\nTotal actions on files containing '{keyword}': {total_actions}")

    def list_files_with_keyword(self, file_actions: DataFrame, keyword: str) -> None:
        """List files containing the specified keyword."""
        filtered_files = file_actions[
            file_actions["SourceFileName"].str.contains(keyword, case=False, na=False)
        ]
        unique_files = filtered_files["SourceFileName"].unique()

        if len(unique_files) == 0:
            printc(f"\nNo files found containing '{keyword}'.", "yellow")
        else:
            self.out.print_header(f"Files containing '{keyword}':")
            for file in sorted(unique_files):
                print(file)

    def analyze_multiple_downloads(self, downloads: DataFrame, show_details: bool = False) -> None:
        """Analyze and display files that were downloaded multiple times."""
        duplicate_downloads = downloads["SourceFileName"].value_counts()
        suspicious_downloads = duplicate_downloads[duplicate_downloads > 1]
        if not suspicious_downloads.empty:
            print(color("    Multiple Downloads:", "yellow"))

            # Create a list of files with their paths
            files_with_paths = []
            for filename in suspicious_downloads.index:
                # Find the path for this file
                file_rows = downloads[downloads["SourceFileName"] == filename]
                if not file_rows.empty:
                    path = file_rows.iloc[0].get("CleanPath", "")
                    files_with_paths.append((filename, path))

            if show_details:  # Use hierarchical display with details flag
                print(self.format_hierarchical_file_list(files_with_paths))
            else:  # Use flat display without details
                print(self.format_file_list_with_paths(files_with_paths, show_paths=False))

    def analyze_bulk_operations(
        self, df: DataFrame, op_type: str, show_details: bool = False, time_window: int = 5
    ) -> None:
        """Analyze and display rapid bulk operations within a time window."""
        if df.empty:
            return

        df = df.sort_values("CreationDate")
        df["time_diff"] = df["CreationDate"].diff()
        bulk_ops = df[df["time_diff"].dt.total_seconds() < time_window * 60]

        if bulk_ops.empty:
            return

        # Check if there are any groups that meet the criteria before printing header
        groups = bulk_ops.groupby(bulk_ops["CreationDate"].dt.floor("5min"))
        has_rapid_ops = any(len(group) > 5 for _, group in groups)

        if not has_rapid_ops:
            return

        print(color(f"    Rapid {op_type} (within {time_window} minutes):", "yellow"))
        for _, group in groups:
            if len(group) > 5:
                timestamp = group["CreationDate"].iloc[0].strftime("%Y-%m-%d %H:%M:%S")
                print(f"{' ' * 6}At {color(timestamp, 'cyan')}:")

                if show_details:
                    # Create a list of files with their paths
                    files_with_paths = []
                    for _, row in group.iterrows():
                        filename = row["SourceFileName"]
                        path = row.get("CleanPath", "")
                        files_with_paths.append((filename, path))

                    # Use hierarchical display
                    print(self.format_hierarchical_file_list(files_with_paths))
                else:
                    # Just show the count
                    print(f"{' ' * 8}{color(str(len(group)), 'yellow')} files")

    def format_file_list(
        self,
        files: list[str] | np.ndarray[Any, Any],
        timestamp: str | None = None,
        count: int | None = None,
        indent: int = 6,
    ) -> str:
        """Format a list of files, consolidating similar names."""
        output_lines = []
        indent_str = " " * indent

        # If we have timestamp info, add it first without bullet point
        if timestamp and count:
            output_lines.append(
                f"{' ' * (indent - 2)}{color(str(count), 'yellow')} files at "
                f"{color(timestamp, 'cyan')}"
            )

        # Process the files
        grouped_files = self.group_similar_filenames(files)
        for base_file, variants in grouped_files:
            if variants:  # We have variants
                output_lines.append(
                    f"{indent_str}- {color(base_file, 'green')} +{len(variants) - 1!s} similar"
                )
            else:  # Single file
                output_lines.append(f"{indent_str}- {color(base_file, 'green')}")

        return "\n".join(output_lines)

    def format_file_list_with_paths(
        self,
        files_with_paths: list[tuple[str, str]],
        timestamp: str | None = None,
        count: int | None = None,
        indent: int = 6,
        show_paths: bool = False,
    ) -> str:
        """Format a list of files with their paths, consolidating similar names."""
        output_lines = []
        indent_str = " " * indent

        # If we have timestamp info, add it first without bullet point
        if timestamp and count:
            output_lines.append(
                f"{' ' * (indent - 2)}{color(str(count), 'yellow')} files at "
                f"{color(timestamp, 'cyan')}"
            )

        # Process the files
        for filename, path in files_with_paths:
            path_display = f" ({path})" if path and show_paths else ""
            output_lines.append(f"{indent_str}- {color(filename, 'green')}{path_display}")

        return "\n".join(output_lines)

    def format_hierarchical_file_list(
        self, files_with_paths: list[tuple[str, str]], indent: int = 6
    ) -> str:
        """Format files in a hierarchical tree structure based on their paths."""
        # Group files by path
        path_groups: dict[str, list[str]] = {}
        for filename, path in files_with_paths:
            if not path:
                # Handle files with no path
                if "No Path" not in path_groups:
                    path_groups["No Path"] = []
                path_groups["No Path"].append(filename)
            else:
                if path not in path_groups:
                    path_groups[path] = []
                path_groups[path].append(filename)

        # Build the output
        output_lines = []
        base_indent = " " * indent

        # Sort paths alphabetically (case-insensitive)
        for path in sorted(path_groups.keys(), key=str.lower):
            # Print the path as a header
            if path != "No Path":
                output_lines.append(f"{base_indent[:-2]}+ {color(path, 'yellow')}")
            else:
                output_lines.append(
                    f"{base_indent[:-2]}+ {color('Files with no path information', 'yellow')}"
                )

            # Print files in this path, sorted alphabetically (case-insensitive)
            output_lines.extend(
                f"{base_indent}  - {color(filename, 'green')}"
                for filename in sorted(path_groups[path], key=str.lower)
            )

        return "\n".join(output_lines)

    @staticmethod
    def group_similar_filenames(
        filenames: list[str] | np.ndarray[Any, Any],
    ) -> list[tuple[str, list[str]]]:
        """Group similar filenames together, detecting patterns like (1), (2), etc."""

        def clean_filename(filename: str) -> str:
            """Remove common patterns from filename for grouping."""
            # Remove patterns like (1), (2), etc.
            base = re.sub(r" \(\d+\)(?=\.[^.]+$)", "", filename)
            # Remove patterns like (version 1), (version 2), etc.
            base = re.sub(r" \(version \d+\)(?=\.[^.]+$)", "", base)
            # Remove patterns like (AutoRecovered)
            return re.sub(r" \(AutoRecovered\)(?=\.[^.]+$)", "", base)

        # Sort and group by cleaned filename
        sorted_files = sorted(filenames, key=clean_filename)
        grouped_files = []

        for base_name, group in groupby(sorted_files, key=clean_filename):
            group_list = list(group)
            if len(group_list) > 1:
                # If there are variants, store as (base_name, variants)
                grouped_files.append((base_name, group_list))
            else:
                # If there's only one file, store as is
                grouped_files.append((group_list[0], []))

        return grouped_files

    def analyze_file_operations(self, file_actions: DataFrame, show_details: bool = False) -> None:
        """Analyze file operations with a focus on security-relevant patterns."""
        if file_actions.empty:
            printc("\nNo file operations found.", "yellow")
            return

        self.out.print_header("File Operations Analysis")

        # Group operations by user and date
        daily_ops = (
            file_actions.groupby(["UserId", file_actions["CreationDate"].dt.date, "Operation"])
            .size()
            .reset_index(name="count")
        )

        # Analyze high volume days
        self.analyze_high_volume_days(daily_ops)

        # Analyze operations by user
        has_user_operations = False
        for user, user_group in file_actions.groupby("UserId"):
            downloads = user_group[user_group["Operation"].str.contains("Download", na=False)]
            uploads = user_group[user_group["Operation"].str.contains("Upload", na=False)]

            if len(downloads) > 0 or len(uploads) > 0:
                if not has_user_operations:
                    printc("\nOperation Summary by User:", "yellow")
                    has_user_operations = True

                print(f"\n  {color(user, 'cyan')}:")

                # Analyze different patterns
                self.analyze_multiple_downloads(downloads)
                self.analyze_bulk_operations(downloads, "Downloads", show_details)
                self.analyze_bulk_operations(uploads, "Uploads", show_details)

                # Display statistics and unusual patterns
                printc("\nOverall Statistics:", "yellow")
                self.display_user_statistics(str(user), user_group)
                self.analyze_unusual_patterns(user_group)

    def detect_suspicious_patterns(
        self, file_actions: DataFrame, show_details: bool = False
    ) -> None:
        """Detect potentially suspicious activity patterns."""
        # Mass operations summary
        has_suspicious_activity = False

        for operation_type in ["Download", "Delete"]:
            bulk_ops = file_actions[
                file_actions["Operation"].str.contains(operation_type, na=False)
            ]
            if not bulk_ops.empty:
                user_counts = bulk_ops.groupby("UserId").size()
                suspicious = user_counts[
                    user_counts >= int(self.suspicious_patterns[f"mass_{operation_type.lower()}s"])
                ]
                if not suspicious.empty:
                    if not has_suspicious_activity:
                        self.out.print_header("Bulk Operations")
                        has_suspicious_activity = True
                    print(f"\n  Users with bulk {operation_type.lower()}s:")
                    for user, count in suspicious.items():
                        self._display_user_bulk_operations(
                            str(user),
                            count,
                            operation_type,
                            bulk_ops,
                            show_details,
                        )

    def _display_user_bulk_operations(
        self, user: str, count: int, operation_type: str, bulk_ops: DataFrame, show_details: bool
    ) -> None:
        """Display details of bulk operations for a specific user."""
        print(f"    {color(user, 'cyan')}: {color(str(count), 'yellow')} {operation_type}s")
        if show_details:
            # Show the files for this user's bulk operations
            user_files = bulk_ops[bulk_ops["UserId"] == user]

            # Create a list of files with their paths
            files_with_paths = []
            seen_files = set()  # To avoid duplicates
            for _, row in user_files.iterrows():
                filename = row["SourceFileName"]
                path = row.get("CleanPath", "")
                if (filename, path) not in seen_files:
                    files_with_paths.append((filename, path))
                    seen_files.add((filename, path))

            # Use hierarchical display
            print(self.format_hierarchical_file_list(files_with_paths))

    def analyze_high_volume_days(self, daily_ops: DataFrame, threshold: int = 100) -> None:
        """Analyze and display days with high volume of operations."""
        high_volume_days = daily_ops[daily_ops["count"] >= threshold]

        if not high_volume_days.empty:
            printc("\nHigh Volume Days:", "yellow")
            for (user, date), group in high_volume_days.groupby(["UserId", "CreationDate"]):
                total = group["count"].sum()
                print(
                    f"\n  {color(user, 'cyan')} on {color(str(date), 'cyan')} - "
                    f"{color(str(total), 'yellow')} total operations:"
                )
                for _, row in group.iterrows():
                    print(f"    - {row['Operation']}: {color(str(row['count']), 'yellow')}")

    def display_user_statistics(self, user: str, group: DataFrame) -> None:
        """Display overall statistics for a user."""
        downloads = sum(group["Operation"].str.contains("Download", na=False))
        uploads = sum(group["Operation"].str.contains("Upload", na=False))
        print(f"\n  {color(user, 'cyan')}:")
        print(f"    Downloads: {color(str(downloads), 'yellow')}")
        print(f"    Uploads: {color(str(uploads), 'yellow')}")

    def analyze_unusual_patterns(self, group: DataFrame, show_details: bool = False) -> None:
        """Analyze and display files with unusual operation patterns."""
        multiple_ops = group["SourceFileName"].value_counts()
        unusual = multiple_ops[multiple_ops > 2]  # Files with more than 2 operations

        if not unusual.empty:
            print(color("    Files with multiple operations:", "yellow"))
            for filename in unusual.index:
                file_ops = group[group["SourceFileName"] == filename]["Operation"].value_counts()
                ops_list = [
                    f"{op}: {color(str(count), 'yellow')}" for op, count in file_ops.items()
                ]
                ops_str = ", ".join(ops_list)

                # Get the path for this file
                file_rows = group[group["SourceFileName"] == filename]
                path = file_rows.iloc[0].get("CleanPath", "") if not file_rows.empty else ""
                path_display = f" ({path})" if path and show_details else ""

                print(f"      - {color(filename, 'green')}{path_display}: {ops_str}")

    def analyze_accessed_paths(self, file_actions: DataFrame) -> None:
        """Analyze and display a list of unique paths that were accessed."""
        # Group paths by top-level directory for better organization
        path_groups: dict[str, set[str]] = {}

        # First, collect all file paths to find out which folders were accessed
        for _, row in file_actions.iterrows():
            path = row["CleanPath"]
            filename = row["SourceFileName"]

            if not path or not filename:
                continue

            # Format groups based on location, full path, and filename
            path_groups = self._format_file_paths(path, filename, path_groups)

        # Check if there are any paths to display
        if not path_groups:
            printc("\nNo SharePoint access found.", "yellow")
            return

        self.out.print_header("Accessed SharePoint Locations")

        # Print grouped paths (sort top directories case-insensitive)
        for top_dir, paths in sorted(path_groups.items(), key=lambda x: x[0].lower()):
            printc(f"\n{top_dir}:", "yellow")

            if paths:
                sorted_paths = sorted(paths)
                for path in sorted_paths:
                    printc(f"  {path}", "green")

    def _format_file_paths(
        self, path: str, filename: str, path_groups: dict[str, set[str]]
    ) -> dict[str, set[str]]:
        # Determine the top-level directory
        if path.startswith("OneDrive ≫"):
            # For OneDrive paths, extract the username part as the top directory
            parts = path.split("/", maxsplit=1)
            top_dir = parts[0]  # "OneDrive ≫ username"

            if top_dir not in path_groups:
                path_groups[top_dir] = set()

            # If there's a path after OneDrive ≫ username, use it + filename
            if len(parts) > 1:
                base_path = (
                    parts[1].replace("Documents/Documents/", "Documents/")
                    if parts[1].startswith("Documents/Documents/")
                    else parts[1].replace("Documents/", "")
                )
                path_groups[top_dir].add(f"{base_path}/{filename}")
            else:
                # If the file is in the root, just add the filename
                path_groups[top_dir].add(filename)
        else:
            # For SharePoint, use the first folder as top directory
            top_dir = path.split("/", maxsplit=1)[0] if "/" in path else path
            if top_dir not in path_groups:
                path_groups[top_dir] = set()

            # Build full path including filename
            full_path = f"{path}/{filename}"
            path_groups[top_dir].add(full_path)

        return path_groups

    def get_overall_statistics(
        self, file_actions: DataFrame, actions_to_analyze: list[str]
    ) -> dict[str, pd.Series[str]]:
        """Get overall statistics for file actions."""
        action_stats = {}
        for action in actions_to_analyze:
            action_data = file_actions[file_actions["Operation"] == action]
            action_stats[action] = self.users.get_top_users(action_data, action)
        return action_stats

    def print_timeline(self, df: DataFrame) -> None:
        """Print a chronological timeline of file access events."""
        if df.empty:
            self.logger.info("No file access events found.")
            return

        # Sort by creation date (oldest first)
        sorted_df = df.sort_values("CreationDate")
        self.out.print_header("File Access Timeline (Oldest to Newest)")

        # Calculate column widths
        column_widths = self._calculate_timeline_column_widths(sorted_df)

        # Process and display timeline entries
        self._display_timeline_entries(sorted_df, column_widths)

    def _calculate_timeline_column_widths(self, df: DataFrame) -> dict[str, int]:
        """Calculate the maximum column widths for timeline formatting."""
        max_user_len = max(
            len(str(self.user_mapping.get(str(user).lower(), user)))
            for user in df["UserId"].unique()
        )
        max_operation_len = max(len(str(op)) for op in df["Operation"].unique())

        # Add some padding for better readability
        return {"user": max_user_len + 2, "operation": max_operation_len + 2}

    def _format_timeline_entry(
        self,
        timestamp: str | None,
        user: str | None,
        operation: str | None,
        file_path: str | None,
        widths: dict[str, int],
    ) -> str:
        """Format a single timeline entry with proper colors and alignment."""
        user_padded = f"{user:{widths['user']}}"
        operation_padded = f"{operation:{widths['operation']}}"

        colored_timestamp = color(timestamp or "", "cyan")
        colored_user = color(user_padded or "", "cyan")
        colored_operation = color(operation_padded or "", "yellow")
        colored_file_path = color(file_path or "", "green")

        return f"{colored_timestamp} - {colored_user} {colored_operation} {colored_file_path}"

    def _display_timeline_entries(self, df: DataFrame, column_widths: dict[str, int]) -> None:
        """Process and display timeline entries, handling duplicates."""
        prev_user = None
        prev_operation = None
        prev_file_path = None

        # Format and print each event with aligned columns
        for i, (_, row) in enumerate(df.iterrows()):
            timestamp = row["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")
            user_email = row["UserId"]
            user = str(self.user_mapping.get(str(user_email).lower(), user_email))
            operation = str(row["Operation"])
            filename = row["SourceFileName"]
            path = row["CleanPath"]

            file_path = f"{path}/{filename}" if path else filename

            # Check if this is a duplicate of the previous entry
            is_duplicate = (
                user == prev_user and operation == prev_operation and file_path == prev_file_path
            )

            if is_duplicate:
                continue

            # Print the current non-duplicate entry
            if i == 0 or not is_duplicate:
                print(
                    self._format_timeline_entry(
                        timestamp,
                        user,
                        operation,
                        file_path,
                        column_widths,
                    )
                )

            # Reset duplicate counter and save current values
            prev_user = user
            prev_operation = operation
            prev_file_path = file_path

    def export_file_urls(self, file_actions: DataFrame) -> None:
        """Export full URLs of all accessed files."""
        import urllib.parse

        self.out.print_header("SharePoint and OneDrive URLs")

        # Group URLs by top-level directory for better organization
        url_groups: dict[str, set[str]] = {}

        # First, collect all file URLs
        for _, row in file_actions.iterrows():
            path = row["CleanPath"]
            filename = row["SourceFileName"]
            object_id = row.get("ObjectId", "")

            if not path or not filename or not object_id:
                continue

            # URL encode the object_id to make it clickable
            encoded_url = urllib.parse.quote(object_id, safe=":/")

            # Determine the top-level directory for grouping
            if path.startswith("OneDrive ≫"):
                # For OneDrive URLs
                parts = path.split("/", maxsplit=1)
                top_dir = parts[0]  # "OneDrive ≫ username"

                if top_dir not in url_groups:
                    url_groups[top_dir] = set()

                # Add the full URL
                url_groups[top_dir].add(encoded_url)
            else:
                # For SharePoint URLs
                top_dir = path.split("/")[0] if "/" in path else path
                if top_dir not in url_groups:
                    url_groups[top_dir] = set()

                # Add the full URL
                url_groups[top_dir].add(encoded_url)

        # Print grouped URLs (sort top directories case-insensitive)
        for top_dir, urls in sorted(url_groups.items(), key=lambda x: x[0].lower()):
            printc(f"\n{top_dir}:", "yellow")

            if urls:
                sorted_urls = sorted(urls)
                for url in sorted_urls:
                    printc(f"  {url}", "green")
