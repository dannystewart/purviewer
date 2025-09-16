# type: ignore[reportAssignmentType]
from __future__ import annotations

import csv
import operator
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pandas as pd
from pandas import DataFrame
from polykit.text import print_color as printc
from tabulate import tabulate

from purviewer.tools import AuditAnalyzer

if TYPE_CHECKING:
    from pandas import DataFrame


@dataclass
class UserActions(AuditAnalyzer):
    """Analyze user activity in the file actions."""

    def __post_init__(self) -> None:
        self.max_users: int = self.config.max_users

    def create_user_mapping(self, users_file: str | None = None) -> dict[str, str]:
        """Create a mapping of User Principal Name to Display Name from a CSV file."""
        user_mapping = {}

        if users_file is None:
            return user_mapping

        try:
            with Path(users_file).open(encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    user_mapping[row["User principal name"].lower()] = row["Display name"]
        except FileNotFoundError:
            pass  # User mapping is optional, so just silently skip if no file is found
        return user_mapping

    def filter_by_user(self, user: str, file_actions: DataFrame) -> DataFrame:
        """Filter file actions by user, adding domain if missing."""
        if "@" not in user and self.config.email_domain:
            user += f"@{self.config.email_domain}"
        return file_actions[file_actions["UserId"].str.lower() == user.lower()]

    def get_top_users(self, df: DataFrame, action_name: str) -> pd.Series[int]:
        """Get the top users for a specific action."""
        if df.empty:
            return pd.Series()

        user_counts = df["UserId"].value_counts().head(self.max_users)

        # Only display the table if there's more than one user
        unique_users = df["UserId"].nunique()
        if unique_users > 1:
            self.out.print_header(
                f"Top {min(self.max_users, unique_users)} users by {action_name} count"
            )

            # Create a table with user names
            table_data = []
            for user, count in user_counts.items():
                display_name = self.config.user_mapping.get(str(user).lower(), "Unknown")
                table_data.append([user, display_name, count])

            headers = ["User", "Name", "Count"]
            print(tabulate(table_data, headers=headers, tablefmt="simple"))

        return user_counts

    def get_grouped_actions(
        self, user_actions: DataFrame, actions_to_analyze: list[str], sort_by: str
    ) -> None:
        """Get grouped file actions taken by the user."""
        grouped_actions: dict[str, list[Any]] = defaultdict(list)

        for _, row in user_actions.iterrows():
            grouped_actions[row["Operation"]].append(row)

        sort_key = {"date": "CreationDate", "filename": "SourceFileName", "username": "UserId"}.get(
            sort_by, "CreationDate"
        )

        for action in actions_to_analyze:
            if action in grouped_actions:
                printc(f"\n{action}:", "yellow")
                sorted_ops = sorted(
                    grouped_actions[action],
                    key=operator.itemgetter(sort_key),
                    reverse=(sort_by == "date"),
                )

                headers = ["File Name", "User", "Date"]
                min_widths = [40, 15, 0]
                col_formats = [f"{{:<{width}}}" for width in min_widths]

                formatted_headers = [
                    fmt.format(header) for fmt, header in zip(col_formats, headers, strict=False)
                ]
                formatted_table = [
                    [
                        fmt.format(str(row[col]))
                        for fmt, col in zip(
                            col_formats, ["SourceFileName", "UserId", "CreationDate"], strict=False
                        )
                    ]
                    for row in sorted_ops
                ]

                colored_headers = self.out.color_headers(formatted_headers)

                print(tabulate(formatted_table, headers=colored_headers, tablefmt="plain"))
