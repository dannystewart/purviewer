# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from polykit.text import color
from polykit.text import print_color as printc

if TYPE_CHECKING:
    from logging import Logger

    from pandas import DataFrame
    from polykit.text.types import TextColor

    from purviewer.data import AuditConfig


@dataclass
class OutputFormatter:
    """Format output with consistent styling."""

    config: AuditConfig
    logger: Logger

    def print_header(self, header: str, color: TextColor | None = None) -> None:
        """Print a header with a separator."""
        if color is None:
            color = "blue"

        separator = "=" * len(header)
        printc(f"\n{header}\n{separator}", color)

    def color_headers(self, headers: list[str], color_name: TextColor | None = None) -> list[str]:
        """Apply color to headers."""
        if color_name is None:
            color_name = "yellow"

        return [color(header, color_name) for header in headers]

    def print_date_range(self, df: DataFrame, filtered_df: DataFrame | None = None) -> None:
        """Print the date range of the data."""
        start_date = df["CreationDate"].min().strftime("%Y-%m-%d")
        end_date = df["CreationDate"].max().strftime("%Y-%m-%d")

        if filtered_df is not None and not filtered_df.empty:
            filtered_start = filtered_df["CreationDate"].min().strftime("%Y-%m-%d")
            filtered_end = filtered_df["CreationDate"].max().strftime("%Y-%m-%d")
            print(color("Original log range: ", "green") + f"{start_date} to {end_date}")
            print(color("Filtering results to: ", "yellow") + f"{filtered_start} to {filtered_end}")
        else:
            print(color("Date range: ", "green") + f"{start_date} to {end_date}")
