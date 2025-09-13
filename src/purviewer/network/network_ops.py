# type: ignore[reportAssignmentType]
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import iplooker.ip_looker as iplooker
from polykit.text import color
from polykit.text import print_color as printc

from purviewer.data import AuditAnalyzer

if TYPE_CHECKING:
    from pandas import DataFrame


@dataclass
class NetworkOperations(AuditAnalyzer):
    """Analyze network activity in the file actions."""

    @staticmethod
    def is_ipv6(ip: Any) -> bool:
        """Check if an IP address is IPv6."""
        return ":" in str(ip)

    @staticmethod
    def matches_ip_pattern(ip: str, patterns: list[str]) -> bool:
        """Check if an IP address matches any of the given patterns (supporting wildcards)."""
        ip_str = str(ip)
        return any(fnmatch.fnmatch(ip_str, pattern) for pattern in patterns)

    def analyze_ip_addresses(self, file_actions: DataFrame) -> None:
        """Analyze IP addresses used in file actions."""
        if "ClientIP" not in file_actions.columns or file_actions["ClientIP"].isna().all():
            printc("\nNo IP information available.", "yellow")
            return

        self.out.print_header("IP Address Summary")
        ip_counts = file_actions["ClientIP"].value_counts()

        # Separate IPv4 and IPv6 addresses
        ipv4_counts = {ip: count for ip, count in ip_counts.items() if not self.is_ipv6(ip)}
        ipv6_counts = {ip: count for ip, count in ip_counts.items() if self.is_ipv6(ip)}

        # Show IPv4 addresses
        if ipv4_counts:
            self._print_ip_usage(ipv4_counts, file_actions, "IPv4", 15)

        # Show IPv6 addresses
        if ipv6_counts:
            self._print_ip_usage(ipv6_counts, file_actions, "IPv6", 40)

    def _print_ip_usage(
        self, ip_counts: dict[Any, int], file_actions: DataFrame, ip_type: str, ip_width: int
    ) -> None:
        """Print IP address usage statistics."""
        printc(f"\n{ip_type} Addresses by Usage:", "yellow")
        for ip, count_ip in ip_counts.items():
            actions = file_actions[file_actions["ClientIP"] == ip]
            users = actions["UserId"].nunique()

            if users == 1:
                print(
                    f"  - {ip:{ip_width}} {color(f'{count_ip:>5}', 'yellow')} {'action' if count_ip == 1 else 'actions'}"
                )
            else:
                print(
                    f"  - {ip:{ip_width}} {color(f'{count_ip:>5}', 'yellow')} actions by "  # No pluralization, for alignment
                    f"{color(str(users), 'yellow')} users"
                )

            if users > 1:  # Show user breakdown only for IPs used by multiple users
                for user, count_user in actions["UserId"].value_counts().items():
                    print(
                        f"      {color(user, 'cyan')}: "
                        f"{color(str(count_user), 'yellow')} {'action' if count_user == 1 else 'actions'}"
                    )

    def analyze_ip_addresses_with_lookup(self, file_actions: DataFrame) -> None:
        """Analyze IP addresses with detailed lookups."""
        self.out.print_header("IP Address Analysis")

        if "ClientIP" not in file_actions.columns or file_actions["ClientIP"].isna().all():
            printc("\nNo IP information available.", "yellow")
            return

        # Get unique IPs and their usage
        ip_counts = file_actions["ClientIP"].value_counts()

        # Separate IPv4 and IPv6
        ipv4_counts = {ip: count for ip, count in ip_counts.items() if not self.is_ipv6(ip)}
        ipv6_counts = {ip: count for ip, count in ip_counts.items() if self.is_ipv6(ip)}

        # Process IPv4 addresses
        if ipv4_counts:
            self._print_ip_usage(ipv4_counts, file_actions, "IPv4", 15)

            # Do the IP lookup
            for ip in ipv4_counts:
                iplooker.IPLooker(str(ip))

        # Process IPv6 addresses
        if ipv6_counts:
            self._print_ip_usage(ipv6_counts, file_actions, "IPv6", 40)

            # Do the IP lookup
            for ip in ipv6_counts:
                iplooker.IPLooker(str(ip))

    def analyze_user_agents(self, file_actions: DataFrame) -> None:
        """Analyze user agents for potential suspicious activity."""
        if "UserAgent" not in file_actions.columns:
            printc("\nNo User Agent information available.", "yellow")
            return

        # Filter out empty user agents
        valid_agents = file_actions[
            file_actions["UserAgent"].notna() & (file_actions["UserAgent"] != "")
        ]

        if valid_agents.empty:
            return

        self.out.print_header("User Agent Analysis")

        agents = valid_agents["UserAgent"].value_counts()
        known_good = self.config.known_good
        unknown_agents = [
            agent
            for agent in agents.index
            if not any(known in str(agent) for known in known_good["user_agents"])
        ]

        if unknown_agents:
            # First, show a summary
            total_actions = sum(agents[agent] for agent in unknown_agents)
            total_users = len(
                set(valid_agents[valid_agents["UserAgent"].isin(unknown_agents)]["UserId"])
            )
            print(
                f"\nFound {color(str(len(unknown_agents)), 'yellow')} unique user agents "
                f"performing {color(str(total_actions), 'yellow')} actions "
                f"by {color(str(total_users), 'yellow')} {'user' if total_users == 1 else 'users'}:\n"
            )

            # Then show the details
            for agent in unknown_agents:
                actions = valid_agents[valid_agents["UserAgent"] == agent]
                users = actions["UserId"].unique()

                if total_users == 1:  # Compact format for single user
                    action_count = len(actions)
                    action_count_text = color(f"{action_count}", "yellow")
                    print(f"  - {color('Agent:', 'yellow')} {agent} ({action_count_text} actions)")
                else:  # Detailed format for multiple users
                    print(f"  - {color('Agent:', 'yellow')} {agent}")
                    for user in users:
                        user_actions = actions[actions["UserId"] == user]
                        print(
                            f"      {color(user, 'cyan')}: "
                            f"{color(str(len(user_actions)), 'yellow')} actions"
                        )
                    print()
        else:
            self.logger.info("No unknown User Agents were found.")

    def analyze_specific_ips(self, file_actions: DataFrame, ip_list: list[str]) -> None:
        """Analyze activity from specific IP addresses."""
        self.out.print_header(
            f"Analysis for Specified IP Address{'es' if len(ip_list) > 1 else ''}"
        )

        def matches_pattern(ip: str) -> bool:
            return self.matches_ip_pattern(ip, [ip])

        for ip in ip_list:
            ip_actions = file_actions[file_actions["ClientIP"].apply(matches_pattern)]

            if ip_actions.empty:
                print(f"No activity found for IP: {ip}")
                continue

            printc(f"\nIP: {ip}", "yellow")

            # List the IPs that matched the pattern
            matching_ips = ip_actions["ClientIP"].unique()
            if len(matching_ips) == 1:
                print(f"  Matching IP: {matching_ips[0]}")
            else:
                print(f"  Matching IPs ({len(matching_ips)}): {', '.join(matching_ips)}")

            # Get user breakdown
            users = ip_actions["UserId"].value_counts()
            print(f"  Total events: {len(ip_actions)}")
            print(f"  Unique users: {len(users)}")
            print(
                f"  Date range: {ip_actions['CreationDate'].min().strftime('%Y-%m-%d %H:%M')} to "
                f"{ip_actions['CreationDate'].max().strftime('%Y-%m-%d %H:%M')}"
            )

            # Show operations performed from this IP
            operations = ip_actions["Operation"].value_counts()
            print("\n  Operations:")
            for op, count in operations.items():
                print(f"    - {op}: {color(str(count), 'yellow')}")

            # Show user breakdown
            print("\n  Users:")
            for user, count in users.items():
                printc(f"    - {user} ", "cyan", end="")
                print(f"({count} events")

                # Show operations by this user from this IP
                user_ops = ip_actions[ip_actions["UserId"] == user]["Operation"].value_counts()
                for op, op_count in user_ops.items():
                    print(f"      - {op}: {op_count}")

            # Show timeline of events
            print("\n  Timeline:")
            ip_actions_sorted = ip_actions.sort_values("CreationDate")
            for _, row in ip_actions_sorted.iterrows():
                date = row["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")
                user = row["UserId"]
                operation = row["Operation"]
                filename = row.get("SourceFileName", "N/A")

                printc(f"    {date}", "cyan", end=" ")
                printc(f"{user}", "cyan", end=" ")
                print(f"{operation} - {filename}")
