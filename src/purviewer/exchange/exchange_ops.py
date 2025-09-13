# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

# type: ignore[reportAssignmentType]

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from polykit.text import print_color as printc

from purviewer.data import AuditAnalyzer

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from pandas import DataFrame, Series


@dataclass
class ExchangeOperations(AuditAnalyzer):
    """Analyze Exchange activity in the audit logs."""

    def process_exchange_events(self, df: DataFrame) -> DataFrame:
        """Process and format Exchange-specific events."""
        # Filter for Exchange workload
        exch_data = df[
            df["AuditData"].apply(lambda x: isinstance(x, dict) and x.get("Workload") == "Exchange")
        ]

        if exch_data.empty:
            return exch_data

        # Extract additional Exchange-specific fields
        exchange_events = exch_data.copy()
        exchange_events = self._extract_basic_fields(exchange_events)

        # Extract item subject and details
        exchange_events["ItemSubject"] = exchange_events["AuditData"].apply(
            self._extract_item_subject
        )
        exchange_events["ItemDetails"] = exchange_events["AuditData"].apply(
            self._extract_item_details
        )

        return exchange_events

    def _extract_basic_fields(self, exchange_events: DataFrame) -> DataFrame:
        """Extract basic Exchange-specific fields."""
        exchange_events["Workload"] = exchange_events["AuditData"].apply(
            lambda x: x.get("Workload", "")
        )
        exchange_events["ResultStatus"] = exchange_events["AuditData"].apply(
            lambda x: x.get("ResultStatus", "")
        )
        exchange_events["ExternalAccess"] = exchange_events["AuditData"].apply(
            lambda x: x.get("ExternalAccess", False)
        )
        exchange_events["ClientInfoString"] = exchange_events["AuditData"].apply(
            lambda x: x.get("ClientInfoString", "")
        )
        return exchange_events

    def _extract_item_subject(self, audit_data: dict[str, Any] | None) -> str:
        """Extract subject information from audit data."""
        if not isinstance(audit_data, dict):
            return "No subject available"

        # Check different possible locations for subject
        if "Item" in audit_data and isinstance(audit_data["Item"], dict):
            return audit_data["Item"].get("Subject", "")
        if (
            "AffectedItems" in audit_data
            and isinstance(audit_data["AffectedItems"], list)
            and audit_data["AffectedItems"]
        ):
            return audit_data["AffectedItems"][0].get("Subject", "")
        if (
            "Folders" in audit_data
            and isinstance(audit_data["Folders"], list)
            and audit_data["Folders"]
        ):
            folder_items = audit_data["Folders"][0].get("FolderItems", [])
            if folder_items and isinstance(folder_items, list):
                return f"{len(folder_items)} items in {audit_data['Folders'][0].get('Path', 'unknown folder')}"
        return "No subject available"

    def _extract_item_details(self, audit_data: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Extract detailed information about accessed items."""
        if not isinstance(audit_data, dict):
            return []

        items = []

        # Check for AffectedItems
        if "AffectedItems" in audit_data and isinstance(audit_data["AffectedItems"], list):
            items.extend([item for item in audit_data["AffectedItems"] if isinstance(item, dict)])

        # Check for Item
        elif "Item" in audit_data and isinstance(audit_data["Item"], dict):
            items.append(audit_data["Item"])

        # Check for Folders
        elif "Folders" in audit_data and isinstance(audit_data["Folders"], list):
            for folder in audit_data["Folders"]:
                if isinstance(folder, dict) and "FolderItems" in folder:
                    for item in folder.get("FolderItems", []):
                        if isinstance(item, dict):
                            # Add folder path to item
                            item["FolderPath"] = folder.get("Path", "Unknown folder")
                            items.append(item)

        return items

    def display_exchange_events(
        self, exchange_events: DataFrame, show_details: bool = False
    ) -> None:
        """Display Exchange events in a meaningful, condensed format."""
        if exchange_events.empty:
            return

        # Create a copy to avoid SettingWithCopyWarning
        events_df = exchange_events.copy()

        self.out.print_header("Exchange Activity Analysis", "blue")

        # Get total event count and date range
        total_events = len(events_df)
        start_date = events_df["CreationDate"].min().strftime("%Y-%m-%d")
        end_date = events_df["CreationDate"].max().strftime("%Y-%m-%d")
        self.logger.info(
            "Found %d Exchange event%s from %s to %s.",
            total_events,
            "s" if total_events > 1 else "",
            start_date,
            end_date,
        )

        self._summarize_user_activity(events_df)
        self._analyze_client_applications(events_df)
        self._analyze_noteworthy_operations(events_df)
        self._analyze_folder_access(events_df)
        self._analyze_email_details(events_df, show_details)

    def _summarize_user_activity(self, events_df: DataFrame) -> None:
        """Summarize activity by user with operation breakdowns."""
        printc("\nExchange Activity by User:", "yellow")
        user_counts = events_df["UserId"].value_counts()

        for user, count in user_counts.items():
            user_ops = events_df[events_df["UserId"] == user]["Operation"].value_counts()

            printc(f"  {user} ", "cyan", end="")
            print(f"{count} total event{'s' if count > 1 else ''}")

            # Show operation breakdown for this user
            for op, op_count in user_ops.items():
                print(f"    - {op}: {op_count}")

    def _analyze_client_applications(self, events_df: DataFrame) -> None:
        """Analyze client applications used for Exchange operations."""
        printc("\nClient Applications Used:", "yellow")

        # Create a copy for modification
        df = events_df.copy()

        # Extract client app from ClientInfoString
        def extract_client(client_string: str) -> str:
            if not client_string:
                return "Unknown"
            if "Client=OWA" in client_string:
                return "Outlook Web Access"
            if "Client=REST" in client_string:
                return "REST API"
            if "Client=Outlook" in client_string:
                return "Outlook Desktop"
            if "Client=Exchange" in client_string:
                return "Exchange"
            return (
                client_string.split(";", maxsplit=1)[0] if ";" in client_string else client_string
            )

        df["ClientApp"] = df["ClientInfoString"].apply(extract_client)
        client_counts = df["ClientApp"].value_counts()

        for client, count in client_counts.items():
            print(f"  {client}: {count} event{'s' if count > 1 else ''}")

    def _analyze_noteworthy_operations(self, events_df: DataFrame) -> None:
        """Analyze noteworthy operations like deletions and rule changes."""
        interesting_ops = [
            "Create",
            "HardDelete",
            "Move",
            "MoveToDeletedItems",
            "New-InboxRule",
            "Send",
            "Set-InboxRule",
            "SoftDelete",
            "UpdateInboxRules",
        ]
        interesting_events = events_df[events_df["Operation"].isin(interesting_ops)]

        if not interesting_events.empty:
            printc("\nNoteworthy Exchange Operations:", "yellow")

            for op, group in interesting_events.groupby("Operation"):
                printc(
                    f"\n  {op} Operations ({len(group)} event{'s' if len(group) != 1 else ''}):",
                    "yellow",
                )

                for user, user_group in group.groupby("UserId"):
                    printc(f"    {user} ", "cyan", end="")
                    print(f"({len(user_group)} event{'s' if len(user_group) > 1 else ''})")

                    # For each operation, show details about affected items
                    for _, row in user_group.iterrows():
                        subject = row.get("ItemSubject", "No subject available")
                        date = cast("datetime", row["CreationDate"]).strftime("%Y-%m-%d")

                        if subject != "No subject available":
                            printc(f"      - {date}: ", "cyan", end="")
                            print(subject)

    def _analyze_folder_access(self, events_df: DataFrame) -> None:
        """Analyze mailbox folder access patterns."""
        folder_access_data = events_df[
            (events_df["Operation"] == "MailItemsAccessed")
            & (events_df["ItemSubject"].str.contains("items in", na=False))
        ].copy()

        if not folder_access_data.empty:
            printc("\nMailbox Folder Access:", "yellow")

            # Extract folder path from subject
            def extract_folder(subject: str) -> str:
                if "items in " in subject:
                    return subject.split("items in ")[1]
                return "Unknown folder"

            # Now we can safely modify the copy
            folder_access_data["Folder"] = folder_access_data["ItemSubject"].apply(extract_folder)
            folder_counts = folder_access_data["Folder"].value_counts()

            for folder, count in folder_counts.items():
                print(f"  {folder}: accessed {count} times")

                # Show users accessing this folder
                folder_users = folder_access_data[folder_access_data["Folder"] == folder][
                    "UserId"
                ].value_counts()
                for user, user_count in folder_users.items():
                    printc(f"    - {user} ", "cyan", end="")
                    print(f"{user_count}")

    def _analyze_email_details(self, events_df: DataFrame, show_details: bool = False) -> None:
        """Analyze and display detailed information about accessed emails."""
        if not show_details:
            return

        # Get filtered email events
        filtered_events = self._filter_significant_email_events(events_df)

        if filtered_events.empty:
            return

        printc("\nDetailed Email Access:", "yellow")

        # Sort events by timestamp
        email_events_sorted = filtered_events.sort_values("CreationDate")

        for _, row in email_events_sorted.iterrows():
            self._print_event_header(row)
            self._process_event_by_operation(row)

    def _filter_significant_email_events(self, events_df: DataFrame) -> DataFrame:
        """Filter out routine mailbox access events and keep only significant ones."""
        email_operations = [
            "MailItemsAccessed",
            "Send",
            "Create",
            "Update",
            "Move",
            "MoveToDeletedItems",
            "SoftDelete",
            "HardDelete",
            "SearchQueryInitiated",
            "New-InboxRule",
            "Set-InboxRule",
            "UpdateInboxRules",
        ]

        # Get all email-related events
        email_events = events_df[events_df["Operation"].isin(email_operations)]

        if email_events.empty:
            self.logger.info("No mail events found.")
            return email_events

        # Apply the filter to remove routine access events
        filtered_events = email_events[~email_events.apply(self._is_routine_access, axis=1)]

        # If we've filtered everything out, let the user know
        if filtered_events.empty and len(email_events) > 0:
            self.logger.info(
                "Found %d email events, but they appear to be routine mailbox access events.",
                len(email_events),
            )
        else:
            self.logger.info(
                "Showing %d significant email events (filtered out %d routine access events)",
                len(filtered_events),
                len(email_events) - len(filtered_events),
            )

        return filtered_events

    def _is_routine_access(self, row: Series) -> bool:
        """Determine if this is a routine mailbox access event that should be filtered."""
        # If it's not MailItemsAccessed, keep it
        if row["Operation"] != "MailItemsAccessed":
            return False

        # Check subject for indicators of routine folder access
        subject = row.get("ItemSubject", "")
        if subject and ("items in" in str(subject) or "item in" in str(subject)):
            return True

        # Check if we have empty or "no subject" items
        items = row.get("ItemDetails", [])

        # If no items, it's likely routine access
        if not items:
            return True

        # Check if all items have no subject
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("Subject", "").strip():
                    return False
            return True

        return False

    def _print_event_header(self, row: Series) -> None:
        """Print the header for an email event."""
        user = str(row["UserId"])
        operation = str(row["Operation"])
        date = cast("datetime", row["CreationDate"]).strftime("%Y-%m-%d %H:%M:%S")
        client_ip = row.get("ClientIP", "Unknown IP")
        client_app = self._extract_client(str(row.get("ClientInfoString", "")))

        printc(f"\n  {date}", "cyan", end=" ")
        printc(f"{user}", "cyan", end=" ")
        print(f"[{client_ip}] [{client_app}]")
        print(f"  Operation: {operation}")

    def _process_event_by_operation(self, row: Series) -> None:
        """Process event details based on operation type."""
        operation = str(row["Operation"])

        mail_operations = {
            "MailItemsAccessed",
            "Send",
            "Create",
            "Update",
            "Move",
            "MoveToDeletedItems",
            "SoftDelete",
            "HardDelete",
        }

        if operation in mail_operations:
            self._process_mail_operation(row)
        elif "InboxRule" in operation:
            self._process_inbox_rule(row)
        elif operation == "SearchQueryInitiated":
            self._process_search_operation(row)

    def _process_mail_operation(self, row: Series) -> None:
        """Process details for mail item operations."""
        operation = str(row["Operation"])
        audit_data = row["AuditData"]

        # Ensure audit_data is a dictionary
        if not isinstance(audit_data, dict):
            print("    Unable to process mail operation: audit data is not properly formatted")
            return

        # For Update operations, extract info directly from the Item field
        if operation == "Update" and "Item" in audit_data:
            self._parse_update_operation(audit_data)

        else:  # Process MailItemsAccessed and other operations
            subject = row.get("ItemSubject", "No subject available")
            items = row.get("ItemDetails", [])

            if items:
                self._display_mail_items(items)
            elif subject and subject != "No subject available" and "items in" not in subject:
                print("    - Subject: ", end="")
                printc(f"{subject}", "green")

    def _parse_update_operation(self, audit_data: dict[str, Any]) -> None:
        item = audit_data.get("Item", {})
        subject = item.get("Subject", "No subject available")
        folder_path = item.get("ParentFolder", {}).get("Path", "")
        attachments = item.get("Attachments", "")

        # Try to extract sender from InternetMessageId or other fields
        message_id = item.get("InternetMessageId", "")
        sender = "Unknown"

        # Try to extract sender from message ID
        if message_id and "@" in message_id:
            try:
                domain_part = message_id.split("@")[1].split(">")[0]
                if domain_part:
                    sender = domain_part
            except (IndexError, AttributeError):
                pass

        # Print subject with color
        print("    - Subject: ", end="")
        printc(f"{subject}", "green")

        # Print sender information if available
        print("      Message ID: ", end="")
        printc(f"{sender}", "cyan")

        if folder_path:  # Print folder path if available
            print("      Folder: ", end="")
            printc(f"{folder_path}", "cyan")

        if attachments:  # If there are attachments, filter and display them
            attachments_list = attachments.split("; ")
            filtered_attachments, image_count = self._parse_attachment_list(attachments_list)

            if filtered_attachments:
                print("      Attachments: ", end="")
                printc(f"{'; '.join(filtered_attachments)}", "green", end="")

                # Print image count in white on the same line
                if image_count > 0:
                    print(f" (+ {image_count} small image file{'s' if image_count > 1 else ''})")
                else:
                    print()  # Just end the line
            elif image_count > 0:
                print(
                    f"      Attachments: {image_count} small image file{'s' if image_count > 1 else ''} only"
                )

    def _parse_attachment_list(self, attachments_list: list[str]) -> tuple[list[str], int]:
        """Filter out small image files commonly found in email signatures."""
        filtered_attachments = []
        image_count = 0

        # Size threshold for small images (30KB)
        small_image_threshold = 500 * 1024

        for att in attachments_list:
            # Skip invalid format
            if not ("(" in att and ")" in att and "b)" in att):
                filtered_attachments.append(att)
                continue

            # Format typically: "filename.ext (12345b)"
            att_name = att.split(" (")[0]
            size_part = att.split(" (")[1].replace("b)", "")

            try:
                # Parse size and check if it's a small image
                size_bytes = int(size_part)

                # Check if it's a small image file (likely a signature or inline image)
                is_image = att_name.startswith("image") and any(
                    ext in att_name.lower() for ext in [".png", ".jpg", ".jpeg", ".gif"]
                )

                # Skip small images
                if is_image and size_bytes < small_image_threshold:
                    image_count += 1
                    continue

                # Format size for display
                if size_bytes < 1024:
                    size_str = f"{size_bytes}B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f}KB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f}MB"

                # Build the attachment string
                attachment_str = f"{att_name} ({size_str})"

                # Add camera emoji for large images
                if is_image and size_bytes >= 1024 * 1024:
                    attachment_str += " 📷"

                filtered_attachments.append(attachment_str)

            except ValueError:
                # If we can't parse the size, just use the original
                filtered_attachments.append(att)

        return filtered_attachments, image_count

    def _display_mail_items(self, items: Sequence[Any]) -> None:
        """Display details for mail items."""
        # Group no-subject items by folder
        folder_groups = {}
        meaningful_items = []

        # Sort items into meaningful ones and folder groups
        self._sort_mail_items(items, meaningful_items, folder_groups)

        # Display meaningful items first
        for item in meaningful_items:
            self._display_single_mail_item(item)

        # Display grouped no-subject items
        for folder, count in folder_groups.items():
            print(f"    - {count} items with no subject in folder: ", end="")
            printc(f"{folder}", "cyan")

    def _sort_mail_items(
        self, items: Sequence[Any], meaningful_items: list[Any], folder_groups: dict[str, int]
    ) -> None:
        """Sort mail items into meaningful ones and folder groups."""
        for item in items:
            subject = item.get("Subject", "No subject available")
            folder = item.get("FolderPath", "Unknown folder")

            if subject == "No subject available":
                folder_groups.setdefault(folder, 0)
                folder_groups[folder] += 1
            else:
                meaningful_items.append(item)

    def _display_single_mail_item(self, item: dict[str, Any]) -> None:
        """Display details for a single mail item."""
        subject = item.get("Subject", "")

        # Extract sender and recipient information
        sender = self._extract_sender_info(item)
        recipient = self._extract_recipient_info(item)
        folder = item.get("FolderPath", "")

        # Print subject
        print("    - Subject: ", end="")
        printc(f"{subject}", "green")

        # Print sender with color highlighting
        if sender != "Unknown":
            print("      From: ", end="")
            printc(f"{sender}", "green")

        # Print recipient with color highlighting
        if recipient != "Unknown":
            print("      To: ", end="")
            printc(f"{recipient}", "green")

        # Print folder with color highlighting
        if folder:
            print("      Folder: ", end="")
            printc(f"{folder}", "cyan")

        # Handle attachments if present
        self._display_attachments_if_present(item)

        print()  # Add separator between items

    def _extract_sender_info(self, item: dict[str, Any]) -> str:
        """Extract sender information from mail item."""
        return (
            item.get("From")
            or item.get("Sender")
            or item.get("SenderName")
            or item.get("SenderAddress")
            or item.get("InternetMessageHeaders", {}).get("From")
            or "Unknown"
        )

    def _extract_recipient_info(self, item: dict[str, Any]) -> str:
        """Extract recipient information from mail item."""
        return (
            item.get("To")
            or item.get("Recipients")
            or item.get("RecipientEmailAddress")
            or item.get("InternetMessageHeaders", {}).get("To")
            or "Unknown"
        )

    def _display_attachments_if_present(self, item: dict[str, Any]) -> None:
        """Display attachment information if present in the mail item."""
        attachments = item.get("Attachments", "")

        if not attachments:
            return

        if isinstance(attachments, str):
            att_list = attachments.split("; ")
            filtered_attachments, image_count = self._parse_attachment_list(att_list)

            if filtered_attachments:
                result = "; ".join(filtered_attachments)
                if image_count > 0:
                    result += f" (+ {image_count} images)"
                return print(f"      Attachments: {result}")
            if image_count > 0:
                print(
                    f"      Attachments: {image_count} small image file{'s' if image_count > 1 else ''} only"
                )

        print(f"      Attachments: {attachments}")

    def _process_inbox_rule(self, row: Series) -> None:
        """Process details for inbox rule operations."""
        audit_data = row["AuditData"]
        if isinstance(audit_data, dict) and "Parameters" in audit_data:
            parameters = audit_data.get("Parameters", [])
            print("    Rule details:")
            for param in parameters:
                if isinstance(param, dict):
                    name = param.get("Name", "")
                    value = param.get("Value", "")
                    print(f"      {name}: {value}")

    def _process_search_operation(self, row: Series) -> None:
        """Process details for search operations."""
        audit_data = row["AuditData"]
        if isinstance(audit_data, dict):
            query = audit_data.get("QueryText", "Unknown query")
            print(f"    Search query: {query}")

            # Show any other relevant search details
            search_type = audit_data.get("SearchType", "")
            if search_type:
                print(f"    Search type: {search_type}")

            mailboxes = audit_data.get("MailboxesSearched", [])
            if mailboxes:
                print(f"    Mailboxes searched: {', '.join(mailboxes)}")

    def _extract_client(self, client_string: str) -> str:
        """Extract client app from ClientInfoString."""
        if not client_string:
            return "Unknown"
        if "Client=OWA" in client_string:
            return "Outlook Web Access"
        if "Client=REST" in client_string:
            return "REST API"
        if "Client=Outlook" in client_string:
            return "Outlook Desktop"
        if "Client=Exchange" in client_string:
            return "Exchange"
        return client_string.split(";", maxsplit=1)[0] if ";" in client_string else client_string

    def generate_exchange_activity_table(self, exchange_events: DataFrame) -> None:
        """Generate a comprehensive table of all Exchange activity with each individual item."""
        if exchange_events.empty:
            self.logger.info("Skipping Exchange; no events present in log data.")
            return

        self.out.print_header("Complete Exchange Activity Log", "blue")

        # Sort events by timestamp
        events_sorted = exchange_events.sort_values("CreationDate")

        # Print the table header
        self._print_exchange_table_header()

        # Process and print each event
        total_items = self._print_all_exchange_events(events_sorted)

        # Print summary information
        self._print_exchange_summary(events_sorted, total_items)

    def _print_exchange_table_header(self) -> None:
        """Print the header row for the Exchange activity table."""
        headers = [
            "Timestamp",
            "User",
            "Operation",
            "Subject",
            "Folder",
            "Message ID",
            "Attachments",
        ]

        # Print headers
        for i, header in enumerate(headers):
            printc(f"{header:<20}", "blue", end="")
            if i < len(headers) - 1:
                print(" | ", end="")
        print()

        # Print separator
        column_widths = [20, 20, 20, 30, 30, 40, 40]
        separator = "-+-".join("-" * width for width in column_widths)
        print(separator)

    def _print_all_exchange_events(self, events_df: DataFrame) -> int:
        """Process and print all Exchange events, returning the total number of individual items."""
        total_items = 0

        for _, row in events_df.iterrows():
            timestamp = cast("datetime", row["CreationDate"]).strftime("%Y-%m-%d %H:%M:%S")
            user = row["UserId"]
            operation = row["Operation"]

            # For MailItemsAccessed with item details, print each item separately
            if operation == "MailItemsAccessed" and row.get("ItemDetails"):
                total_items += self._print_mail_items_accessed(row, timestamp, user, operation)
            else:
                # For other operations, print the single event
                self._print_other_exchange_event(row, timestamp, user, operation)
                total_items += 1

        return total_items

    def _print_mail_items_accessed(
        self, row: Series, timestamp: str, user: str, operation: str
    ) -> int:
        """Print details for a MailItemsAccessed event with multiple items."""
        items = row.get("ItemDetails", [])
        if not items:
            return 0

        item_count = len(items) if isinstance(items, list) else 0

        # Print header for this event
        printc(f"  {timestamp} {user}", "cyan")
        print(f"    {operation} ({item_count} items)")

        # Print details for each item
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                subject = item.get("Subject", "No subject")
                folder = item.get("FolderPath", "Unknown folder")
                print(f"      - {subject} (in {folder})")

        return item_count

    def _print_other_exchange_event(
        self, row: Series, timestamp: str, user: str, operation: str
    ) -> None:
        """Print details for a non-MailItemsAccessed Exchange event."""
        # Get basic info available in the event
        subject = row.get("ItemSubject", "")
        folder = ""
        message_id = ""
        attachments = ""

        # Try to extract additional details from AuditData
        audit_data = row["AuditData"]
        if isinstance(audit_data, dict):
            # Extract details based on the event type
            if "Item" in audit_data and isinstance(audit_data["Item"], dict):
                item = audit_data["Item"]
                if not subject:
                    subject = item.get("Subject", "No subject available")
                folder = item.get("ParentFolder", {}).get("Path", "")
                message_id = item.get("InternetMessageId", "")
                attachments = item.get("Attachments", "")

            # For search operations
            elif operation == "SearchQueryInitiated":
                query = audit_data.get("QueryText", "")
                subject = f"Search: {query[:50]}..." if len(query) > 50 else f"Search: {query}"
                mailboxes = audit_data.get("MailboxesSearched", [])
                if mailboxes:
                    folder = f"Mailboxes: {', '.join(mailboxes)}"

            # For rule operations
            elif "InboxRule" in operation:
                subject = self._extract_rule_details(audit_data)

        # For folder access events
        if subject and "items in " in subject:
            folder = subject.split("items in ")[1]
            subject = f"{subject.split(' items in ')[0]} items"

        # Print the row
        self._print_table_row(timestamp, user, operation, subject, folder, message_id, attachments)

    def _extract_rule_details(self, audit_data: dict[str, Any]) -> str:
        """Extract and format details for inbox rule operations."""
        subject = "Inbox Rule Configuration"

        if "Parameters" in audit_data:
            parameters = audit_data.get("Parameters", [])
            param_details = []

            for param in parameters:
                if isinstance(param, dict):
                    name = param.get("Name", "")
                    value = param.get("Value", "")
                    if name and value:
                        param_details.append(f"{name}: {value}")

            if param_details:
                subject += (
                    f" ({'; '.join(param_details[:2])}...)"
                    if len(param_details) > 2
                    else f" ({'; '.join(param_details)})"
                )

        return subject

    def _print_table_row(
        self,
        timestamp: str,
        user: str,
        operation: str,
        subject: str,
        folder: str,
        message_id: str,
        attachments: Any,
    ) -> None:
        """Print a single row of the Exchange activity table."""
        # Format the attachments field
        formatted_attachments = self._format_attachments_for_display(attachments)

        # Truncate fields if needed
        subject = subject[:30] + "..." if len(subject) > 30 else subject
        folder = folder[:30] + "..." if len(folder) > 30 else folder
        message_id = message_id[:40] + "..." if len(message_id) > 40 else message_id

        # Print each field with appropriate color
        printc(f"{timestamp:<20}", "cyan", end=" | ")
        printc(f"{user:<20}", "cyan", end=" | ")
        printc(f"{operation:<20}", "yellow", end=" | ")
        print(f"{subject:<30}", end=" | ")
        print(f"{folder:<30}", end=" | ")
        print(f"{message_id:<40}", end=" | ")
        print(f"{formatted_attachments:<40}")

    def _format_attachments_for_display(self, attachments: Any) -> str:
        """Format attachment information for display in the table."""
        if not attachments:
            return ""

        if isinstance(attachments, str):
            att_list = attachments.split("; ")
            filtered_attachments, image_count = self._parse_attachment_list(att_list)

            if filtered_attachments:
                result = "; ".join(filtered_attachments)
                if image_count > 0:
                    result += f" (+ {image_count} images)"
                return result[:40] + "..." if len(result) > 40 else result
            if image_count > 0:
                return f"{image_count} images only"

        return str(attachments)[:40] + "..." if len(str(attachments)) > 40 else str(attachments)

    def _print_exchange_summary(self, events_df: DataFrame, total_items: int) -> None:
        """Print summary information about the Exchange events."""
        print(f"\nTotal Exchange events: {len(events_df)}")
        print(f"Total individual items: {total_items}")
        print(
            f"Date range: {events_df['CreationDate'].min().strftime('%Y-%m-%d')} to "
            f"{events_df['CreationDate'].max().strftime('%Y-%m-%d')}"
        )

        # Print operation counts
        op_counts = events_df["Operation"].value_counts()
        print("\nOperation counts:")
        for op, count in op_counts.items():
            print(f"  {op}: {count}")

    def generate_exchange_activity_csv(self, exchange_events: DataFrame, output_file: str) -> None:
        """Generate a comprehensive CSV file of all Exchange activity with full details."""
        if exchange_events.empty:
            self.logger.info("Skipping Exchange; no events present in log data.")
            return

        # Sort events by timestamp
        events_sorted = exchange_events.sort_values("CreationDate")

        # Prepare data for CSV
        csv_data = []
        previous_message_id = None

        # Process each event
        for _, row in events_sorted.iterrows():
            timestamp = cast("datetime", row["CreationDate"]).strftime("%Y-%m-%d %H:%M:%S")
            user = row["UserId"]
            operation = row["Operation"]

            # For MailItemsAccessed with item details, include each item separately
            if operation == "MailItemsAccessed" and row.get("ItemDetails"):
                items = row.get("ItemDetails", [])
                if not isinstance(items, list):
                    items = []

                for item in items:
                    if isinstance(item, dict):
                        csv_row = {
                            "Timestamp": timestamp,
                            "User": str(user),
                            "Operation": str(operation),
                            "Subject": item.get("Subject", "No subject"),
                            "Folder": item.get("FolderPath", "Unknown folder"),
                            "ClientIP": str(row.get("ClientIP", "")),
                            "ClientApp": self._extract_client(str(row.get("ClientInfoString", ""))),
                        }
                        csv_data.append(csv_row)
            else:
                # For other operations, include the single event
                csv_row = self._prepare_other_event_csv_row(timestamp, user, operation, row)

                # Skip if this is an immediate duplicate by Message ID
                current_message_id = csv_row["Message ID"]
                if current_message_id and current_message_id == previous_message_id:
                    continue

                csv_data.append(csv_row)
                previous_message_id = current_message_id

        # Define CSV headers
        headers = [
            "Timestamp",
            "User",
            "Operation",
            "Subject",
            "Folder",
            "Message ID",
            "Attachments",
            "Client IP",
            "Client Info",
        ]

        # Write to CSV
        try:
            with Path(output_file).open("w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                writer.writerows(csv_data)

            self.logger.info("Exchange activity data exported to %s", output_file)
            self.logger.info("Total records: %d", len(csv_data))

        except Exception as e:
            self.logger.error("Failed to write CSV file: %s", str(e))

    def _prepare_other_event_csv_row(
        self, timestamp: str, user: str, operation: str, row: Series
    ) -> dict[str, str]:
        """Prepare a CSV row for a non-MailItemsAccessed event."""
        # Initialize the row with default values
        csv_row = {
            "Timestamp": timestamp,
            "User": user,
            "Operation": operation,
            "Subject": row.get("ItemSubject", ""),
            "Folder": "",
            "Message ID": "",
            "Attachments": "",
            "Client IP": row.get("ClientIP", ""),
            "Client Info": row.get("ClientInfoString", ""),
        }

        # Extract additional details from AuditData
        audit_data = row["AuditData"]
        if not isinstance(audit_data, dict):
            return csv_row

        # Update client info if available in audit data
        csv_row["Client IP"] = audit_data.get("ClientIPAddress", csv_row["Client IP"])
        csv_row["Client Info"] = audit_data.get("ClientInfoString", csv_row["Client Info"])

        # Handle different operation types
        if "Item" in audit_data and isinstance(audit_data["Item"], dict):
            self._extract_item_details_for_csv(audit_data["Item"], csv_row)
        elif operation == "SearchQueryInitiated":
            self._extract_search_details(audit_data, csv_row)
        elif "InboxRule" in operation:
            self._extract_rule_details_for_csv(audit_data, csv_row)

        # Process folder access events
        if "items in " in csv_row["Subject"]:
            parts = csv_row["Subject"].split(" items in ")
            csv_row["Subject"] = f"{parts[0]} items"
            csv_row["Folder"] = parts[1] if len(parts) > 1 else ""

        return csv_row

    def _extract_item_details_for_csv(self, item: dict[str, Any], csv_row: dict[str, str]) -> None:
        """Extract details from an item object and update the CSV row."""
        if not csv_row["Subject"]:
            csv_row["Subject"] = item.get("Subject", "No subject available")

        # Get folder path
        parent_folder = item.get("ParentFolder", {})
        if isinstance(parent_folder, dict):
            csv_row["Folder"] = parent_folder.get("Path", "")

        # Get message ID and attachments
        csv_row["Message ID"] = item.get("InternetMessageId", "")
        csv_row["Attachments"] = item.get("Attachments", "")

    def _extract_search_details(self, audit_data: dict[str, Any], csv_row: dict[str, str]) -> None:
        """Extract details from a search operation and update the CSV row."""
        query = audit_data.get("QueryText", "")
        csv_row["Subject"] = f"Search: {query}"

        # Add mailboxes if available
        mailboxes = audit_data.get("MailboxesSearched", [])
        if mailboxes:
            csv_row["Folder"] = f"Mailboxes: {', '.join(mailboxes)}"

    def _extract_rule_details_for_csv(
        self, audit_data: dict[str, Any], csv_row: dict[str, str]
    ) -> None:
        """Extract details from a rule operation and update the CSV row."""
        csv_row["Subject"] = "Inbox Rule Configuration"

        if "Parameters" not in audit_data:
            return

        parameters = audit_data.get("Parameters", [])
        param_details = []

        for param in parameters:
            if isinstance(param, dict):
                name = param.get("Name", "")
                value = param.get("Value", "")
                if name and value:
                    param_details.append(f"{name}: {value}")

        if param_details:
            csv_row["Subject"] += f" ({'; '.join(param_details)})"

    def _prepare_mail_item_csv_row(
        self, timestamp: str, user: str, operation: str, row: Series
    ) -> list[dict[str, str]]:
        """Prepare CSV rows for a MailItemsAccessed event with multiple items."""
        rows = []
        items = row.get("ItemDetails", [])

        if not isinstance(items, list):
            items = []

        for item in items:
            if isinstance(item, dict):
                csv_row = {
                    "Timestamp": timestamp,
                    "User": str(user),
                    "Operation": str(operation),
                    "Subject": item.get("Subject", "No subject"),
                    "Folder": item.get("FolderPath", "Unknown folder"),
                    "ClientIP": str(row.get("ClientIP", "")),
                    "ClientApp": self._extract_client(str(row.get("ClientInfoString", ""))),
                }
                rows.append(csv_row)

        return rows
