"""Output formatter for CLI command results.

Provides consistent, rich output formatting across all CLI commands
without external dependencies (pure Python with simple ANSI codes).
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal formatting."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls) -> None:
        """Disable all colors (for non-TTY output)."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""


@dataclass
class EventStats:
    """Statistics for generated events."""

    total: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_dataset: dict[str, int] = field(default_factory=dict)

    def add_event(self, event: dict[str, Any]) -> None:
        """Add an event to statistics."""
        self.total += 1

        # Count by dataset
        dataset = event.get("data_stream", {}).get("dataset", "unknown")
        self.by_dataset[dataset] = self.by_dataset.get(dataset, 0) + 1

        # Count by event category
        categories = event.get("event", {}).get("category", [])
        if categories:
            cat = categories[0] if isinstance(categories, list) else categories
            self.by_type[cat] = self.by_type.get(cat, 0) + 1


@dataclass
class GenerationSummary:
    """Summary of a generation run."""

    command: str
    duration_seconds: float
    event_stats: EventStats
    time_range_start: str | None = None
    time_range_end: str | None = None
    correlation_ids: dict[str, list[str]] = field(default_factory=dict)
    indices_written: list[str] = field(default_factory=list)
    kibana_base_url: str = "http://localhost:5601"
    attack_pattern: str | None = None
    attack_ttps: list[str] = field(default_factory=list)
    detection_recommendations: list[str] = field(default_factory=list)
    world_summary: dict[str, Any] | None = None

    def add_correlation_id(self, field_name: str, value: str) -> None:
        """Add a correlation ID."""
        if field_name not in self.correlation_ids:
            self.correlation_ids[field_name] = []
        if value not in self.correlation_ids[field_name]:
            self.correlation_ids[field_name].append(value)

    def collect_correlation_ids(self, events: list[dict[str, Any]]) -> None:
        """Collect correlation IDs from events."""
        for event in events:
            # host.id
            host_id = event.get("host", {}).get("id")
            if host_id:
                self.add_correlation_id("host.id", host_id)

            # user.name
            user_name = event.get("user", {}).get("name")
            if user_name:
                self.add_correlation_id("user.name", user_name)

            # process.entity_id
            entity_id = event.get("process", {}).get("entity_id")
            if entity_id:
                self.add_correlation_id("process.entity_id", entity_id)

            # network.community_id
            community_id = event.get("network", {}).get("community_id")
            if community_id:
                self.add_correlation_id("network.community_id", community_id)

            # Collect time range
            timestamp = event.get("@timestamp")
            if timestamp:
                if self.time_range_start is None or timestamp < self.time_range_start:
                    self.time_range_start = timestamp
                if self.time_range_end is None or timestamp > self.time_range_end:
                    self.time_range_end = timestamp


class OutputFormatter:
    """Formatter for CLI output."""

    def __init__(self, use_colors: bool = True, json_output: bool = False) -> None:
        """
        Initialize formatter.

        Args:
            use_colors: Whether to use ANSI colors
            json_output: Whether to output JSON instead of formatted text
        """
        self.use_colors = use_colors
        self.json_output = json_output

        if not use_colors:
            Colors.disable()

    def format_summary(self, summary: GenerationSummary) -> str:
        """
        Format a generation summary for display.

        Args:
            summary: GenerationSummary to format

        Returns:
            Formatted string
        """
        if self.json_output:
            return self._format_summary_json(summary)

        lines = []
        c = Colors

        # Header
        lines.append("")
        lines.append(f"{c.BOLD}{'=' * 70}{c.RESET}")
        lines.append(f"{c.BOLD}GENERATION SUMMARY{c.RESET}")
        lines.append(f"{c.BOLD}{'=' * 70}{c.RESET}")

        # Command info
        lines.append(f"Command: {summary.command}")
        lines.append(f"Duration: {summary.duration_seconds:.2f}s")

        # Events generated
        lines.append("")
        lines.append(f"{c.CYAN}Events Generated:{c.RESET}")
        lines.append(f"  Total: {c.BOLD}{summary.event_stats.total}{c.RESET}")
        for dataset, count in sorted(summary.event_stats.by_dataset.items()):
            lines.append(f"    {dataset}: {count}")

        # Time range
        if summary.time_range_start and summary.time_range_end:
            lines.append("")
            lines.append(f"{c.CYAN}Time Range:{c.RESET}")
            lines.append(f"  Start: {summary.time_range_start}")
            lines.append(f"  End:   {summary.time_range_end}")

        # Correlation IDs
        if summary.correlation_ids:
            lines.append("")
            lines.append(f"{c.CYAN}Correlation IDs:{c.RESET}")
            for field_name, values in summary.correlation_ids.items():
                lines.append(f"  {field_name}: {len(values)} unique")
                for value in values[:5]:
                    lines.append(f"    - {value}")
                if len(values) > 5:
                    lines.append(f"    ... and {len(values) - 5} more")

        # Attack pattern info
        if summary.attack_pattern:
            lines.append("")
            lines.append(f"{c.YELLOW}Attack Pattern:{c.RESET} {summary.attack_pattern}")
            if summary.attack_ttps:
                lines.append(f"  MITRE ATT&CK TTPs: {', '.join(summary.attack_ttps)}")

        # Detection recommendations
        if summary.detection_recommendations:
            lines.append("")
            lines.append(f"{c.YELLOW}Detection Recommendations:{c.RESET}")
            for rec in summary.detection_recommendations:
                lines.append(f"  - {rec}")

        # Indexed indices
        if summary.indices_written:
            lines.append("")
            lines.append(f"{c.GREEN}Indexed to Elasticsearch:{c.RESET}")
            for index in summary.indices_written:
                lines.append(f"  - {index}")

        # Kibana queries
        lines.append("")
        lines.append(f"{c.CYAN}Kibana Queries:{c.RESET}")
        if summary.correlation_ids.get("host.id"):
            host_ids = summary.correlation_ids["host.id"][:5]
            query = "host.id:(" + " OR ".join(host_ids) + ")"
            lines.append(f"  All events: {query}")
        lines.append(f"  Timeline: {summary.kibana_base_url}/app/security/timelines")
        lines.append(f"  Analyzer: {summary.kibana_base_url}/app/security/hosts")

        # Footer
        lines.append("")
        lines.append(f"{c.BOLD}{'=' * 70}{c.RESET}")

        return "\n".join(lines)

    def _format_summary_json(self, summary: GenerationSummary) -> str:
        """Format summary as JSON."""
        data = {
            "command": summary.command,
            "duration_seconds": summary.duration_seconds,
            "events": {
                "total": summary.event_stats.total,
                "by_type": summary.event_stats.by_type,
                "by_dataset": summary.event_stats.by_dataset,
            },
            "time_range": {
                "start": summary.time_range_start,
                "end": summary.time_range_end,
            },
            "correlation_ids": summary.correlation_ids,
            "indices_written": summary.indices_written,
        }
        if summary.attack_pattern:
            data["attack"] = {
                "pattern": summary.attack_pattern,
                "ttps": summary.attack_ttps,
                "detection_recommendations": summary.detection_recommendations,
            }
        return json.dumps(data, indent=2)

    def format_table(
        self,
        headers: list[str],
        rows: list[list[str]],
        title: str | None = None,
    ) -> str:
        """
        Format data as a simple table.

        Args:
            headers: Column headers
            rows: Table rows
            title: Optional table title

        Returns:
            Formatted table string
        """
        if not rows:
            return "No data to display."

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        lines = []
        c = Colors

        if title:
            lines.append(f"\n{c.BOLD}{title}{c.RESET}")
            lines.append("-" * sum(widths) + "-" * (len(widths) * 3))

        # Header row
        header_line = "  ".join(
            f"{c.BOLD}{h:<{widths[i]}}{c.RESET}" for i, h in enumerate(headers)
        )
        lines.append(header_line)
        lines.append("-" * sum(widths) + "-" * (len(widths) * 3))

        # Data rows
        for row in rows:
            row_line = "  ".join(
                f"{str(cell):<{widths[i]}}" for i, cell in enumerate(row) if i < len(widths)
            )
            lines.append(row_line)

        return "\n".join(lines)

    def format_success(self, message: str) -> str:
        """Format a success message."""
        return f"{Colors.GREEN}✓{Colors.RESET} {message}"

    def format_error(self, message: str) -> str:
        """Format an error message."""
        return f"{Colors.RED}✗{Colors.RESET} {message}"

    def format_warning(self, message: str) -> str:
        """Format a warning message."""
        return f"{Colors.YELLOW}!{Colors.RESET} {message}"

    def format_info(self, message: str) -> str:
        """Format an info message."""
        return f"{Colors.CYAN}ℹ{Colors.RESET} {message}"

    @staticmethod
    def build_kibana_discover_link(
        base_url: str,
        index_pattern: str,
        query: str,
        time_from: str = "now-24h",
        time_to: str = "now",
    ) -> str:
        """
        Build a Kibana Discover link.

        Args:
            base_url: Kibana base URL
            index_pattern: Index pattern to search
            query: KQL query string
            time_from: Start time
            time_to: End time

        Returns:
            Kibana Discover URL
        """
        from urllib.parse import quote

        encoded_query = quote(query)
        return (
            f"{base_url}/app/discover#/"
            f"?_g=(time:(from:'{time_from}',to:'{time_to}'))"
            f"&_a=(index:'{index_pattern}',query:(language:kuery,query:'{encoded_query}'))"
        )

    @staticmethod
    def build_kibana_timeline_link(base_url: str) -> str:
        """Build a Kibana Security Timeline link."""
        return f"{base_url}/app/security/timelines"

    @staticmethod
    def build_kibana_analyzer_link(base_url: str, process_entity_id: str) -> str:
        """Build a Kibana Analyzer link for a process."""
        return f"{base_url}/app/security/hosts/events?query=process.entity_id:{process_entity_id}"


