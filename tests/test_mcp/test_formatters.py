"""Tests for MCP response formatters."""

import json

from secgen.mcp import formatters


class TestFormatSuccessResponse:
    """Tests for format_success_response function."""

    def test_basic_success_response(self):
        """Test basic success response formatting."""
        result = formatters.format_success_response({"key": "value"})

        data = json.loads(result)
        assert data["success"] is True
        assert data["key"] == "value"

    def test_success_response_with_metadata(self):
        """Test success response with metadata."""
        result = formatters.format_success_response({"key": "value"}, extra_info="test", count=42)

        data = json.loads(result)
        assert data["success"] is True
        assert data["metadata"]["extra_info"] == "test"
        assert data["metadata"]["count"] == 42

    def test_success_response_handles_datetime(self):
        """Test that success response handles datetime objects."""
        from datetime import datetime

        result = formatters.format_success_response({"timestamp": datetime(2024, 1, 15, 12, 0, 0)})

        data = json.loads(result)
        assert data["success"] is True
        assert "2024" in data["timestamp"]


class TestFormatErrorResponse:
    """Tests for format_error_response function."""

    def test_basic_error_response(self):
        """Test basic error response formatting."""
        result = formatters.format_error_response(error="Something went wrong", tool="test_tool")

        data = json.loads(result)
        assert data["success"] is False
        assert data["error"] == "Something went wrong"
        assert data["tool"] == "test_tool"

    def test_error_response_with_suggestion(self):
        """Test error response with suggestion."""
        result = formatters.format_error_response(
            error="Missing argument",
            tool="test_tool",
            suggestion="Provide the required argument",
        )

        data = json.loads(result)
        assert data["success"] is False
        assert data["suggestion"] == "Provide the required argument"

    def test_error_response_with_context(self):
        """Test error response with additional context."""
        result = formatters.format_error_response(
            error="Invalid value",
            tool="test_tool",
            received_value="bad",
            expected_type="int",
        )

        data = json.loads(result)
        assert data["success"] is False
        assert data["context"]["received_value"] == "bad"
        assert data["context"]["expected_type"] == "int"


class TestFormatEventTypesList:
    """Tests for format_event_types_list function."""

    def test_format_event_types(self):
        """Test formatting event types list."""
        event_types = [
            {"name": "dns", "category": "network"},
            {"name": "file", "category": "endpoint"},
        ]

        result = formatters.format_event_types_list(event_types)

        data = json.loads(result)
        assert data["success"] is True
        assert data["count"] == 2
        assert len(data["event_types"]) == 2

    def test_format_empty_event_types(self):
        """Test formatting empty event types list."""
        result = formatters.format_event_types_list([])

        data = json.loads(result)
        assert data["success"] is True
        assert data["count"] == 0
        assert len(data["event_types"]) == 0


class TestFormatAttackPatternsList:
    """Tests for format_attack_patterns_list function."""

    def test_format_attack_patterns(self):
        """Test formatting attack patterns list."""
        patterns = [
            {"name": "brute-force", "ttps": ["T1110"]},
            {"name": "c2-beacon", "ttps": ["T1071"]},
        ]

        result = formatters.format_attack_patterns_list(patterns)

        data = json.loads(result)
        assert data["success"] is True
        assert data["count"] == 2
        assert len(data["attack_patterns"]) == 2


class TestFormatGenerationSummary:
    """Tests for format_generation_summary function."""

    def test_format_generation_summary(self):
        """Test formatting generation summary."""
        result = formatters.format_generation_summary(
            event_type="dns",
            count=100,
            events_summary={"total": 100, "by_dataset": {"dns.query": 100}},
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["event_type"] == "dns"
        assert data["events_generated"] == 100

    def test_format_generation_summary_with_world(self):
        """Test formatting generation summary with World state."""
        result = formatters.format_generation_summary(
            event_type="dns",
            count=50,
            events_summary={"total": 50},
            world_summary={"total_hosts": 10, "total_users": 20},
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["world_state"]["total_hosts"] == 10


class TestFormatAttackExecutionSummary:
    """Tests for format_attack_execution_summary function."""

    def test_format_attack_summary(self):
        """Test formatting attack execution summary."""
        result = formatters.format_attack_execution_summary(
            pattern="brute-force",
            iterations=3,
            total_events=150,
            events_by_type={"authentication": 150},
            ttps=["T1110.001", "T1110.003"],
            detection_recommendations=["Monitor failed logins"],
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["attack_pattern"] == "brute-force"
        assert data["iterations"] == 3
        assert data["total_events"] == 150
        assert "T1110.001" in data["mitre_attck"]["ttps"]

    def test_format_attack_summary_mitre_references(self):
        """Test that attack summary includes MITRE references."""
        result = formatters.format_attack_execution_summary(
            pattern="test",
            iterations=1,
            total_events=10,
            events_by_type={},
            ttps=["T1110.001"],
            detection_recommendations=[],
        )

        data = json.loads(result)
        assert "references" in data["mitre_attck"]
        assert "attack.mitre.org" in data["mitre_attck"]["references"][0]


class TestFormatWorldSummary:
    """Tests for format_world_summary function."""

    def test_format_world_summary_ephemeral(self):
        """Test formatting ephemeral World summary."""
        result = formatters.format_world_summary(
            source="ephemeral",
            summary={"total_hosts": 10, "total_users": 20},
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "ephemeral"
        assert data["total_hosts"] == 10

    def test_format_world_summary_with_file_path(self):
        """Test formatting World summary with file path."""
        result = formatters.format_world_summary(
            source="file",
            summary={"total_hosts": 5},
            file_path="/path/to/world.json",
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "file"
        assert data["file_path"] == "/path/to/world.json"


class TestFormatCapabilitiesResponse:
    """Tests for format_capabilities_response function."""

    def test_format_capabilities(self):
        """Test formatting capabilities response."""
        result = formatters.format_capabilities_response(
            version="2.1.0",
            event_types_count=15,
            attack_patterns_count=10,
            categories=["endpoint", "network", "identity"],
            features=["network-map", "timeline"],
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["version"] == "2.1.0"
        assert data["capabilities"]["event_types"] == 15
        assert data["capabilities"]["attack_patterns"] == 10
        assert "safety" in data
        assert data["safety"]["dry_run_default"] is True


class TestFormatValidationResult:
    """Tests for format_validation_result function."""

    def test_format_successful_validation(self):
        """Test formatting successful validation."""
        result = formatters.format_validation_result(
            connected=True,
            cluster_info={"cluster_name": "test", "version": "8.12.0"},
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["connected"] is True
        assert data["cluster"]["cluster_name"] == "test"

    def test_format_failed_validation(self):
        """Test formatting failed validation."""
        result = formatters.format_validation_result(connected=False, error="Connection refused")

        data = json.loads(result)
        assert data["success"] is True  # Response format success
        assert data["connected"] is False
        assert data["error"] == "Connection refused"


class TestFormatIndexingResult:
    """Tests for format_indexing_result function."""

    def test_format_successful_indexing(self):
        """Test formatting successful indexing result."""
        result = formatters.format_indexing_result(
            indexed=True,
            event_count=100,
            indices=["logs-dns.query-default"],
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["indexed"] is True
        assert data["events_count"] == 100
        assert "logs-dns.query-default" in data["indices"]

    def test_format_failed_indexing(self):
        """Test formatting failed indexing result."""
        result = formatters.format_indexing_result(
            indexed=False, event_count=0, indices=[], error="Authentication failed"
        )

        data = json.loads(result)
        assert data["success"] is True  # Response format success
        assert data["indexed"] is False
        assert data["error"] == "Authentication failed"


