"""Tests for MCP discovery tools."""

import json

import pytest

from secgen.mcp.state import MCPState
from secgen.mcp.tools import discovery
from secgen.registry_bootstrap import ensure_bootstrapped


@pytest.fixture(autouse=True)
def bootstrap_registry():
    """Ensure registry is bootstrapped before tests."""
    ensure_bootstrapped()


@pytest.fixture
def state():
    """Create fresh MCPState for each test."""
    return MCPState()


class TestListEventTypes:
    """Tests for list_event_types tool."""

    @pytest.mark.asyncio
    async def test_list_all_event_types(self, state):
        """Test listing all event types without filter."""
        result = await discovery.handle_tool("list_event_types", {}, state)

        data = json.loads(result)
        assert data["success"] is True
        assert "count" in data
        assert "event_types" in data
        assert data["count"] > 0
        assert len(data["event_types"]) == data["count"]

    @pytest.mark.asyncio
    async def test_list_event_types_with_category_filter(self, state):
        """Test listing event types filtered by category."""
        result = await discovery.handle_tool(
            "list_event_types",
            {"category": "network"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True

        # All returned event types should be in 'network' category
        for et in data["event_types"]:
            assert et["category"] == "network"

    @pytest.mark.asyncio
    async def test_list_event_types_invalid_category(self, state):
        """Test listing event types with invalid category returns error."""
        result = await discovery.handle_tool(
            "list_event_types",
            {"category": "invalid_category"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "invalid_category" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_event_type_structure(self, state):
        """Test that event types have expected structure."""
        result = await discovery.handle_tool("list_event_types", {}, state)

        data = json.loads(result)
        assert data["success"] is True

        # Check first event type has expected fields
        et = data["event_types"][0]
        assert "name" in et
        assert "category" in et
        assert "description" in et
        assert "index_pattern" in et


class TestListAttackPatterns:
    """Tests for list_attack_patterns tool."""

    @pytest.mark.asyncio
    async def test_list_all_attack_patterns(self, state):
        """Test listing all attack patterns without filter."""
        result = await discovery.handle_tool("list_attack_patterns", {}, state)

        data = json.loads(result)
        assert data["success"] is True
        assert "count" in data
        assert "attack_patterns" in data
        assert data["count"] > 0

    @pytest.mark.asyncio
    async def test_list_attack_patterns_with_category_filter(self, state):
        """Test listing attack patterns filtered by category."""
        result = await discovery.handle_tool(
            "list_attack_patterns",
            {"category": "identity"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True

        # All returned patterns should be in 'identity' category
        for ap in data["attack_patterns"]:
            assert ap["category"] == "identity"

    @pytest.mark.asyncio
    async def test_list_attack_patterns_with_ttp_filter(self, state):
        """Test listing attack patterns filtered by MITRE TTP."""
        result = await discovery.handle_tool(
            "list_attack_patterns",
            {"ttp": "T1110"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True

        # All returned patterns should have the TTP
        for ap in data["attack_patterns"]:
            ttps = ap.get("ttps", [])
            assert any("T1110" in ttp for ttp in ttps)

    @pytest.mark.asyncio
    async def test_attack_pattern_structure(self, state):
        """Test that attack patterns have expected structure."""
        result = await discovery.handle_tool("list_attack_patterns", {}, state)

        data = json.loads(result)
        assert data["success"] is True

        # Check first attack pattern has expected fields
        ap = data["attack_patterns"][0]
        assert "name" in ap
        assert "category" in ap
        assert "description" in ap
        assert "ttps" in ap
        assert "event_types" in ap


class TestDescribeEventType:
    """Tests for describe_event_type tool."""

    @pytest.mark.asyncio
    async def test_describe_valid_event_type(self, state):
        """Test describing a valid event type."""
        result = await discovery.handle_tool(
            "describe_event_type",
            {"name": "dns"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["name"] == "dns"
        assert "category" in data
        assert "description" in data
        assert "ecs_fields" in data
        assert "index_pattern" in data
        assert "generator_class" in data

    @pytest.mark.asyncio
    async def test_describe_unknown_event_type(self, state):
        """Test describing an unknown event type returns error with suggestions."""
        result = await discovery.handle_tool(
            "describe_event_type",
            {"name": "nonexistent_type"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "not found" in data["error"].lower()
        assert "suggestion" in data

    @pytest.mark.asyncio
    async def test_describe_event_type_missing_name(self, state):
        """Test describing event type without name returns error."""
        result = await discovery.handle_tool(
            "describe_event_type",
            {},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "missing" in data["error"].lower()


class TestDescribeAttackPattern:
    """Tests for describe_attack_pattern tool."""

    @pytest.mark.asyncio
    async def test_describe_valid_attack_pattern(self, state):
        """Test describing a valid attack pattern."""
        result = await discovery.handle_tool(
            "describe_attack_pattern",
            {"name": "brute-force"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["name"] == "brute-force"
        assert "category" in data
        assert "description" in data
        assert "ttps" in data
        assert "mitre_attck_references" in data
        assert "required_params" in data
        assert "detection_recommendations" in data

    @pytest.mark.asyncio
    async def test_describe_unknown_attack_pattern(self, state):
        """Test describing an unknown attack pattern returns error with suggestions."""
        result = await discovery.handle_tool(
            "describe_attack_pattern",
            {"name": "nonexistent_pattern"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "not found" in data["error"].lower()
        assert "suggestion" in data

    @pytest.mark.asyncio
    async def test_describe_attack_pattern_missing_name(self, state):
        """Test describing attack pattern without name returns error."""
        result = await discovery.handle_tool(
            "describe_attack_pattern",
            {},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "missing" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_attack_pattern_has_mitre_references(self, state):
        """Test that attack patterns include MITRE ATT&CK references."""
        result = await discovery.handle_tool(
            "describe_attack_pattern",
            {"name": "brute-force"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True

        # Check MITRE references are URLs
        for ref in data.get("mitre_attck_references", []):
            assert ref.startswith("https://attack.mitre.org/techniques/")


class TestUnknownTool:
    """Tests for unknown tool handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, state):
        """Test that unknown tool name returns error."""
        result = await discovery.handle_tool(
            "unknown_tool",
            {},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data
        assert "unknown" in data["error"].lower()


