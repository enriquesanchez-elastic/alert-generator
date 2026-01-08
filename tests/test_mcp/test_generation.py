"""Tests for MCP generation tools."""

import json
from unittest.mock import MagicMock

import pytest

from secgen.config.settings import Settings
from secgen.mcp.state import MCPState
from secgen.mcp.tools import generation
from secgen.registry_bootstrap import ensure_bootstrapped


@pytest.fixture(autouse=True)
def bootstrap_registry():
    """Ensure registry is bootstrapped before tests."""
    ensure_bootstrapped()


@pytest.fixture
def state():
    """Create fresh MCPState for each test."""
    return MCPState()


@pytest.fixture
def settings():
    """Create mock settings for testing."""
    mock_settings = MagicMock(spec=Settings)
    mock_settings.elastic_url_with_protocol = "http://localhost:9200"
    mock_settings.elastic_username = "elastic"
    mock_settings.elastic_password = "changeme"
    mock_settings.kibana_url = "http://localhost:5601"
    return mock_settings


class TestGenerateEvents:
    """Tests for generate_events tool."""

    @pytest.mark.asyncio
    async def test_generate_events_success(self, state, settings):
        """Test generating events successfully."""
        result = await generation.handle_tool(
            "generate_events",
            {"event_type": "dns", "count": 10},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["event_type"] == "dns"
        assert data["events_generated"] == 10
        assert "summary" in data

    @pytest.mark.asyncio
    async def test_generate_events_missing_event_type(self, state, settings):
        """Test generating events without event_type."""
        result = await generation.handle_tool(
            "generate_events",
            {"count": 10},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "event_type" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_generate_events_invalid_event_type(self, state, settings):
        """Test generating events with invalid event type."""
        result = await generation.handle_tool(
            "generate_events",
            {"event_type": "nonexistent", "count": 10},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_generate_events_with_world(self, state, settings):
        """Test generating events with World state."""
        result = await generation.handle_tool(
            "generate_events",
            {"event_type": "dns", "count": 5, "use_world": True},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "world_state" in data
        assert state.world is not None

    @pytest.mark.asyncio
    async def test_generate_events_tracks_in_state(self, state, settings):
        """Test that generated events are tracked in state."""
        await generation.handle_tool(
            "generate_events",
            {"event_type": "dns", "count": 5},
            state,
            settings,
        )

        assert state.total_events_count == 5
        assert len(state.events_generated) == 5

    @pytest.mark.asyncio
    async def test_generate_events_invalid_count(self, state, settings):
        """Test generating events with invalid count."""
        result = await generation.handle_tool(
            "generate_events",
            {"event_type": "dns", "count": 50000},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "count" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_generate_events_dry_run_default(self, state, settings):
        """Test that dry_run is true by default."""
        result = await generation.handle_tool(
            "generate_events",
            {"event_type": "dns", "count": 5},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["summary"]["dry_run"] is True
        assert data["summary"]["indexed"] is False


class TestExecuteAttack:
    """Tests for execute_attack tool."""

    @pytest.mark.asyncio
    async def test_execute_attack_success(self, state, settings):
        """Test executing attack pattern successfully."""
        result = await generation.handle_tool(
            "execute_attack",
            {"pattern": "brute-force", "count": 1},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["attack_pattern"] == "brute-force"
        assert data["iterations"] == 1
        assert "ttps" in data["mitre_attck"]
        assert len(data["mitre_attck"]["ttps"]) > 0

    @pytest.mark.asyncio
    async def test_execute_attack_missing_pattern(self, state, settings):
        """Test executing attack without pattern."""
        result = await generation.handle_tool(
            "execute_attack",
            {"count": 1},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "pattern" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_attack_invalid_pattern(self, state, settings):
        """Test executing attack with invalid pattern."""
        result = await generation.handle_tool(
            "execute_attack",
            {"pattern": "nonexistent-attack"},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_attack_multiple_iterations(self, state, settings):
        """Test executing attack with multiple iterations."""
        result = await generation.handle_tool(
            "execute_attack",
            {"pattern": "brute-force", "count": 2},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["iterations"] == 2
        assert data["total_events"] > 0

    @pytest.mark.asyncio
    async def test_execute_attack_has_detection_recommendations(self, state, settings):
        """Test that attack result includes detection recommendations."""
        result = await generation.handle_tool(
            "execute_attack",
            {"pattern": "brute-force"},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "detection" in data
        assert "recommendations" in data["detection"]


class TestGenerateCampaign:
    """Tests for generate_campaign tool."""

    @pytest.mark.asyncio
    async def test_generate_campaign_success(self, state, settings):
        """Test generating campaign successfully."""
        result = await generation.handle_tool(
            "generate_campaign",
            {"num_hosts": 5, "num_alerts": 10},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "campaign" in data
        assert "generation" in data
        assert data["generation"]["total_events"] > 0

    @pytest.mark.asyncio
    async def test_generate_campaign_default_params(self, state, settings):
        """Test generating campaign with default parameters."""
        result = await generation.handle_tool(
            "generate_campaign",
            {},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_generate_campaign_invalid_num_hosts(self, state, settings):
        """Test generating campaign with invalid num_hosts."""
        result = await generation.handle_tool(
            "generate_campaign",
            {"num_hosts": 500},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "num_hosts" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_generate_campaign_has_phases(self, state, settings):
        """Test that campaign includes phase statistics."""
        result = await generation.handle_tool(
            "generate_campaign",
            {"num_hosts": 5, "num_alerts": 20},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "phases" in data["generation"]

    @pytest.mark.asyncio
    async def test_generate_campaign_creates_world(self, state, settings):
        """Test that campaign creates World state."""
        result = await generation.handle_tool(
            "generate_campaign",
            {"num_hosts": 5},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert state.world is not None
        assert "world_summary" in data


class TestUnknownTool:
    """Tests for unknown tool handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, state, settings):
        """Test that unknown tool name returns error."""
        result = await generation.handle_tool(
            "unknown_generation",
            {},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "unknown" in data["error"].lower()


