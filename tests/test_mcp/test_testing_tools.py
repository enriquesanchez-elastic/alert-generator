"""Tests for MCP testing tools."""

import json
from unittest.mock import MagicMock

import pytest

from secgen.config.settings import Settings
from secgen.features.definitions import FEATURE_TESTS
from secgen.mcp.state import MCPState
from secgen.mcp.tools import testing
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


class TestTestElasticFeature:
    """Tests for test_elastic_feature tool."""

    @pytest.mark.asyncio
    async def test_feature_test_network_map(self, state, settings):
        """Test network-map feature test."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 20},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["feature"]["name"] == "network-map"
        assert data["generation"]["total_events"] > 0

    @pytest.mark.asyncio
    async def test_feature_test_timeline(self, state, settings):
        """Test timeline feature test."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "timeline", "count": 30},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["feature"]["name"] == "timeline"

    @pytest.mark.asyncio
    async def test_feature_test_entity_analytics(self, state, settings):
        """Test entity-analytics feature test."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "entity-analytics", "count": 25},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["feature"]["name"] == "entity-analytics"

    @pytest.mark.asyncio
    async def test_feature_test_missing_feature(self, state, settings):
        """Test feature test without feature name."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "feature" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_feature_test_invalid_feature(self, state, settings):
        """Test feature test with invalid feature name."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "nonexistent-feature"},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_feature_test_default_count(self, state, settings):
        """Test feature test uses default count from definition."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map"},  # No count specified
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        # Default count for network-map is 200
        assert data["generation"]["total_events"] > 0

    @pytest.mark.asyncio
    async def test_feature_test_invalid_count(self, state, settings):
        """Test feature test with invalid count."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 50000},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "count" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_feature_test_includes_verification_steps(self, state, settings):
        """Test that feature test includes verification steps."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 15},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "verification" in data
        assert "steps" in data["verification"]
        assert len(data["verification"]["steps"]) > 0

    @pytest.mark.asyncio
    async def test_feature_test_includes_kibana_url(self, state, settings):
        """Test that feature test includes Kibana URL."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 15},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "kibana_url" in data["feature"]
        assert "localhost:5601" in data["feature"]["kibana_url"]

    @pytest.mark.asyncio
    async def test_feature_test_includes_correlation_ids(self, state, settings):
        """Test that feature test includes correlation IDs."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "timeline", "count": 20},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "correlation_ids" in data["verification"]

    @pytest.mark.asyncio
    async def test_feature_test_creates_world(self, state, settings):
        """Test that feature test creates World state."""
        result = await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 15},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert state.world is not None
        assert "world_summary" in data

    @pytest.mark.asyncio
    async def test_feature_test_tracks_events(self, state, settings):
        """Test that feature test tracks events in state."""
        await testing.handle_tool(
            "test_elastic_feature",
            {"feature": "network-map", "count": 20},
            state,
            settings,
        )

        assert state.total_events_count > 0
        assert len(state.events_generated) > 0

    @pytest.mark.asyncio
    async def test_all_defined_features_work(self, state, settings):
        """Test that all defined features can be tested."""
        for feature_name in FEATURE_TESTS.keys():
            # Reset state for each feature
            state.reset_session()

            result = await testing.handle_tool(
                "test_elastic_feature",
                {"feature": feature_name, "count": 15},
                state,
                settings,
            )

            data = json.loads(result)
            # Some features may not have all generators available
            # but the tool should not crash
            assert data["success"] is True, f"Feature {feature_name} failed: {data}"


class TestUnknownTool:
    """Tests for unknown tool handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, state, settings):
        """Test that unknown tool name returns error."""
        result = await testing.handle_tool(
            "unknown_testing_tool",
            {},
            state,
            settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "unknown" in data["error"].lower()


