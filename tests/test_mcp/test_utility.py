"""Tests for MCP utility tools."""

import json
from unittest.mock import MagicMock, patch

import pytest

from secgen.config.settings import Settings
from secgen.mcp.state import MCPState
from secgen.mcp.tools import utility
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
    return mock_settings


class TestValidateElasticsearch:
    """Tests for validate_elasticsearch tool."""

    @pytest.mark.asyncio
    async def test_validate_elasticsearch_success(self, state, settings):
        """Test successful Elasticsearch validation."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cluster_name": "test-cluster",
            "cluster_uuid": "abc123",
            "version": {"number": "8.12.0"},
            "tagline": "You Know, for Search",
        }

        with patch("secgen.mcp.tools.utility.requests.get", return_value=mock_response):
            result = await utility.handle_tool("validate_elasticsearch", {}, state, settings)

        data = json.loads(result)
        assert data["success"] is True
        assert data["connected"] is True
        assert data["cluster"]["cluster_name"] == "test-cluster"
        assert data["cluster"]["version"] == "8.12.0"

    @pytest.mark.asyncio
    async def test_validate_elasticsearch_connection_error(self, state, settings):
        """Test Elasticsearch validation with connection error."""
        import requests

        with patch(
            "secgen.mcp.tools.utility.requests.get",
            side_effect=requests.exceptions.ConnectionError("Connection refused"),
        ):
            result = await utility.handle_tool("validate_elasticsearch", {}, state, settings)

        data = json.loads(result)
        assert data["success"] is True  # Response format success
        assert data["connected"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_validate_elasticsearch_auth_error(self, state, settings):
        """Test Elasticsearch validation with authentication error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Authentication required"

        with patch("secgen.mcp.tools.utility.requests.get", return_value=mock_response):
            result = await utility.handle_tool("validate_elasticsearch", {}, state, settings)

        data = json.loads(result)
        assert data["success"] is True  # Response format success
        assert data["connected"] is False
        assert "401" in data.get("error", "")


class TestGetCapabilities:
    """Tests for get_capabilities tool."""

    @pytest.mark.asyncio
    async def test_get_capabilities_success(self, state):
        """Test getting server capabilities."""
        # Create mock settings
        mock_settings = MagicMock()

        result = await utility.handle_tool("get_capabilities", {}, state, mock_settings)

        data = json.loads(result)
        assert data["success"] is True
        assert "version" in data
        assert "capabilities" in data
        assert data["capabilities"]["event_types"] > 0
        assert data["capabilities"]["attack_patterns"] > 0
        assert len(data["capabilities"]["categories"]) > 0
        assert len(data["capabilities"]["testable_features"]) > 0

    @pytest.mark.asyncio
    async def test_get_capabilities_safety_flags(self, state):
        """Test that capabilities include safety flags."""
        mock_settings = MagicMock()

        result = await utility.handle_tool("get_capabilities", {}, state, mock_settings)

        data = json.loads(result)
        assert data["success"] is True
        assert "safety" in data
        assert data["safety"]["dry_run_default"] is True
        assert data["safety"]["indexing_requires_confirmation"] is True


class TestIndexEvents:
    """Tests for index_events tool."""

    @pytest.mark.asyncio
    async def test_index_events_requires_both_flags(self, state):
        """Test that index_events requires both confirmation flags."""
        mock_settings = MagicMock()

        # Only enable_indexing
        result = await utility.handle_tool(
            "index_events",
            {"enable_indexing": True, "confirm": False},
            state,
            mock_settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "confirmation" in data["error"].lower()

        # Only confirm
        result = await utility.handle_tool(
            "index_events",
            {"enable_indexing": False, "confirm": True},
            state,
            mock_settings,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "confirmation" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_index_events_success_with_both_flags(self, state):
        """Test that index_events enables indexing with both flags."""
        mock_settings = MagicMock()

        # Both flags true
        result = await utility.handle_tool(
            "index_events",
            {"enable_indexing": True, "confirm": True},
            state,
            mock_settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert data["indexing_enabled"] is True
        assert data["dry_run"] is False
        assert state.enable_indexing is True
        assert state.dry_run is False

    @pytest.mark.asyncio
    async def test_index_events_warning_message(self, state):
        """Test that index_events includes warning message."""
        mock_settings = MagicMock()

        result = await utility.handle_tool(
            "index_events",
            {"enable_indexing": True, "confirm": True},
            state,
            mock_settings,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert "warning" in data
        assert "elasticsearch" in data["warning"].lower()


class TestUnknownTool:
    """Tests for unknown tool handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, state):
        """Test that unknown tool name returns error."""
        mock_settings = MagicMock()

        result = await utility.handle_tool("unknown_utility", {}, state, mock_settings)

        data = json.loads(result)
        assert data["success"] is False
        assert "unknown" in data["error"].lower()

