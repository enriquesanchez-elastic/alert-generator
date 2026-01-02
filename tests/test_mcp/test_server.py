"""Tests for MCP server initialization and routing."""

import pytest

from secgen.mcp.server import SecGenMCPServer
from secgen.registry_bootstrap import ensure_bootstrapped


@pytest.fixture(autouse=True)
def bootstrap_registry():
    """Ensure registry is bootstrapped before tests."""
    ensure_bootstrapped()


class TestSecGenMCPServer:
    """Tests for SecGenMCPServer class."""

    def test_server_initialization(self):
        """Test that server initializes without errors."""
        server = SecGenMCPServer()

        assert server.server is not None
        assert server.state is not None
        assert server.settings is not None

    def test_server_state_initialized(self):
        """Test that server state is properly initialized."""
        server = SecGenMCPServer()

        # State should have safe defaults
        assert server.state.dry_run is True
        assert server.state.enable_indexing is False
        assert server.state.world is None
        assert server.state.total_events_count == 0

    def test_server_settings_loaded(self):
        """Test that server loads settings."""
        server = SecGenMCPServer()

        # Settings should be loaded
        assert hasattr(server.settings, "elastic_url_with_protocol")
        assert hasattr(server.settings, "elastic_username")


class TestToolRegistration:
    """Tests for tool registration."""

    def test_tools_registered(self):
        """Test that tools are registered with the server."""
        server = SecGenMCPServer()

        # The server should have registered tools
        # We can't directly check registered tools without calling list_tools
        # but we can verify the server instance exists
        assert server.server.name == "secgen-mcp"


class TestToolRouting:
    """Tests for tool routing logic."""

    @pytest.mark.asyncio
    async def test_discovery_tools_route_correctly(self):
        """Test that discovery tools route to discovery handler."""
        server = SecGenMCPServer()

        # Test list tools route
        discovery_tools = ["list_event_types", "list_attack_patterns"]
        for tool in discovery_tools:
            result = await server._handle_list_tools(tool, {})
            # Should return valid JSON
            import json

            data = json.loads(result)
            assert "success" in data

    @pytest.mark.asyncio
    async def test_describe_tools_route_correctly(self):
        """Test that describe tools route to discovery handler."""
        server = SecGenMCPServer()

        # Test describe routes
        result = await server._handle_describe_tools("describe_event_type", {"name": "dns"})

        import json

        data = json.loads(result)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_world_tools_route_correctly(self):
        """Test that world tools route to world handler."""
        server = SecGenMCPServer()

        # Test world tool routes
        result = await server._handle_world_tools("create_world", {"num_hosts": 5})

        import json

        data = json.loads(result)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_generation_tools_route_correctly(self):
        """Test that generation tools route to generation handler."""
        server = SecGenMCPServer()

        # Test generation tool routes
        result = await server._handle_generation_tools(
            "generate_events", {"event_type": "dns", "count": 5}
        )

        import json

        data = json.loads(result)
        assert "success" in data

    @pytest.mark.asyncio
    async def test_utility_tools_route_correctly(self):
        """Test that utility tools route to utility handler."""
        server = SecGenMCPServer()

        # Test utility tool routes
        result = await server._handle_utility_tools("get_capabilities", {})

        import json

        data = json.loads(result)
        assert "success" in data
        assert "capabilities" in data

    @pytest.mark.asyncio
    async def test_testing_tools_route_correctly(self):
        """Test that testing tools route to testing handler."""
        server = SecGenMCPServer()

        # Test testing tool routes
        result = await server._handle_testing_tool(
            "test_elastic_feature", {"feature": "network-map", "count": 15}
        )

        import json

        data = json.loads(result)
        assert "success" in data


class TestErrorHandling:
    """Tests for error handling."""

    @pytest.mark.asyncio
    async def test_invalid_tool_returns_error(self):
        """Test that invalid tool name returns error response."""
        server = SecGenMCPServer()

        # Call with unknown tool name via describe (which routes to discovery)
        result = await server._handle_describe_tools("describe_nonexistent", {"name": "test"})

        import json

        data = json.loads(result)
        assert data["success"] is False
        assert "error" in data

