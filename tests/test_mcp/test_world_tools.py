"""Tests for MCP World state tools."""

import json
import tempfile
from pathlib import Path

import pytest

from secgen.mcp.state import MCPState
from secgen.mcp.tools import world


@pytest.fixture
def state():
    """Create fresh MCPState for each test."""
    return MCPState()


class TestCreateWorld:
    """Tests for create_world tool."""

    @pytest.mark.asyncio
    async def test_create_world_default_params(self, state):
        """Test creating world with default parameters."""
        result = await world.handle_tool("create_world", {}, state)

        data = json.loads(result)
        assert data["success"] is True
        assert state.world is not None
        assert state.world_source == "ephemeral"

    @pytest.mark.asyncio
    async def test_create_world_custom_params(self, state):
        """Test creating world with custom host/user counts."""
        result = await world.handle_tool(
            "create_world",
            {"num_hosts": 25, "num_users": 50},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True
        # World.populate() generates approximate counts
        assert len(state.world.hosts) > 0
        assert len(state.world.users) > 0

    @pytest.mark.asyncio
    async def test_create_world_requires_reset_if_exists(self, state):
        """Test that creating world fails if one exists without reset flag."""
        # First create
        await world.handle_tool("create_world", {}, state)

        # Second create without reset
        result = await world.handle_tool("create_world", {}, state)

        data = json.loads(result)
        assert data["success"] is False
        assert "reset" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_create_world_with_reset(self, state):
        """Test creating world with reset flag replaces existing."""
        # First create with 10 hosts
        await world.handle_tool("create_world", {"num_hosts": 10}, state)
        first_host_count = len(state.world.hosts)

        # Second create with reset and 20 hosts
        result = await world.handle_tool(
            "create_world",
            {"num_hosts": 20, "reset": True},
            state,
        )

        data = json.loads(result)
        assert data["success"] is True
        assert len(state.world.hosts) == 20
        assert len(state.world.hosts) != first_host_count

    @pytest.mark.asyncio
    async def test_create_world_invalid_num_hosts(self, state):
        """Test creating world with invalid num_hosts."""
        result = await world.handle_tool(
            "create_world",
            {"num_hosts": 5000},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "num_hosts" in data["error"].lower()


class TestGetWorldInfo:
    """Tests for get_world_info tool."""

    @pytest.mark.asyncio
    async def test_get_world_info_no_world(self, state):
        """Test getting world info when no world exists."""
        result = await world.handle_tool("get_world_info", {}, state)

        data = json.loads(result)
        assert data["success"] is False
        assert "no world" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_get_world_info_with_world(self, state):
        """Test getting world info when world exists."""
        # Create world first
        await world.handle_tool("create_world", {"num_hosts": 5, "num_users": 10}, state)

        result = await world.handle_tool("get_world_info", {}, state)

        data = json.loads(result)
        assert data["success"] is True
        assert "world_state" in data
        assert data["world_state"]["source"] == "ephemeral"


class TestSaveWorld:
    """Tests for save_world tool."""

    @pytest.mark.asyncio
    async def test_save_world_success(self, state):
        """Test saving world to file."""
        # Create world first
        await world.handle_tool("create_world", {"num_hosts": 3, "num_users": 6}, state)

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            result = await world.handle_tool(
                "save_world",
                {"file_path": temp_path},
                state,
            )

            data = json.loads(result)
            assert data["success"] is True
            assert data["saved"] is True

            # Verify file exists
            assert Path(temp_path).exists()

        finally:
            Path(temp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_save_world_no_world(self, state):
        """Test saving world when no world exists."""
        result = await world.handle_tool(
            "save_world",
            {"file_path": "test.json"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "no world" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_save_world_missing_path(self, state):
        """Test saving world without file path."""
        await world.handle_tool("create_world", {}, state)

        result = await world.handle_tool("save_world", {}, state)

        data = json.loads(result)
        assert data["success"] is False
        assert "file_path" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_save_world_path_traversal_blocked(self, state):
        """Test that path traversal attempts are blocked."""
        await world.handle_tool("create_world", {}, state)

        result = await world.handle_tool(
            "save_world",
            {"file_path": "../../../etc/passwd.json"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "traversal" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_save_world_non_json_blocked(self, state):
        """Test that non-JSON files are blocked."""
        await world.handle_tool("create_world", {}, state)

        result = await world.handle_tool(
            "save_world",
            {"file_path": "test.txt"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert ".json" in data["error"].lower()


class TestLoadWorld:
    """Tests for load_world tool."""

    @pytest.mark.asyncio
    async def test_load_world_success(self, state):
        """Test loading world from file."""
        # Create and save world first
        await world.handle_tool("create_world", {"num_hosts": 4, "num_users": 8}, state)
        original_host_count = len(state.world.hosts)
        original_user_count = len(state.world.users)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            await world.handle_tool(
                "save_world",
                {"file_path": temp_path},
                state,
            )

            # Create new state and load
            new_state = MCPState()
            result = await world.handle_tool(
                "load_world",
                {"file_path": temp_path},
                new_state,
            )

            data = json.loads(result)
            assert data["success"] is True
            assert new_state.world is not None
            assert new_state.world_source == "file"
            # Verify it matches what was saved
            assert len(new_state.world.hosts) == original_host_count
            assert len(new_state.world.users) == original_user_count

        finally:
            Path(temp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_load_world_file_not_found(self, state):
        """Test loading world from non-existent file."""
        result = await world.handle_tool(
            "load_world",
            {"file_path": "nonexistent_world.json"},
            state,
        )

        data = json.loads(result)
        assert data["success"] is False
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_load_world_missing_path(self, state):
        """Test loading world without file path."""
        result = await world.handle_tool("load_world", {}, state)

        data = json.loads(result)
        assert data["success"] is False
        assert "file_path" in data["error"].lower()


class TestUnknownTool:
    """Tests for unknown tool handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self, state):
        """Test that unknown tool name returns error."""
        result = await world.handle_tool("unknown_world_tool", {}, state)

        data = json.loads(result)
        assert data["success"] is False
        assert "unknown" in data["error"].lower()
