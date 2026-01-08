"""Tests for MCP session state management."""

import tempfile
from pathlib import Path

import pytest

from secgen.mcp.state import MCPState


class TestMCPState:
    """Test MCPState class."""

    def test_initial_state(self):
        """Test initial state is correct."""
        state = MCPState()

        assert state.world is None
        assert state.world_source == "none"
        assert state.world_file_path is None
        assert state.dry_run is True  # Safe default
        assert state.enable_indexing is False
        assert state.total_events_count == 0
        assert len(state.events_generated) == 0
        assert len(state.events_by_type) == 0
        assert len(state.events_by_dataset) == 0

    def test_get_or_create_world_creates_new(self):
        """Test get_or_create_world creates new World."""
        state = MCPState()

        world = state.get_or_create_world(num_hosts=5, num_users=10)

        assert world is not None
        assert state.world is world
        assert state.world_source == "ephemeral"
        # World.populate() generates approximate counts
        assert len(world.hosts) > 0
        assert len(world.users) > 0

    def test_get_or_create_world_returns_existing(self):
        """Test get_or_create_world returns existing World."""
        state = MCPState()

        world1 = state.get_or_create_world(num_hosts=5, num_users=10)
        initial_host_count = len(world1.hosts)
        initial_user_count = len(world1.users)
        world2 = state.get_or_create_world(num_hosts=20, num_users=40)

        # Should return same World instance
        assert world1 is world2
        # Should not change size (existing World not modified)
        assert len(world2.hosts) == initial_host_count
        assert len(world2.users) == initial_user_count

    def test_get_or_create_world_with_reset(self):
        """Test get_or_create_world with reset creates new World."""
        state = MCPState()

        world1 = state.get_or_create_world(num_hosts=5, num_users=10)
        world2 = state.get_or_create_world(num_hosts=20, num_users=40, reset=True)

        # Should be different World instances
        assert world1 is not world2
        # Should have new size (approximate - World.populate() is probabilistic)
        assert len(world2.hosts) > 0
        assert len(world2.users) > 0

    def test_reset_world(self):
        """Test reset_world clears World state."""
        state = MCPState()
        state.get_or_create_world()

        state.reset_world()

        assert state.world is None
        assert state.world_source == "none"
        assert state.world_file_path is None

    def test_save_and_load_world(self):
        """Test save and load World from file."""
        state = MCPState()

        # Create World
        state.get_or_create_world(num_hosts=3, num_users=6)

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            original_host_count = len(state.world.hosts)
            original_user_count = len(state.world.users)

            state.save_world_to_file(temp_path)

            assert state.world_file_path == temp_path
            assert state.world_source == "file"

            # Create new state and load
            state2 = MCPState()
            world2 = state2.load_world_from_file(temp_path)

            assert state2.world is world2
            assert state2.world_source == "file"
            assert state2.world_file_path == temp_path

            # Verify World content matches saved state
            assert len(world2.hosts) == original_host_count
            assert len(world2.users) == original_user_count

        finally:
            # Cleanup
            Path(temp_path).unlink(missing_ok=True)

    def test_save_world_without_world_raises_error(self):
        """Test save_world raises error if no World exists."""
        state = MCPState()

        with pytest.raises(ValueError, match="No World state to save"):
            state.save_world_to_file("test.json")

    def test_add_events_tracking(self):
        """Test add_events tracks events correctly."""
        state = MCPState()

        events = [
            {
                "event": {"kind": "event"},
                "data_stream": {"dataset": "endpoint.events.process"},
            },
            {
                "event": {"kind": "alert"},
                "data_stream": {"dataset": "endpoint.events.file"},
            },
            {
                "event": {"kind": "event"},
                "data_stream": {"dataset": "endpoint.events.process"},
            },
        ]

        state.add_events(events)

        assert state.total_events_count == 3
        assert len(state.events_generated) == 3
        assert state.events_by_type["event"] == 2
        assert state.events_by_type["alert"] == 1
        assert state.events_by_dataset["endpoint.events.process"] == 2
        assert state.events_by_dataset["endpoint.events.file"] == 1

    def test_get_session_summary(self):
        """Test get_session_summary returns correct data."""
        state = MCPState()

        # Create World
        state.get_or_create_world(num_hosts=5, num_users=10)

        # Add events
        events = [
            {
                "event": {"kind": "event"},
                "data_stream": {"dataset": "dns.query"},
            }
        ]
        state.add_events(events)

        summary = state.get_session_summary()

        assert summary["total_events_generated"] == 1
        assert summary["events_by_dataset"]["dns.query"] == 1
        assert summary["world_state"]["source"] == "ephemeral"
        # World.populate() generates approximate counts
        assert summary["world_state"]["summary"]["total_hosts"] > 0
        assert summary["world_state"]["summary"]["total_users"] > 0
        assert summary["configuration"]["dry_run"] is True
        assert summary["configuration"]["indexing_enabled"] is False

    def test_clear_events(self):
        """Test clear_events clears event tracking."""
        state = MCPState()

        events = [
            {
                "event": {"kind": "event"},
                "data_stream": {"dataset": "dns.query"},
            }
        ]
        state.add_events(events)

        state.clear_events()

        assert state.total_events_count == 0
        assert len(state.events_generated) == 0
        assert len(state.events_by_type) == 0
        assert len(state.events_by_dataset) == 0

    def test_reset_session(self):
        """Test reset_session clears everything."""
        state = MCPState()

        # Set up state
        state.get_or_create_world()
        state.add_events([{"event": {"kind": "event"}, "data_stream": {"dataset": "test"}}])
        state.dry_run = False
        state.enable_indexing = True

        state.reset_session()

        # Everything should be reset
        assert state.world is None
        assert state.total_events_count == 0
        assert state.dry_run is True
        assert state.enable_indexing is False
