"""Session state management for MCP server."""

from dataclasses import dataclass, field
from typing import Any

from secgen.core.world import World


@dataclass
class MCPState:
    """Session state for MCP server.

    Maintains state across MCP tool calls within a single session:
    - World state for entity correlation
    - Generated events tracking
    - Configuration (dry-run mode, indexing)
    """

    # World state (created lazily on first use)
    world: World | None = None
    world_source: str = "none"  # "none", "ephemeral", "file"
    world_file_path: str | None = None

    # Session configuration
    dry_run: bool = True  # Safe default: no indexing
    enable_indexing: bool = False

    # Session tracking
    events_generated: list[dict[str, Any]] = field(default_factory=list)
    total_events_count: int = 0

    # Event statistics
    events_by_type: dict[str, int] = field(default_factory=dict)
    events_by_dataset: dict[str, int] = field(default_factory=dict)

    def get_or_create_world(
        self,
        num_hosts: int = 10,
        num_users: int = 20,
        reset: bool = False,
    ) -> World:
        """Get existing World or create ephemeral one.

        Args:
            num_hosts: Number of hosts to create
            num_users: Number of users to create
            reset: If True, reset existing World

        Returns:
            World instance
        """
        if self.world is None or reset:
            self.world = World()
            self.world.populate(num_hosts=num_hosts, num_users=num_users)
            self.world_source = "ephemeral"
            self.world_file_path = None
        return self.world

    def reset_world(self) -> None:
        """Clear World state."""
        self.world = None
        self.world_source = "none"
        self.world_file_path = None

    def load_world_from_file(self, file_path: str) -> World:
        """Load World state from file.

        Args:
            file_path: Path to World state JSON file

        Returns:
            Loaded World instance
        """
        self.world = World.load(file_path)
        self.world_source = "file"
        self.world_file_path = file_path
        return self.world

    def save_world_to_file(self, file_path: str) -> None:
        """Save World state to file.

        Args:
            file_path: Path to save World state JSON

        Raises:
            ValueError: If no World state exists
        """
        if self.world is None:
            raise ValueError("No World state to save")

        self.world.save(file_path)
        self.world_file_path = file_path
        if self.world_source == "ephemeral":
            self.world_source = "file"

    def add_events(self, events: list[dict[str, Any]]) -> None:
        """Track generated events.

        Args:
            events: List of generated event dictionaries
        """
        self.events_generated.extend(events)
        self.total_events_count += len(events)

        # Update statistics
        for event in events:
            # Track by dataset
            dataset = event.get("data_stream", {}).get("dataset", "unknown")
            self.events_by_dataset[dataset] = self.events_by_dataset.get(dataset, 0) + 1

            # Track by event kind
            event_kind = event.get("event", {}).get("kind", "unknown")
            self.events_by_type[event_kind] = self.events_by_type.get(event_kind, 0) + 1

    def get_session_summary(self) -> dict[str, Any]:
        """Get session statistics summary.

        Returns:
            Dictionary with session statistics
        """
        world_summary = None
        if self.world is not None:
            world_summary = self.world.summary()

        return {
            "total_events_generated": self.total_events_count,
            "events_by_dataset": dict(self.events_by_dataset),
            "events_by_type": dict(self.events_by_type),
            "world_state": {
                "source": self.world_source,
                "file_path": self.world_file_path,
                "summary": world_summary,
            },
            "configuration": {
                "dry_run": self.dry_run,
                "indexing_enabled": self.enable_indexing,
            },
        }

    def clear_events(self) -> None:
        """Clear tracked events (keep World state)."""
        self.events_generated.clear()
        self.total_events_count = 0
        self.events_by_type.clear()
        self.events_by_dataset.clear()

    def reset_session(self) -> None:
        """Reset entire session state."""
        self.reset_world()
        self.clear_events()
        self.dry_run = True
        self.enable_indexing = False
