"""Process event generator for creating ECS-compliant process events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.models.scenario import ProcessInfo, Scenario
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.core.world import World
    from secgen.models.entities import Host, User


@register_event_type(
    name="process",
    category=GeneratorCategory.ENDPOINT,
    description="Process execution events for Analyzer visualization and threat detection",
    ecs_fields=[
        "process.name",
        "process.executable",
        "process.entity_id",
        "process.parent.entity_id",
        "process.command_line",
        "process.args",
    ],
    index_pattern="logs-endpoint.events.process-default",
    example_params={"scenario": "Malicious PowerShell", "timestamp_offset": 0},
)
class ProcessEventGenerator:
    """Generator for creating process event documents."""

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize process event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        scenario: Scenario,
        entity_ids: list[str],
        hostname: str,
        agent_id: str,
        timestamp_offset: int = 0,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Generate process events for a variable-depth process hierarchy.

        Args:
            scenario: Attack scenario
            entity_ids: List of entity IDs for each process (from root to leaf)
            hostname: Hostname for the events (ignored if host provided)
            agent_id: Agent ID for the events (ignored if host provided)
            timestamp_offset: Minutes to offset timestamps
            host: Optional Host entity for proper correlation
            user: Optional User entity for proper correlation

        Returns:
            Tuple of (List of process event dictionaries, List of entity IDs used)
            The entity_ids should be passed to AlertGenerator.generate() for
            proper Session View and Analyzer correlation.
        """
        now = (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).isoformat()
        base_timestamp_ms = int(
            (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).timestamp() * 1000
        )

        # Use entity if provided
        if host:
            hostname = host.name
            agent_id = host.agent_id
            host_info = host.to_ecs_dict()
        else:
            host_info = {
                "hostname": hostname,
                "name": hostname,
                "os": {"family": "linux", "name": "Linux", "platform": "linux"},
            }

        events = []
        session_leader_id = entity_ids[0]
        num_processes = len(scenario.processes)

        for i, process_info in enumerate(scenario.processes):
            entity_id = entity_ids[i]

            # Build ancestry (all previous processes in reverse order)
            if i == 0:
                ancestry: list[str] = []
                parent_info = None
            else:
                ancestry = entity_ids[i - 1 :: -1]
                parent_info = scenario.processes[i - 1]

            # Generate hash for this process
            process_hash = self.randomizer.generate_hash("md5")

            # Determine user info - use entity if provided, else scenario
            if user:
                user_id = user.id
                user_name = user.name
            else:
                user_id = "0" if process_info.user == "root" else "1000"
                user_name = process_info.user

            # Base process event structure
            event: dict[str, Any] = {
                "@timestamp": now,
                "agent": host.to_agent_dict() if host else {"type": "endpoint", "id": agent_id},
                "ecs": {"version": "1.4.0"},
                "event": {
                    "kind": "event",
                    "category": ["process"],
                    "type": ["start"],
                    "action": "exec",
                    "id": self.randomizer.generate_uuid(),
                    "sequence": i + 1,
                },
                "process": {
                    "entity_id": entity_id,
                    "pid": 100 + (i * 1000) + random.randint(0, 100),
                    "name": process_info.name,
                    "executable": process_info.executable,
                    "command_line": " ".join(process_info.args),
                    "args": process_info.args,
                    "args_count": len(process_info.args),
                    "working_directory": process_info.working_dir,
                    "start": base_timestamp_ms - ((num_processes - i) * 1000),
                    "uptime": 0,
                    "interactive": True,
                    "user": {
                        "id": user_id,
                        "name": user_name,
                    },
                    "group": {
                        "id": user_id,
                        "name": user_name,
                    },
                    "tty": {"char_device": {"major": 8, "minor": 1}},
                    "hash": {"md5": process_hash},
                    "code_signature": {"status": "trusted", "subject_name": "Microsoft"},
                    "Ext": {"ancestry": ancestry},
                },
                "host": host_info,
                "user": {
                    "id": user_id,
                    "name": user_name,
                },
                "group": {
                    "id": user_id,
                    "name": user_name,
                },
                "data_stream": {
                    "type": "logs",
                    "dataset": "endpoint.events.process",
                    "namespace": "default",
                },
            }

            # Add related fields for correlation
            if user:
                event["related"] = {
                    "user": user.to_related_user(),
                }

            # Session leader info (first process)
            root_process = scenario.processes[0]
            session_leader = self._create_process_leader_info(
                root_process, session_leader_id, base_timestamp_ms, num_processes, user
            )

            event["process"]["session_leader"] = session_leader
            event["process"]["entry_leader"] = {
                **session_leader,
                "start": ["1970-01-01T00:00:00.000Z"],
            }
            event["process"]["group_leader"] = session_leader

            # Add parent info if not the root
            if parent_info:
                event["process"]["parent"] = self._create_parent_info(
                    parent_info,
                    entity_ids[i - 1],
                    base_timestamp_ms,
                    num_processes,
                    i,
                    user,
                )

            events.append(event)

        return events, entity_ids

    def _create_process_leader_info(
        self,
        process_info: ProcessInfo,
        entity_id: str,
        base_timestamp_ms: int,
        num_processes: int,
        user: Optional["User"] = None,
    ) -> dict[str, Any]:
        """Create session leader information."""
        if user:
            user_id = user.id
            user_name = user.name
        else:
            user_id = "0" if process_info.user == "root" else "1000"
            user_name = process_info.user

        return {
            "entity_id": entity_id,
            "name": process_info.name,
            "pid": 100 + random.randint(0, 50),
            "interactive": True,
            "user": {"id": user_id, "name": user_name},
            "group": {"id": user_id, "name": user_name},
            "working_directory": process_info.working_dir,
            "executable": process_info.executable,
            "command_line": " ".join(process_info.args),
            "args": process_info.args,
            "args_count": len(process_info.args),
            "start": base_timestamp_ms - (num_processes * 1000),
            "tty": {"char_device": {"major": 8, "minor": 1}},
        }

    def _create_parent_info(
        self,
        parent_info: ProcessInfo,
        parent_entity_id: str,
        base_timestamp_ms: int,
        num_processes: int,
        current_index: int,
        user: Optional["User"] = None,
    ) -> dict[str, Any]:
        """Create parent process information."""
        if user:
            user_id = user.id
            user_name = user.name
        else:
            user_id = "0" if parent_info.user == "root" else "1000"
            user_name = parent_info.user

        return {
            "entity_id": parent_entity_id,
            "pid": 100 + ((current_index - 1) * 1000) + random.randint(0, 100),
            "user": {
                "id": user_id,
                "name": user_name,
            },
            "group": {
                "id": user_id,
                "name": user_name,
            },
            "interactive": True,
            "name": parent_info.name,
            "executable": parent_info.executable,
            "command_line": " ".join(parent_info.args),
            "args": parent_info.args,
            "args_count": len(parent_info.args),
            "working_directory": parent_info.working_dir,
            "start": base_timestamp_ms - ((num_processes - current_index + 1) * 1000),
            "tty": {"char_device": {"major": 8, "minor": 1}},
        }

    def generate_from_world(
        self,
        scenario: Scenario,
        world: "World",
        host: "Host",
        user: "User",
        timestamp_offset: int = 0,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Generate process events using World state for proper correlation.

        This method spawns processes in the World's process tree, ensuring
        proper entity_id correlation for Timeline and Analyzer views.

        Args:
            scenario: Attack scenario
            world: World state manager
            host: Host entity to spawn processes on
            user: User entity running the processes
            timestamp_offset: Minutes to offset timestamps

        Returns:
            Tuple of (List of process event dictionaries, List of entity IDs)
            The entity_ids should be passed to AlertGenerator.generate() for
            proper Session View and Analyzer correlation.
        """
        # Convert scenario processes to process info dicts
        process_infos = [
            {
                "name": p.name,
                "executable": p.executable,
                "args": p.args,
                "working_dir": p.working_dir,
                "user": user.name,
                "user_id": user.id,
            }
            for p in scenario.processes
        ]

        # Spawn process chain in world
        process_nodes = world.spawn_process_chain(host.id, process_infos, user)

        if not process_nodes:
            # Fallback to legacy generation if world spawn fails
            entity_ids = [self.randomizer.generate_entity_id() for _ in scenario.processes]
            return self.generate(
                scenario, entity_ids, host.name, host.agent_id, timestamp_offset, host, user
            )

        # Generate events from spawned processes
        entity_ids = [node.entity_id for node in process_nodes]
        return self.generate(
            scenario, entity_ids, host.name, host.agent_id, timestamp_offset, host, user
        )
