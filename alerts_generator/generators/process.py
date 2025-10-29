"""Process event generator for creating ECS-compliant process events."""

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from alerts_generator.generators.randomizers import RandomDataGenerator
from alerts_generator.models.scenario import ProcessInfo, Scenario


class ProcessEventGenerator:
    """Generator for creating process event documents."""

    def __init__(self, randomizer: Optional[RandomDataGenerator] = None) -> None:
        """
        Initialize process event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        scenario: Scenario,
        entity_ids: List[str],
        hostname: str,
        agent_id: str,
        timestamp_offset: int = 0,
    ) -> List[Dict[str, any]]:
        """
        Generate process events for a variable-depth process hierarchy.

        Args:
            scenario: Attack scenario
            entity_ids: List of entity IDs for each process (from root to leaf)
            hostname: Hostname for the events
            agent_id: Agent ID for the events
            timestamp_offset: Minutes to offset timestamps

        Returns:
            List of process event dictionaries
        """
        now = (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).isoformat()
        base_timestamp_ms = int(
            (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).timestamp() * 1000
        )

        events = []
        session_leader_id = entity_ids[0]
        num_processes = len(scenario.processes)

        for i, process_info in enumerate(scenario.processes):
            entity_id = entity_ids[i]

            # Build ancestry (all previous processes in reverse order)
            if i == 0:
                ancestry: List[str] = []
                parent_info = None
            else:
                ancestry = entity_ids[i - 1 :: -1]
                parent_info = scenario.processes[i - 1]

            # Generate hash for this process
            process_hash = self.randomizer.generate_hash("md5")

            # Base process event structure
            event: Dict[str, any] = {
                "@timestamp": now,
                "agent": {"type": "endpoint", "id": agent_id},
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
                        "id": "0" if process_info.user == "root" else "1000",
                        "name": process_info.user,
                    },
                    "group": {
                        "id": "0" if process_info.user == "root" else "1000",
                        "name": process_info.user,
                    },
                    "tty": {"char_device": {"major": 8, "minor": 1}},
                    "hash": {"md5": process_hash},
                    "code_signature": {"status": "trusted", "subject_name": "Microsoft"},
                    "Ext": {"ancestry": ancestry},
                },
                "host": {
                    "hostname": hostname,
                    "name": hostname,
                    "os": {"family": "linux", "name": "Linux", "platform": "linux"},
                },
                "user": {
                    "id": "0" if process_info.user == "root" else "1000",
                    "name": process_info.user,
                },
                "group": {
                    "id": "0" if process_info.user == "root" else "1000",
                    "name": process_info.user,
                },
                "data_stream": {
                    "type": "logs",
                    "dataset": "endpoint.events.process",
                    "namespace": "default",
                },
            }

            # Session leader info (first process)
            root_process = scenario.processes[0]
            session_leader = self._create_process_leader_info(
                root_process, session_leader_id, base_timestamp_ms, num_processes
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
                )

            events.append(event)

        return events

    def _create_process_leader_info(
        self,
        process_info: ProcessInfo,
        entity_id: str,
        base_timestamp_ms: int,
        num_processes: int,
    ) -> Dict[str, any]:
        """Create session leader information."""
        return {
            "entity_id": entity_id,
            "name": process_info.name,
            "pid": 100 + random.randint(0, 50),
            "interactive": True,
            "user": {"id": "0", "name": process_info.user},
            "group": {"id": "0", "name": process_info.user},
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
    ) -> Dict[str, any]:
        """Create parent process information."""
        return {
            "entity_id": parent_entity_id,
            "pid": 100 + ((current_index - 1) * 1000) + random.randint(0, 100),
            "user": {
                "id": "0" if parent_info.user == "root" else "1000",
                "name": parent_info.user,
            },
            "group": {
                "id": "0" if parent_info.user == "root" else "1000",
                "name": parent_info.user,
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
