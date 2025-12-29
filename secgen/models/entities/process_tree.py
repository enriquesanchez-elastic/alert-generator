"""Process tree entity model for persistent world state."""

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ProcessNode:
    """
    A single process node in a process tree.

    Represents a process with full ECS field coverage for
    process correlation and lineage tracking.

    Attributes:
        entity_id: Unique process identifier (process.entity_id)
        pid: Process ID
        name: Process name
        executable: Full executable path
        command_line: Complete command line
        args: Arguments as list
        working_directory: Working directory
        user_name: User running the process
        user_id: User ID
        parent_entity_id: Parent process entity_id for lineage
        session_leader_id: Session leader entity_id
        entry_leader_id: Entry leader entity_id (SSH, terminal)
        start_time: Process start timestamp (ms since epoch)
        hash_md5: Executable MD5 hash
        hash_sha256: Executable SHA256 hash
        code_signature_status: Code signature status
        code_signature_subject: Code signer name
        children: Child process nodes
    """

    entity_id: str
    pid: int
    name: str
    executable: str
    command_line: str
    args: list[str]
    working_directory: str
    user_name: str
    user_id: str
    parent_entity_id: str | None = None
    session_leader_id: str | None = None
    entry_leader_id: str | None = None
    start_time: int = field(
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    hash_md5: str | None = None
    hash_sha256: str | None = None
    code_signature_status: str = "trusted"
    code_signature_subject: str = "Microsoft Corporation"
    children: list["ProcessNode"] = field(default_factory=list)

    def add_child(self, child: "ProcessNode") -> None:
        """Add a child process to this node."""
        child.parent_entity_id = self.entity_id
        if self.session_leader_id:
            child.session_leader_id = self.session_leader_id
        if self.entry_leader_id:
            child.entry_leader_id = self.entry_leader_id
        self.children.append(child)

    def get_ancestry(self, tree: "ProcessTree") -> list[str]:
        """
        Get the ancestry chain for this process.

        Args:
            tree: The process tree containing this node

        Returns:
            List of entity_ids from parent to root (process.Ext.ancestry)
        """
        ancestry = []
        current_parent_id = self.parent_entity_id

        while current_parent_id:
            ancestry.append(current_parent_id)
            parent_node = tree.get_process(current_parent_id)
            if parent_node:
                current_parent_id = parent_node.parent_entity_id
            else:
                break

        return ancestry

    def to_ecs_dict(self, ancestry: list[str] | None = None) -> dict[str, Any]:
        """
        Convert to ECS-compatible process fields dictionary.

        Args:
            ancestry: Pre-computed ancestry list

        Returns:
            Dictionary with ECS process.* fields
        """
        result: dict[str, Any] = {
            "entity_id": self.entity_id,
            "pid": self.pid,
            "name": self.name,
            "executable": self.executable,
            "command_line": self.command_line,
            "args": self.args,
            "args_count": len(self.args),
            "working_directory": self.working_directory,
            "start": self.start_time,
            "uptime": 0,
            "interactive": True,
            "user": {
                "id": self.user_id,
                "name": self.user_name,
            },
            "group": {
                "id": self.user_id,
                "name": self.user_name,
            },
            "hash": {},
            "code_signature": {
                "status": self.code_signature_status,
                "subject_name": self.code_signature_subject,
            },
            "Ext": {
                "ancestry": ancestry or [],
            },
        }

        if self.hash_md5:
            result["hash"]["md5"] = self.hash_md5
        if self.hash_sha256:
            result["hash"]["sha256"] = self.hash_sha256

        return result

    def to_parent_dict(self) -> dict[str, Any]:
        """
        Convert to ECS-compatible process.parent fields.

        Returns:
            Dictionary with ECS process.parent.* fields
        """
        return {
            "entity_id": self.entity_id,
            "pid": self.pid,
            "name": self.name,
            "executable": self.executable,
            "command_line": self.command_line,
            "args": self.args,
            "args_count": len(self.args),
            "working_directory": self.working_directory,
            "start": self.start_time,
            "user": {
                "id": self.user_id,
                "name": self.user_name,
            },
            "group": {
                "id": self.user_id,
                "name": self.user_name,
            },
            "interactive": True,
        }

    def to_session_leader_dict(self) -> dict[str, Any]:
        """
        Convert to ECS-compatible session_leader fields.

        Returns:
            Dictionary with ECS process.session_leader.* fields
        """
        return {
            "entity_id": self.entity_id,
            "pid": self.pid,
            "name": self.name,
            "executable": self.executable,
            "command_line": self.command_line,
            "args": self.args,
            "args_count": len(self.args),
            "working_directory": self.working_directory,
            "start": self.start_time,
            "interactive": True,
            "user": {
                "id": self.user_id,
                "name": self.user_name,
            },
            "group": {
                "id": self.user_id,
                "name": self.user_name,
            },
        }


@dataclass
class ProcessTree:
    """
    A tree of processes on a single host.

    Manages process hierarchy and provides methods for
    spawning new processes with proper lineage.

    Attributes:
        host_id: Host this tree belongs to
        boot_id: Boot ID scoping process entity_ids
        processes: Dictionary of entity_id -> ProcessNode
        root_processes: List of root process entity_ids (session leaders)
    """

    host_id: str
    boot_id: str
    processes: dict[str, ProcessNode] = field(default_factory=dict)
    root_processes: list[str] = field(default_factory=list)

    # PID counter for this tree
    _next_pid: int = field(default=100, repr=False)

    @staticmethod
    def generate_entity_id() -> str:
        """Generate a unique process entity ID."""
        return str(uuid.uuid4())[:10]

    @staticmethod
    def generate_hash(hash_type: str = "md5") -> str:
        """Generate a random hash value."""
        length_map = {
            "md5": 16,
            "sha1": 20,
            "sha256": 32,
        }
        length = length_map.get(hash_type, 16)
        return "".join([f"{random.randint(0, 255):02x}" for _ in range(length)])

    def _get_next_pid(self) -> int:
        """Get next available PID."""
        pid = self._next_pid
        self._next_pid += random.randint(1, 100)
        return pid

    def spawn_process(
        self,
        name: str,
        executable: str,
        args: list[str],
        working_directory: str,
        user_name: str,
        user_id: str,
        parent_id: str | None = None,
        is_session_leader: bool = False,
    ) -> ProcessNode:
        """
        Spawn a new process in the tree.

        Args:
            name: Process name
            executable: Full executable path
            args: Command line arguments
            working_directory: Working directory
            user_name: User running the process
            user_id: User ID
            parent_id: Parent process entity_id (None for session leaders)
            is_session_leader: Whether this is a session leader

        Returns:
            New ProcessNode added to the tree
        """
        entity_id = self.generate_entity_id()
        pid = self._get_next_pid()

        # Determine session/entry leader
        if is_session_leader or parent_id is None:
            session_leader_id = entity_id
            entry_leader_id = entity_id
        else:
            parent = self.get_process(parent_id)
            session_leader_id = parent.session_leader_id if parent else entity_id
            entry_leader_id = parent.entry_leader_id if parent else entity_id

        node = ProcessNode(
            entity_id=entity_id,
            pid=pid,
            name=name,
            executable=executable,
            command_line=" ".join(args) if args else executable,
            args=args or [executable],
            working_directory=working_directory,
            user_name=user_name,
            user_id=user_id,
            parent_entity_id=parent_id,
            session_leader_id=session_leader_id,
            entry_leader_id=entry_leader_id,
            hash_md5=self.generate_hash("md5"),
            hash_sha256=self.generate_hash("sha256"),
        )

        # Add to tree
        self.processes[entity_id] = node

        # Track root processes
        if parent_id is None:
            self.root_processes.append(entity_id)
        else:
            # Add as child to parent
            parent = self.get_process(parent_id)
            if parent:
                parent.children.append(node)

        return node

    def get_process(self, entity_id: str) -> ProcessNode | None:
        """Get a process by entity_id."""
        return self.processes.get(entity_id)

    def get_session_leader(self, entity_id: str) -> ProcessNode | None:
        """Get the session leader for a process."""
        process = self.get_process(entity_id)
        if process and process.session_leader_id:
            return self.get_process(process.session_leader_id)
        return None

    def get_entry_leader(self, entity_id: str) -> ProcessNode | None:
        """Get the entry leader for a process."""
        process = self.get_process(entity_id)
        if process and process.entry_leader_id:
            return self.get_process(process.entry_leader_id)
        return None

    def spawn_chain(
        self,
        process_infos: list[dict[str, Any]],
        user_name: str,
        user_id: str,
    ) -> list[ProcessNode]:
        """
        Spawn a chain of processes (parent -> child -> grandchild...).

        Args:
            process_infos: List of dicts with name, executable, args, working_dir
            user_name: User running all processes
            user_id: User ID

        Returns:
            List of ProcessNodes in order (root to leaf)
        """
        nodes = []
        parent_id = None

        for i, info in enumerate(process_infos):
            node = self.spawn_process(
                name=info["name"],
                executable=info["executable"],
                args=info.get("args", [info["executable"]]),
                working_directory=info.get("working_dir", "/"),
                user_name=info.get("user", user_name),
                user_id=info.get("user_id", user_id),
                parent_id=parent_id,
                is_session_leader=(i == 0),
            )
            nodes.append(node)
            parent_id = node.entity_id

        return nodes

    def clear(self) -> None:
        """Clear all processes (simulates reboot)."""
        self.processes.clear()
        self.root_processes.clear()
        self._next_pid = 100
