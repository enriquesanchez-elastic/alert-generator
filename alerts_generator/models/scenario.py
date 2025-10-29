"""Scenario models representing attack scenarios."""

from dataclasses import dataclass
from typing import List, Literal


@dataclass(frozen=True)
class ProcessInfo:
    """
    Information about a process in an attack chain.

    Attributes:
        name: Process name (e.g., "bash", "explorer.exe")
        executable: Full path to executable
        args: Command-line arguments
        working_dir: Working directory
        user: User running the process
    """

    name: str
    executable: str
    args: List[str]
    working_dir: str
    user: str


@dataclass(frozen=True)
class MalwareFile:
    """
    Information about the malicious file in an attack scenario.

    Attributes:
        name: Filename
        path: Full path to the file
        extension: File extension (including dot, e.g., ".exe", ".php")
    """

    name: str
    path: str
    extension: str


Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Scenario:
    """
    Attack scenario definition.

    Attributes:
        name: Scenario name (e.g., "Ransomware", "Web Shell Deployment")
        description: Human-readable description of the attack
        severity: Alert severity level
        processes: List of processes in attack chain (root to leaf)
        malware_file: Information about the malicious file
    """

    name: str
    description: str
    severity: Severity
    processes: List[ProcessInfo]
    malware_file: MalwareFile

    def __post_init__(self) -> None:
        """Validate scenario attributes."""
        if not self.name:
            raise ValueError("Scenario name cannot be empty")
        if not self.processes:
            raise ValueError("Scenario must have at least one process")
        if len(self.processes) < 2:
            raise ValueError("Scenario must have at least 2 processes in the chain")
        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError(
                f"Invalid severity: {self.severity}. Must be one of: low, medium, high, critical"
            )
