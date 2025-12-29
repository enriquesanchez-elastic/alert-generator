"""Scenario models representing attack scenarios."""

from dataclasses import dataclass, field
from typing import Any, Literal


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
    args: list[str]
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

# Event types for multi-event scenarios
EventType = Literal[
    "process",
    "file",
    "registry",
    "network",
    "authentication",
    "dns",
    "http",
    "tls",
    "aws_cloudtrail",
    "azure_signin",
    "azure_audit",
    "gcp_audit",
]


@dataclass
class EventTemplate:
    """
    Template for generating a specific event type.

    Attributes:
        type: Event type (process, file, registry, network, etc.)
        template: Template name (e.g., 'powershell_encoded', 'malware_drop') or empty for inline params
        params: Additional parameters for the generator
        delay_seconds: Delay after previous event in seconds
    """

    type: EventType
    template: str = ""  # Empty string means use inline params only
    params: dict[str, Any] = field(default_factory=dict)
    delay_seconds: int = 0


@dataclass
class PhaseCorrelation:
    """
    Correlation settings for a phase.

    Attributes:
        same_host: All events in phase on same host
        same_user: All events in phase by same user
        process_tree: Maintain process tree relationship
    """

    same_host: bool = True
    same_user: bool = True
    process_tree: bool = True


@dataclass
class AttackPhase:
    """
    A phase within a multi-stage attack scenario.

    Attributes:
        name: Phase name (e.g., "initial_access", "execution", "persistence")
        description: Phase description
        events: List of event templates to generate
        correlation: Correlation settings
        duration_minutes: Duration of this phase in minutes
    """

    name: str
    events: list[EventTemplate]
    description: str = ""
    correlation: PhaseCorrelation = field(default_factory=PhaseCorrelation)
    duration_minutes: int = 5


@dataclass
class EnvironmentConfig:
    """
    Environment configuration for scenario execution.

    Attributes:
        os_family: Target OS (linux, windows, macos)
        host_template: Host template to use
        user_template: User template to use
    """

    os_family: str = "linux"
    host_template: str = "workstation"
    user_template: str = "standard"


@dataclass(frozen=True)
class Scenario:
    """
    Attack scenario definition.

    Supports both legacy single-alert scenarios and new multi-event scenarios.

    Attributes:
        name: Scenario name (e.g., "Ransomware", "Web Shell Deployment")
        description: Human-readable description of the attack
        severity: Alert severity level
        processes: List of processes in attack chain (root to leaf) - legacy
        malware_file: Information about the malicious file - legacy
    """

    name: str
    description: str
    severity: Severity
    processes: list[ProcessInfo]
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


@dataclass
class MultiEventScenario:
    """
    Multi-event attack scenario with phases.

    This is the new scenario format that supports generating multiple
    correlated event types across attack phases.

    Attributes:
        name: Scenario name
        description: Scenario description
        severity: Severity level
        phases: List of attack phases
        environment: Environment configuration
        threat_actor: Associated threat actor name
        ttps: MITRE ATT&CK TTPs
        generate_indicators: Whether to generate matching threat indicators
    """

    name: str
    severity: Severity
    phases: list[AttackPhase]
    description: str = ""
    environment: EnvironmentConfig = field(default_factory=EnvironmentConfig)
    threat_actor: str | None = None
    ttps: list[str] = field(default_factory=list)
    generate_indicators: bool = True

    def __post_init__(self) -> None:
        """Validate scenario attributes."""
        if not self.name:
            raise ValueError("Scenario name cannot be empty")
        if not self.phases:
            raise ValueError("Multi-event scenario must have at least one phase")
        if self.severity not in ["low", "medium", "high", "critical"]:
            raise ValueError(
                f"Invalid severity: {self.severity}. Must be one of: low, medium, high, critical"
            )

    def get_all_events(self) -> list[EventTemplate]:
        """Get all event templates across all phases."""
        events = []
        for phase in self.phases:
            events.extend(phase.events)
        return events

    def to_legacy_scenario(self) -> Scenario | None:
        """
        Convert to legacy scenario format if possible.

        Returns Scenario if the multi-event scenario has process events,
        otherwise returns None.
        """
        # Find process events
        process_events = [e for phase in self.phases for e in phase.events if e.type == "process"]

        if len(process_events) < 2:
            return None

        # Create ProcessInfo from templates
        processes = []
        for pe in process_events:
            params = pe.params
            processes.append(
                ProcessInfo(
                    name=params.get("name", "unknown"),
                    executable=params.get("executable", "/bin/unknown"),
                    args=params.get("args", []),
                    working_dir=params.get("working_dir", "/"),
                    user=params.get("user", "root"),
                )
            )

        # Create MalwareFile from file events
        file_events = [e for phase in self.phases for e in phase.events if e.type == "file"]

        if file_events:
            fe_params = file_events[0].params
            malware_file = MalwareFile(
                name=fe_params.get("name", "malware.bin"),
                path=fe_params.get("path", "/tmp/malware.bin"),
                extension=fe_params.get("extension", ".bin"),
            )
        else:
            malware_file = MalwareFile(
                name="malware.bin",
                path="/tmp/malware.bin",
                extension=".bin",
            )

        return Scenario(
            name=self.name,
            description=self.description,
            severity=self.severity,
            processes=processes,
            malware_file=malware_file,
        )


# Event template presets for common attack patterns
EVENT_TEMPLATES = {
    # Process templates
    "bash_session": {
        "type": "process",
        "params": {
            "name": "bash",
            "executable": "/bin/bash",
            "args": ["-i"],
            "working_dir": "/home/user",
            "user": "user",
        },
    },
    "powershell_encoded": {
        "type": "process",
        "params": {
            "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "args": ["-enc", "JABjAGwAaQBlAG4AdAA="],
            "working_dir": "C:\\Windows\\System32",
            "user": "SYSTEM",
        },
    },
    # File templates
    "malware_drop": {
        "type": "file",
        "params": {
            "action": "creation",
            "is_malicious": True,
        },
    },
    "data_staging": {
        "type": "file",
        "params": {
            "action": "creation",
            "is_malicious": True,
            "staged_files": 5,
        },
    },
    # Network templates
    "c2_beacon": {
        "type": "network",
        "params": {
            "is_malicious": True,
            "direction": "egress",
        },
    },
    "data_exfiltration": {
        "type": "network",
        "params": {
            "is_malicious": True,
            "direction": "egress",
            "bytes_sent": 10000000,
        },
    },
    # Authentication templates
    "successful_login": {
        "type": "authentication",
        "params": {
            "outcome": "success",
        },
    },
    "failed_login": {
        "type": "authentication",
        "params": {
            "outcome": "failure",
        },
    },
    "brute_force": {
        "type": "authentication",
        "params": {
            "outcome": "failure",
            "attempts": 50,
        },
    },
    # Registry templates (Windows)
    "run_key_persistence": {
        "type": "registry",
        "params": {
            "action": "modification",
            "persistence_type": "run_key",
            "is_malicious": True,
        },
    },
    # DNS templates
    "dga_activity": {
        "type": "dns",
        "params": {
            "is_malicious": True,
            "dga": True,
        },
    },
    "dns_tunneling": {
        "type": "dns",
        "params": {
            "is_malicious": True,
            "tunneling": True,
        },
    },
}
