"""Registry event generator for creating ECS-compliant Windows registry events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import (
    GeneratorCategory,
    register_attack_pattern,
    register_event_type,
)

if TYPE_CHECKING:
    from secgen.models.entities import Host, User
    from secgen.models.entities.process_tree import ProcessNode

RegistryAction = Literal["modification", "creation", "deletion", "query", "rename"]


@register_event_type(
    name="registry",
    category=GeneratorCategory.ENDPOINT,
    description="Windows registry events for detecting persistence and defense evasion",
    ecs_fields=[
        "registry.path",
        "registry.key",
        "registry.value",
        "registry.data.strings",
        "event.action",
    ],
    index_pattern="logs-endpoint.events.registry-default",
    example_params={"action": "modification", "is_malicious": True},
)
class RegistryEventGenerator:
    """
    Generator for creating ECS-compliant Windows registry events.

    Registry events are critical for detecting:
    - Persistence mechanisms (Run keys, Services)
    - Defense evasion (disabling security tools)
    - Privilege escalation (UAC bypass)
    - Credential access (credential manager)
    - System configuration changes
    """

    # Registry hives
    HIVES = [
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
        "HKEY_USERS",
        "HKEY_CLASSES_ROOT",
        "HKEY_CURRENT_CONFIG",
    ]

    HIVE_ABBREVIATIONS = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_USERS": "HKU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKEY_CURRENT_CONFIG": "HKCC",
    }

    # Persistence-related registry paths (high value for detection)
    PERSISTENCE_PATHS = [
        # Run keys
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        # Services
        ("HKEY_LOCAL_MACHINE", "SYSTEM\\CurrentControlSet\\Services"),
        # Scheduled Tasks
        (
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
        ),
        # Winlogon
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        # Shell extensions
        (
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
        ),
        # Browser Helper Objects
        (
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
        ),
        # AppInit DLLs
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
        # Image File Execution Options (debugger persistence)
        (
            "HKEY_LOCAL_MACHINE",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        ),
    ]

    # Security-related registry paths
    SECURITY_PATHS = [
        # Windows Defender
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows Defender"),
        # UAC
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
        # Firewall
        (
            "HKEY_LOCAL_MACHINE",
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
        ),
        # LSA
        ("HKEY_LOCAL_MACHINE", "SYSTEM\\CurrentControlSet\\Control\\Lsa"),
        # Security Center
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Security Center"),
    ]

    # Common legitimate registry paths
    LEGITIMATE_PATHS = [
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"),
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Office"),
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Cryptography"),
    ]

    # Registry data types
    DATA_TYPES = [
        "REG_SZ",
        "REG_EXPAND_SZ",
        "REG_BINARY",
        "REG_DWORD",
        "REG_QWORD",
        "REG_MULTI_SZ",
        "REG_NONE",
    ]

    # Suspicious value names for persistence
    SUSPICIOUS_VALUE_NAMES = [
        "SecurityUpdate",
        "WindowsDefenderUpdate",
        "SystemMonitor",
        "MicrosoftUpdate",
        "ServiceHost",
        "TaskScheduler",
        "WindowsServices",
        "RuntimeBroker",
        "BackgroundTask",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize registry event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        action: RegistryAction,
        hive: str | None = None,
        key: str | None = None,
        value_name: str | None = None,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        process: Optional["ProcessNode"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
    ) -> dict[str, Any]:
        """
        Generate a single registry event.

        Args:
            action: Registry action (modification, creation, deletion, query)
            hive: Optional specific registry hive
            key: Optional specific registry key path
            value_name: Optional specific value name
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            process: Optional ProcessNode for process linkage
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious registry characteristics

        Returns:
            ECS-compliant registry event dictionary
        """
        # Registry events are Windows-only
        if host and host.os.family != "windows":
            # Return empty event for non-Windows hosts
            return {}

        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Select registry path
        if hive and key:
            selected_hive = hive
            selected_key = key
        elif is_malicious:
            selected_hive, selected_key = random.choice(
                self.PERSISTENCE_PATHS + self.SECURITY_PATHS
            )
        else:
            selected_hive, selected_key = random.choice(self.LEGITIMATE_PATHS)

        # Generate full path
        full_path = f"{selected_hive}\\{selected_key}"

        # Generate value name if not provided
        if not value_name:
            if is_malicious:
                value_name = random.choice(self.SUSPICIOUS_VALUE_NAMES)
            else:
                value_name = f"Setting{random.randint(1, 100)}"

        # Generate registry data
        data_type = random.choice(self.DATA_TYPES)
        data_value = self._generate_registry_data(data_type, is_malicious)

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["registry"],
                "type": self._get_event_type(action),
                "action": f"registry-{action}",
                "id": self.randomizer.generate_uuid(),
                "outcome": "success",
            },
            "registry": {
                "hive": selected_hive,
                "key": selected_key,
                "path": full_path,
                "value": value_name,
                "data": {
                    "type": data_type,
                    "strings": (
                        [data_value]
                        if data_type in ["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"]
                        else None
                    ),
                    "bytes": data_value if data_type == "REG_BINARY" else None,
                },
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.registry",
                "namespace": "default",
            },
        }

        # Clean up None values in registry.data
        event["registry"]["data"] = {
            k: v for k, v in event["registry"]["data"].items() if v is not None
        }

        # Add host information
        if host:
            event["host"] = host.to_ecs_dict()
            event["agent"] = host.to_agent_dict()
        else:
            hostname = self.randomizer.generate_hostname()
            event["host"] = {
                "name": hostname,
                "hostname": hostname,
                "os": {"family": "windows", "name": "Windows", "platform": "windows"},
            }
            event["agent"] = {
                "type": "endpoint",
                "id": self.randomizer.generate_uuid(),
            }

        # Add user information
        if user:
            event["user"] = user.to_ecs_dict()
        else:
            event["user"] = {
                "name": "SYSTEM",
                "id": "S-1-5-18",
                "domain": "NT AUTHORITY",
            }

        # Add process information (linking registry event to responsible process)
        if process:
            event["process"] = {
                "entity_id": process.entity_id,
                "pid": process.pid,
                "name": process.name,
                "executable": process.executable,
            }
        else:
            event["process"] = {
                "entity_id": self.randomizer.generate_entity_id(),
                "pid": random.randint(1000, 65000),
                "name": "reg.exe",
                "executable": "C:\\Windows\\System32\\reg.exe",
            }

        # Add related fields
        related: dict[str, list[str]] = {}
        if user:
            related["user"] = user.to_related_user()
        event["related"] = related

        return event

    def _get_event_type(self, action: RegistryAction) -> list[str]:
        """Map registry action to ECS event.type."""
        type_mapping = {
            "creation": ["creation"],
            "modification": ["change"],
            "deletion": ["deletion"],
            "query": ["access"],
            "rename": ["change"],
        }
        return type_mapping.get(action, ["info"])

    def _generate_registry_data(self, data_type: str, is_malicious: bool) -> str:
        """Generate realistic registry data based on type."""
        if data_type in ["REG_SZ", "REG_EXPAND_SZ"]:
            if is_malicious:
                # Suspicious executable paths
                paths = [
                    "C:\\Users\\Public\\malware.exe",
                    "C:\\Windows\\Temp\\svchost.exe",
                    "C:\\ProgramData\\update.exe",
                    "powershell.exe -enc " + self.randomizer.generate_hash("sha256")[:32],
                    "cmd.exe /c " + self.randomizer.generate_hash("md5")[:16] + ".bat",
                    "rundll32.exe C:\\Windows\\Temp\\payload.dll,Start",
                    'mshta.exe vbscript:Execute("...")',
                    "%TEMP%\\loader.exe",
                ]
                return random.choice(paths)
            else:
                # Legitimate paths
                paths = [
                    "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
                    "C:\\Windows\\System32\\notepad.exe",
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                ]
                return random.choice(paths)
        elif data_type == "REG_DWORD":
            return str(random.randint(0, 1))
        elif data_type == "REG_QWORD":
            return str(random.randint(0, 2**32))
        elif data_type == "REG_BINARY":
            # Return hex-encoded binary data
            return self.randomizer.generate_hash("sha256")
        elif data_type == "REG_MULTI_SZ":
            return "value1\\0value2\\0value3"
        return ""

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        process: Optional["ProcessNode"] = None,
        malicious_ratio: float = 0.2,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of registry events.

        Args:
            count: Number of events to generate
            host: Optional Host entity
            user: Optional User entity
            process: Optional ProcessNode
            malicious_ratio: Ratio of malicious events (0.0-1.0)
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of registry event dictionaries
        """
        events = []
        actions: list[RegistryAction] = ["modification", "creation", "query", "deletion"]

        for i in range(count):
            action = random.choice(actions)
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                action=action,
                host=host,
                user=user,
                process=process,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            if event:  # Skip empty events (non-Windows)
                events.append(event)

        return events

    @register_attack_pattern(
        name="registry-persistence",
        description="Registry-based persistence mechanism establishment",
        ttps=["T1547.001", "T1543.003", "T1546.012"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process"],
        optional_params=["persistence_type", "malware_path"],
        event_types=["registry"],
        detection_recommendations=[
            "Modifications to Run/RunOnce keys",
            "Service creation via registry",
            "Winlogon or IFEO modifications",
        ],
    )
    def generate_persistence(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        persistence_type: str = "run_key",
        malware_path: str = "C:\\Windows\\Temp\\malware.exe",
    ) -> dict[str, Any]:
        """
        Generate a registry persistence event.

        Args:
            host: Host entity
            user: User entity
            process: Process establishing persistence
            persistence_type: Type of persistence (run_key, service, scheduled_task)
            malware_path: Path to the malicious executable

        Returns:
            Registry modification event for persistence
        """
        persistence_configs = {
            "run_key": {
                "hive": "HKEY_LOCAL_MACHINE",
                "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": random.choice(self.SUSPICIOUS_VALUE_NAMES),
                "data": malware_path,
            },
            "run_key_user": {
                "hive": "HKEY_CURRENT_USER",
                "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": random.choice(self.SUSPICIOUS_VALUE_NAMES),
                "data": malware_path,
            },
            "service": {
                "hive": "HKEY_LOCAL_MACHINE",
                "key": f"SYSTEM\\CurrentControlSet\\Services\\{random.choice(self.SUSPICIOUS_VALUE_NAMES)}",
                "value_name": "ImagePath",
                "data": malware_path,
            },
            "winlogon": {
                "hive": "HKEY_LOCAL_MACHINE",
                "key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "value_name": "Userinit",
                "data": f"C:\\Windows\\System32\\userinit.exe,{malware_path}",
            },
            "ifeo": {
                "hive": "HKEY_LOCAL_MACHINE",
                "key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
                "value_name": "Debugger",
                "data": malware_path,
            },
        }

        config = persistence_configs.get(persistence_type, persistence_configs["run_key"])

        return self.generate(
            action="modification",
            hive=config["hive"],
            key=config["key"],
            value_name=config["value_name"],
            host=host,
            user=user,
            process=process,
            is_malicious=True,
        )

    @register_attack_pattern(
        name="security-disable",
        description="Disabling security features via registry modification",
        ttps=["T1562.001", "T1112"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process"],
        optional_params=["target"],
        event_types=["registry"],
        detection_recommendations=[
            "Windows Defender policy modifications",
            "Firewall disable attempts",
            "UAC bypass via registry",
        ],
    )
    def generate_security_disable(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        target: str = "defender",
    ) -> list[dict[str, Any]]:
        """
        Generate registry events for disabling security features.

        Args:
            host: Host entity
            user: User entity
            process: Process disabling security
            target: Security feature to disable (defender, firewall, uac)

        Returns:
            List of registry modification events
        """
        events = []

        disable_configs = {
            "defender": [
                {
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    "value_name": "DisableAntiSpyware",
                },
                {
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                    "value_name": "DisableRealtimeMonitoring",
                },
            ],
            "firewall": [
                {
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                    "value_name": "EnableFirewall",
                },
            ],
            "uac": [
                {
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "value_name": "EnableLUA",
                },
                {
                    "hive": "HKEY_LOCAL_MACHINE",
                    "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "value_name": "ConsentPromptBehaviorAdmin",
                },
            ],
        }

        configs = disable_configs.get(target, disable_configs["defender"])

        for config in configs:
            event = self.generate(
                action="modification",
                hive=config["hive"],
                key=config["key"],
                value_name=config["value_name"],
                host=host,
                user=user,
                process=process,
                is_malicious=True,
            )
            if event:
                events.append(event)

        return events
