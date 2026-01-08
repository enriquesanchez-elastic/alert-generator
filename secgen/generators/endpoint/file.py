"""File event generator for creating ECS-compliant file events."""

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

FileAction = Literal[
    "creation", "modification", "deletion", "rename", "attributes_modified", "overwrite"
]


@register_event_type(
    name="file",
    category=GeneratorCategory.ENDPOINT,
    description="File system events for detecting malware drops, staging, and tampering",
    ecs_fields=[
        "file.path",
        "file.name",
        "file.hash.sha256",
        "file.code_signature",
        "event.action",
    ],
    index_pattern="logs-endpoint.events.file-default",
    example_params={"action": "creation", "is_malicious": True},
)
class FileEventGenerator:
    """
    Generator for creating ECS-compliant file events.

    File events are critical for detecting:
    - Malware drops and installations
    - Data staging for exfiltration
    - Log clearing and artifact removal
    - Ransomware encryption activity
    - Configuration tampering
    """

    # Common suspicious file paths by OS
    SUSPICIOUS_PATHS = {
        "windows": [
            "C:\\Windows\\Temp",
            "C:\\Users\\Public",
            "C:\\ProgramData",
            "C:\\Windows\\System32",
            "C:\\Temp",
            "C:\\Users\\{user}\\AppData\\Local\\Temp",
            "C:\\Users\\{user}\\AppData\\Roaming",
            "C:\\Users\\{user}\\Downloads",
        ],
        "linux": [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/var/log",
            "/etc",
            "/usr/local/bin",
            "/home/{user}/.local/bin",
            "/home/{user}/.config",
            "/opt",
        ],
        "macos": [
            "/tmp",
            "/var/tmp",
            "/Users/{user}/Downloads",
            "/Users/{user}/Library/Application Support",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/Users/{user}/Library/LaunchAgents",
        ],
    }

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        "executable": [".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js"],
        "script": [".py", ".sh", ".bash", ".pl", ".rb", ".php"],
        "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz"],
        "document": [".doc", ".docx", ".xls", ".xlsx", ".pdf", ".rtf"],
        "config": [".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml"],
    }

    # Malware-like filenames
    MALWARE_NAMES = [
        "svchost",
        "csrss",
        "lsass",
        "explorer",
        "rundll32",
        "cmd",
        "powershell",
        "update",
        "installer",
        "setup",
        "patch",
        "loader",
        "dropper",
        "payload",
        "beacon",
        "shell",
        "backdoor",
        "rat",
        "miner",
    ]

    # Code signature statuses
    SIGNATURE_STATUSES = ["trusted", "untrusted", "unsigned", "invalid", "errorBadDigest"]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize file event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        action: FileAction,
        file_path: str | None = None,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        process: Optional["ProcessNode"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
    ) -> dict[str, Any]:
        """
        Generate a single file event.

        Args:
            action: File action (creation, modification, deletion, rename)
            file_path: Optional specific file path
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            process: Optional ProcessNode for process linkage
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious file characteristics

        Returns:
            ECS-compliant file event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()
        timestamp_ms = int(now.timestamp() * 1000)

        # Determine OS family
        os_family = "linux"
        if host:
            os_family = host.os.family

        # Generate file path if not provided
        if not file_path:
            file_path = self._generate_file_path(os_family, user, is_malicious)

        # Parse file components
        file_name = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
        file_extension = "." + file_name.split(".")[-1] if "." in file_name else ""
        file_directory = file_path.rsplit("/" if "/" in file_path else "\\", 1)[0]

        # Generate file hashes
        file_md5 = self.randomizer.generate_hash("md5")
        file_sha1 = self.randomizer.generate_hash("sha1")
        file_sha256 = self.randomizer.generate_hash("sha256")

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["file"],
                "type": self._get_event_type(action),
                "action": action,
                "id": self.randomizer.generate_uuid(),
                "outcome": "success",
            },
            "file": {
                "path": file_path,
                "name": file_name,
                "directory": file_directory,
                "extension": file_extension.lstrip(".") if file_extension else None,
                "size": random.randint(1024, 10485760),  # 1KB to 10MB
                "mtime": timestamp_ms,
                "ctime": timestamp_ms,
                "accessed": timestamp_ms,
                "created": timestamp_ms - random.randint(0, 86400000),  # Up to 1 day ago
                "hash": {
                    "md5": file_md5,
                    "sha1": file_sha1,
                    "sha256": file_sha256,
                },
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.file",
                "namespace": "default",
            },
        }

        # Add code signature for executables
        if file_extension in [".exe", ".dll", ".sys", ".scr"]:
            if is_malicious:
                event["file"]["code_signature"] = {
                    "exists": random.choice([True, False]),
                    "status": random.choice(["untrusted", "unsigned", "invalid"]),
                    "subject_name": random.choice(["Unknown", "Suspicious Publisher", ""]),
                    "trusted": False,
                    "valid": False,
                }
            else:
                event["file"]["code_signature"] = {
                    "exists": True,
                    "status": "trusted",
                    "subject_name": "Microsoft Corporation",
                    "trusted": True,
                    "valid": True,
                }

        # Add PE metadata for Windows executables
        if os_family == "windows" and file_extension in [".exe", ".dll"]:
            event["file"]["pe"] = {
                "original_file_name": file_name,
                "file_version": f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9999)}.{random.randint(0, 9999)}",
                "product": "Unknown" if is_malicious else "Windows Operating System",
                "company": "Unknown" if is_malicious else "Microsoft Corporation",
            }

        # Add Elastic Defend extension fields
        event["file"]["Ext"] = {
            "entropy": random.uniform(4.0, 8.0) if is_malicious else random.uniform(1.0, 5.0),
            "header_bytes": self.randomizer.generate_hash("md5")[:32],
        }

        # Add host information
        if host:
            event["host"] = host.to_ecs_dict()
            event["agent"] = host.to_agent_dict()
        else:
            event["host"] = {
                "name": self.randomizer.generate_hostname(),
                "os": {"family": os_family},
            }
            event["agent"] = {
                "type": "endpoint",
                "id": self.randomizer.generate_uuid(),
            }

        # Add user information
        if user:
            event["user"] = user.to_ecs_dict()
            event["file"]["owner"] = user.name
        else:
            event["user"] = {
                "name": self.randomizer.generate_username(),
                "id": str(random.randint(1000, 65000)),
            }
            event["file"]["owner"] = event["user"]["name"]

        # Add process information (linking file event to responsible process)
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
                "name": "explorer.exe" if os_family == "windows" else "bash",
                "executable": (
                    "C:\\Windows\\explorer.exe" if os_family == "windows" else "/bin/bash"
                ),
            }

        # Add related fields for correlation
        related: dict[str, list[str]] = {
            "hash": [file_md5, file_sha1, file_sha256],
        }
        if user:
            related["user"] = user.to_related_user()
        event["related"] = related

        # Add rename-specific fields
        if action == "rename":
            old_name = f"old_{file_name}"
            event["file"]["Ext"]["original"] = {
                "path": file_path.replace(file_name, old_name),
                "name": old_name,
            }

        return event

    def _get_event_type(self, action: FileAction) -> list[str]:
        """Map file action to ECS event.type."""
        type_mapping = {
            "creation": ["creation"],
            "modification": ["change"],
            "deletion": ["deletion"],
            "rename": ["change"],
            "attributes_modified": ["change"],
            "overwrite": ["change"],
        }
        return type_mapping.get(action, ["info"])

    def _generate_file_path(
        self,
        os_family: str,
        user: Optional["User"] = None,
        is_malicious: bool = False,
    ) -> str:
        """Generate a realistic file path."""
        paths = self.SUSPICIOUS_PATHS.get(os_family, self.SUSPICIOUS_PATHS["linux"])
        base_path = random.choice(paths)

        # Replace user placeholder
        if user:
            base_path = base_path.replace("{user}", user.name)
        else:
            base_path = base_path.replace("{user}", "victim")

        # Generate filename
        if is_malicious:
            # Use malware-like name
            name_base = random.choice(self.MALWARE_NAMES)
            # Sometimes add random suffix to evade detection
            if random.random() < 0.5:
                name_base += f"_{random.randint(1, 999)}"
            extension = random.choice(self.SUSPICIOUS_EXTENSIONS["executable"])
        else:
            # Normal file
            name_base = f"document_{random.randint(1, 9999)}"
            extension = random.choice([".txt", ".log", ".dat", ".tmp"])

        filename = f"{name_base}{extension}"

        if os_family == "windows":
            return f"{base_path}\\{filename}"
        return f"{base_path}/{filename}"

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
        Generate a batch of file events.

        Args:
            count: Number of events to generate
            host: Optional Host entity
            user: Optional User entity
            process: Optional ProcessNode
            malicious_ratio: Ratio of malicious events (0.0-1.0)
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of file event dictionaries
        """
        events = []
        actions: list[FileAction] = ["creation", "modification", "deletion", "rename"]

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
            events.append(event)

        return events

    @register_attack_pattern(
        name="malware-drop",
        description="Malware file drop to disk by malicious process",
        ttps=["T1105", "T1204.002"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process"],
        optional_params=["malware_name", "drop_path"],
        event_types=["file"],
        detection_recommendations=[
            "Unsigned executables in temp directories",
            "Files with suspicious names mimicking system processes",
            "High entropy files (packed/encrypted)",
        ],
    )
    def generate_malware_drop(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        malware_name: str = "payload.exe",
        drop_path: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a malware drop file creation event.

        Args:
            host: Host entity
            user: User entity
            process: Process that dropped the file
            malware_name: Name of the malware file
            drop_path: Optional specific drop path

        Returns:
            File creation event for malware drop
        """
        os_family = host.os.family

        if not drop_path:
            if os_family == "windows":
                drop_path = f"C:\\Users\\{user.name}\\AppData\\Local\\Temp\\{malware_name}"
            else:
                drop_path = f"/tmp/{malware_name}"

        return self.generate(
            action="creation",
            file_path=drop_path,
            host=host,
            user=user,
            process=process,
            is_malicious=True,
        )

    @register_attack_pattern(
        name="data-staging",
        description="Data staging for exfiltration - copying sensitive files to staging area",
        ttps=["T1074.001", "T1560.001"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process"],
        optional_params=["staged_files"],
        event_types=["file"],
        detection_recommendations=[
            "Bulk file operations to temp directories",
            "Archive creation in staging locations",
            "Sensitive file extensions being copied",
        ],
    )
    def generate_data_staging(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        staged_files: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Generate file events for data staging (pre-exfiltration).

        Args:
            host: Host entity
            user: User entity
            process: Process performing staging
            staged_files: Number of files being staged

        Returns:
            List of file events representing data staging
        """
        events = []
        os_family = host.os.family

        # Staging directory
        if os_family == "windows":
            staging_dir = f"C:\\Users\\{user.name}\\AppData\\Local\\Temp\\staging"
        else:
            staging_dir = "/tmp/.staging"

        # Create staged files (copies of sensitive data)
        sensitive_extensions = [".doc", ".docx", ".xls", ".xlsx", ".pdf", ".pst", ".db"]

        for i in range(staged_files):
            ext = random.choice(sensitive_extensions)
            filename = f"data_{i+1}{ext}"

            if os_family == "windows":
                file_path = f"{staging_dir}\\{filename}"
            else:
                file_path = f"{staging_dir}/{filename}"

            event = self.generate(
                action="creation",
                file_path=file_path,
                host=host,
                user=user,
                process=process,
                is_malicious=True,
            )
            events.append(event)

        # Create archive of staged data
        if os_family == "windows":
            archive_path = f"{staging_dir}\\exfil.zip"
        else:
            archive_path = f"{staging_dir}/exfil.tar.gz"

        archive_event = self.generate(
            action="creation",
            file_path=archive_path,
            host=host,
            user=user,
            process=process,
            is_malicious=True,
        )
        events.append(archive_event)

        return events
