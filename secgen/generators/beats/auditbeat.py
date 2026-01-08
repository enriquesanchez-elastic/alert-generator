"""Auditbeat event generator for creating ECS-compliant audit events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.beats.base import BeatEventGenerator
from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_attack_pattern, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

AuditdataSet = Literal[
    "auditd",
    "system.login",
    "system.user",
    "system.process",
    "file_integrity",
]


@register_event_type(
    name="auditbeat",
    category=GeneratorCategory.ENDPOINT,
    description="Auditbeat events for process, auth, and file integrity monitoring",
    ecs_fields=[
        "event.module",
        "event.dataset",
        "process.name",
        "process.executable",
        "user.name",
        "auditd.result",
    ],
    index_pattern="auditbeat-*",
    example_params={"dataset": "auditd", "is_malicious": False},
)
class AuditbeatEventGenerator(BeatEventGenerator):
    """
    Generator for creating ECS-compliant Auditbeat events.

    Auditbeat collects:
    - auditd: Linux audit framework events (syscalls, file access)
    - system.login: User login/logout events
    - system.user: User account events
    - system.process: Process start/stop events
    - file_integrity: File integrity monitoring (FIM) events
    """

    # Common syscalls
    SYSCALLS = [
        "execve",
        "open",
        "openat",
        "read",
        "write",
        "connect",
        "socket",
        "bind",
        "listen",
        "accept",
        "sendto",
        "recvfrom",
        "unlink",
        "rename",
        "chmod",
        "chown",
        "setuid",
        "setgid",
        "ptrace",
        "kill",
        "fork",
        "clone",
        "mount",
        "umount",
    ]

    # Suspicious syscalls often monitored
    SUSPICIOUS_SYSCALLS = [
        "execve",
        "ptrace",
        "memfd_create",
        "process_vm_readv",
        "process_vm_writev",
        "finit_module",
        "init_module",
        "delete_module",
        "kexec_load",
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
    ]

    # Common process names
    BENIGN_PROCESSES = [
        "/usr/bin/bash",
        "/usr/bin/ls",
        "/usr/bin/cat",
        "/usr/bin/grep",
        "/usr/bin/find",
        "/usr/bin/ps",
        "/usr/bin/top",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/vim",
        "/usr/bin/nano",
        "/usr/bin/curl",
        "/usr/bin/wget",
        "/usr/sbin/sshd",
        "/usr/lib/systemd/systemd",
    ]

    # Suspicious processes
    SUSPICIOUS_PROCESSES = [
        "/tmp/evil",
        "/dev/shm/payload",
        "/var/tmp/.hidden",
        "/tmp/.X11-unix/shell",
        "/usr/bin/nc",
        "/usr/bin/ncat",
        "/usr/bin/nmap",
        "/usr/bin/tcpdump",
        "/tmp/miner",
        "/tmp/xmrig",
    ]

    # FIM paths to monitor
    FIM_PATHS = {
        "critical": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/crontab",
            "/etc/hosts",
        ],
        "system": [
            "/etc/systemd/system/",
            "/lib/systemd/system/",
            "/usr/lib/systemd/system/",
        ],
        "binaries": [
            "/usr/bin/",
            "/usr/sbin/",
            "/bin/",
            "/sbin/",
        ],
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize Auditbeat generator."""
        super().__init__(beat_type="auditbeat", randomizer=randomizer)

    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_offset: int = 0,
        dataset: AuditdataSet | None = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a single Auditbeat event.

        Args:
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            timestamp_offset: Minutes to offset timestamp
            dataset: Auditbeat dataset (auditd, system.login, etc.)
            is_malicious: Whether to generate suspicious activity
            **kwargs: Additional parameters

        Returns:
            ECS-compliant Auditbeat event dictionary
        """
        timestamp = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)

        if dataset is None:
            dataset = random.choice(
                ["auditd", "system.login", "system.process", "file_integrity"]
            )

        if dataset == "auditd":
            return self._generate_auditd_event(
                timestamp, host, user, is_malicious, **kwargs
            )
        elif dataset == "system.login":
            return self._generate_login_event(
                timestamp, host, user, is_malicious, **kwargs
            )
        elif dataset == "system.process":
            return self._generate_process_event(
                timestamp, host, user, is_malicious, **kwargs
            )
        elif dataset == "file_integrity":
            return self._generate_fim_event(
                timestamp, host, user, is_malicious, **kwargs
            )
        else:
            return self._generate_auditd_event(
                timestamp, host, user, is_malicious, **kwargs
            )

    def _generate_auditd_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate an auditd event (Linux audit framework)."""
        event = self._build_base_event(timestamp, host, dataset="auditd.log")

        # Select syscall
        if is_malicious:
            syscall = random.choice(self.SUSPICIOUS_SYSCALLS)
            exe = random.choice(self.SUSPICIOUS_PROCESSES)
            result = random.choice(["success", "fail"])
        else:
            syscall = random.choice(self.SYSCALLS)
            exe = random.choice(self.BENIGN_PROCESSES)
            result = "success"

        # Build auditd-specific fields
        audit_sequence = random.randint(1000, 999999)
        audit_session = str(random.randint(1, 1000))

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "auditd",
                    "dataset": "auditd.log",
                    "category": ["process"],
                    "type": ["info"],
                    "action": syscall,
                    "outcome": "success" if result == "success" else "failure",
                    "id": self.randomizer.generate_uuid(),
                },
                "auditd": {
                    "log": {
                        "sequence": audit_sequence,
                    },
                    "session": audit_session,
                    "result": result,
                    "summary": {
                        "actor": {
                            "primary": user.name if user else "root",
                            "secondary": user.name if user else "root",
                        },
                        "object": {
                            "type": "process",
                            "primary": exe.split("/")[-1],
                        },
                        "how": exe,
                    },
                    "data": {
                        "syscall": syscall,
                        "arch": "x86_64",
                        "success": result,
                        "exit": "0" if result == "success" else "-1",
                        "a0": hex(random.randint(0, 0xFFFFFFFF)),
                        "a1": hex(random.randint(0, 0xFFFFFFFF)),
                        "a2": hex(random.randint(0, 0xFFFFFFFF)),
                        "a3": hex(random.randint(0, 0xFFFFFFFF)),
                        "tty": "pts/0",
                    },
                },
                "process": {
                    "pid": random.randint(1000, 65535),
                    "ppid": random.randint(1, 1000),
                    "name": exe.split("/")[-1],
                    "executable": exe,
                    "working_directory": "/home/user" if user else "/root",
                    "args": [exe],
                    "entity_id": self.randomizer.generate_entity_id(),
                },
            }
        )

        # Add user info
        if user:
            event["user"] = user.to_ecs_dict()
            event["related"] = {"user": user.to_related_user()}
        else:
            username = "root" if not is_malicious else "attacker"
            event["user"] = {
                "name": username,
                "id": "0" if username == "root" else str(random.randint(1000, 65000)),
                "effective": {"name": username},
                "audit": {"name": username},
            }
            event["related"] = {"user": [username]}

        return event

    def _generate_login_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a system.login event."""
        event = self._build_base_event(timestamp, host, dataset="system.login")

        # Determine outcome
        if is_malicious:
            outcome = random.choices(["success", "failure"], weights=[0.2, 0.8])[0]
        else:
            outcome = random.choices(["success", "failure"], weights=[0.9, 0.1])[0]

        source_ip = kwargs.get("source_ip") or self.randomizer.generate_ip()

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "system",
                    "dataset": "system.login",
                    "category": ["authentication"],
                    "type": ["start"] if outcome == "success" else ["start"],
                    "action": "user_login",
                    "outcome": outcome,
                    "id": self.randomizer.generate_uuid(),
                },
                "system": {
                    "auth": {
                        "ssh": {
                            "method": "password",
                            "event": "Accepted" if outcome == "success" else "Failed",
                        },
                    },
                },
                "source": {
                    "ip": source_ip,
                    "port": random.randint(49152, 65535),
                },
                "related": {
                    "ip": [source_ip],
                },
            }
        )

        # Add user info
        if user:
            event["user"] = user.to_ecs_dict()
            event["related"]["user"] = user.to_related_user()
        else:
            username = self.randomizer.generate_username()
            event["user"] = {
                "name": username,
                "id": str(random.randint(1000, 65000)),
            }
            event["related"]["user"] = [username]

        return event

    def _generate_process_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a system.process event."""
        event = self._build_base_event(timestamp, host, dataset="system.process")

        # Select process
        if is_malicious:
            exe = random.choice(self.SUSPICIOUS_PROCESSES)
            action = "process_started"
        else:
            exe = random.choice(self.BENIGN_PROCESSES)
            action = random.choice(["process_started", "process_stopped"])

        process_name = exe.split("/")[-1]
        pid = random.randint(1000, 65535)
        ppid = random.randint(1, 1000)

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "system",
                    "dataset": "system.process",
                    "category": ["process"],
                    "type": ["start"] if "started" in action else ["end"],
                    "action": action,
                    "id": self.randomizer.generate_uuid(),
                },
                "process": {
                    "pid": pid,
                    "ppid": ppid,
                    "name": process_name,
                    "executable": exe,
                    "working_directory": "/home/user" if user else "/root",
                    "args": [exe],
                    "entity_id": self.randomizer.generate_entity_id(),
                    "start": timestamp.isoformat(),
                    "hash": {
                        "sha256": self.randomizer.generate_hash("sha256"),
                    },
                },
                "system": {
                    "process": {
                        "cpu": {
                            "total": {
                                "pct": random.uniform(0, 0.5),
                            },
                        },
                        "memory": {
                            "rss": {
                                "bytes": random.randint(1024 * 1024, 100 * 1024 * 1024),
                            },
                        },
                    },
                },
            }
        )

        # Add user info
        if user:
            event["user"] = user.to_ecs_dict()
            event["process"]["user"] = {"name": user.name, "id": user.id}
        else:
            username = "root" if not is_malicious else self.randomizer.generate_username()
            event["user"] = {
                "name": username,
                "id": "0" if username == "root" else str(random.randint(1000, 65000)),
            }
            event["process"]["user"] = event["user"]

        return event

    def _generate_fim_event(
        self,
        timestamp: datetime,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        is_malicious: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Generate a file_integrity event."""
        event = self._build_base_event(timestamp, host, dataset="file_integrity")

        # Select file path
        if is_malicious:
            path_category = random.choice(["critical", "system"])
        else:
            path_category = random.choice(list(self.FIM_PATHS.keys()))

        if path_category == "critical":
            file_path = random.choice(self.FIM_PATHS["critical"])
        elif path_category == "system":
            base = random.choice(self.FIM_PATHS["system"])
            file_path = f"{base}malicious.service" if is_malicious else f"{base}app.service"
        else:
            base = random.choice(self.FIM_PATHS["binaries"])
            file_path = f"{base}{'evil' if is_malicious else 'app'}"

        action = random.choice(["created", "updated", "deleted", "attributes_modified"])

        event.update(
            {
                "event": {
                    "kind": "event",
                    "module": "file_integrity",
                    "dataset": "file_integrity",
                    "category": ["file"],
                    "type": [action.replace("attributes_modified", "change")],
                    "action": action,
                    "id": self.randomizer.generate_uuid(),
                },
                "file": {
                    "path": file_path,
                    "name": file_path.split("/")[-1],
                    "directory": "/".join(file_path.split("/")[:-1]),
                    "extension": file_path.split(".")[-1] if "." in file_path else "",
                    "type": "file",
                    "size": random.randint(100, 1024 * 1024),
                    "owner": user.name if user else "root",
                    "group": "root",
                    "mode": "0644" if not is_malicious else "0755",
                    "hash": {
                        "sha256": self.randomizer.generate_hash("sha256"),
                        "sha1": self.randomizer.generate_hash("sha1"),
                        "md5": self.randomizer.generate_hash("md5"),
                    },
                },
            }
        )

        # Add user info
        if user:
            event["user"] = user.to_ecs_dict()
        else:
            username = "root" if not is_malicious else "attacker"
            event["user"] = {"name": username}

        return event

    @register_attack_pattern(
        name="auditbeat-suspicious-process",
        description="Suspicious process execution detected by Auditbeat",
        ttps=["T1059", "T1059.004"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host"],
        optional_params=["user", "count"],
        event_types=["auditbeat"],
        detection_recommendations=[
            "Monitor for unusual process executions from /tmp or /dev/shm",
            "Alert on processes with suspicious names or hashes",
            "Track process lineage for anomalous parent-child relationships",
        ],
    )
    def generate_suspicious_process(
        self,
        host: "Host",
        user: Optional["User"] = None,
        count: int = 5,
    ) -> list[dict[str, Any]]:
        """Generate suspicious process events for detection testing."""
        events = []
        for i in range(count):
            event = self.generate(
                host=host,
                user=user,
                timestamp_offset=count - i,
                dataset="system.process",
                is_malicious=True,
            )
            events.append(event)
        return events

    @register_attack_pattern(
        name="auditbeat-brute-force",
        description="Brute force login attempts detected by Auditbeat",
        ttps=["T1110", "T1110.001"],
        category=GeneratorCategory.IDENTITY,
        required_params=["host"],
        optional_params=["user", "attempts", "source_ip"],
        event_types=["auditbeat"],
        detection_recommendations=[
            "Alert on multiple failed login attempts from the same source",
            "Track failed login patterns across users",
            "Monitor for successful login after multiple failures",
        ],
    )
    def generate_brute_force(
        self,
        host: "Host",
        user: Optional["User"] = None,
        attempts: int = 20,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Generate brute force login events."""
        events = []
        source_ip = source_ip or self.randomizer.generate_ip()

        for i in range(attempts):
            is_last = i == attempts - 1
            event = self._generate_login_event(
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=attempts - i),
                host=host,
                user=user,
                is_malicious=not is_last,  # Last attempt succeeds
                source_ip=source_ip,
            )
            if is_last:
                event["event"]["outcome"] = "success"
            else:
                event["event"]["outcome"] = "failure"
            events.append(event)

        return events

