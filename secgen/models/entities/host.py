"""Host entity model for persistent world state."""

import random
import uuid
from dataclasses import dataclass, field
from typing import Literal

OSFamily = Literal["linux", "windows", "macos"]


@dataclass
class OSInfo:
    """Operating system information for a host."""

    family: OSFamily
    name: str
    full: str
    version: str
    kernel: str | None = None
    platform: str | None = None
    type: str | None = None

    @classmethod
    def linux(cls, distro: str = "Ubuntu", version: str = "22.04") -> "OSInfo":
        """Create Linux OS info."""
        return cls(
            family="linux",
            name="Linux",
            full=f"{distro} {version}",
            version=version,
            kernel="5.15.0-generic",
            platform="linux",
            type="linux",
        )

    @classmethod
    def windows(cls, version: str = "10", build: str = "19045") -> "OSInfo":
        """Create Windows OS info."""
        return cls(
            family="windows",
            name="Windows",
            full=f"Windows {version} Enterprise",
            version=f"{version}.0.{build}",
            kernel=build,
            platform="windows",
            type="windows",
        )

    @classmethod
    def macos(cls, version: str = "14.0") -> "OSInfo":
        """Create macOS OS info."""
        return cls(
            family="macos",
            name="macOS",
            full=f"macOS Sonoma {version}",
            version=version,
            kernel="Darwin 23.0.0",
            platform="darwin",
            type="macos",
        )

    def to_dict(self) -> dict:
        """Convert to ECS-compatible dictionary."""
        result = {
            "family": self.family,
            "name": self.name,
            "full": self.full,
            "version": self.version,
        }
        if self.kernel:
            result["kernel"] = self.kernel
        if self.platform:
            result["platform"] = self.platform
        if self.type:
            result["type"] = self.type
        return result


@dataclass
class Host:
    """
    Host entity representing a machine in the simulated environment.

    This is a persistent entity that maintains consistent identifiers
    across all events generated for this host, enabling proper correlation
    in Elastic Security Solution.

    Attributes:
        id: Persistent host.id (UUID) - primary correlation key
        name: Hostname for display
        ip: List of IP addresses assigned to host
        mac: List of MAC addresses
        os: Operating system information
        architecture: CPU architecture (x86_64, arm64)
        agent_id: Elastic Agent ID for this host
        boot_id: Current boot identifier (scopes process.entity_id)
        domain: Windows domain membership (optional)
        geo: Geographic location information (optional)
    """

    id: str
    name: str
    ip: list[str]
    mac: list[str]
    os: OSInfo
    architecture: str = "x86_64"
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    boot_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    domain: str | None = None
    geo: dict | None = None
    # Entity Analytics fields
    asset_criticality: str | None = None  # low, medium, high, critical
    risk_score: int | None = None  # 0-100

    @classmethod
    def generate(
        cls,
        template: str = "workstation",
        os_family: OSFamily | None = None,
        name_override: str | None = None,
    ) -> "Host":
        """
        Generate a new host based on a template.

        Args:
            template: Host template type (workstation, server, domain_controller, etc.)
            os_family: Override OS family (linux, windows, macos)
            name_override: Override generated hostname

        Returns:
            New Host instance with generated attributes
        """
        host_id = str(uuid.uuid4())

        # Template-based configuration
        templates = {
            "workstation": {
                "prefix": "workstation",
                "os": "windows",
                "arch": "x86_64",
            },
            "linux_workstation": {
                "prefix": "dev-machine",
                "os": "linux",
                "arch": "x86_64",
            },
            "mac_workstation": {
                "prefix": "macbook",
                "os": "macos",
                "arch": "arm64",
            },
            "server": {
                "prefix": "server",
                "os": "linux",
                "arch": "x86_64",
            },
            "web_server": {
                "prefix": "web-server",
                "os": "linux",
                "arch": "x86_64",
            },
            "db_server": {
                "prefix": "db-prod",
                "os": "linux",
                "arch": "x86_64",
            },
            "domain_controller": {
                "prefix": "dc",
                "os": "windows",
                "arch": "x86_64",
            },
            "file_server": {
                "prefix": "file-server",
                "os": "windows",
                "arch": "x86_64",
            },
            "mail_server": {
                "prefix": "mail-server",
                "os": "linux",
                "arch": "x86_64",
            },
            "docker_host": {
                "prefix": "docker-host",
                "os": "linux",
                "arch": "x86_64",
            },
            "jenkins": {
                "prefix": "jenkins",
                "os": "linux",
                "arch": "x86_64",
            },
        }

        config = templates.get(template, templates["workstation"])

        # Generate hostname
        if name_override:
            hostname = name_override
        else:
            suffix = str(random.randint(1, 99)).zfill(2)
            hostname = f"{config['prefix']}-{suffix}"

        # Determine OS
        effective_os = os_family or config["os"]
        if effective_os == "linux":
            os_info = OSInfo.linux()
        elif effective_os == "windows":
            os_info = OSInfo.windows()
        else:
            os_info = OSInfo.macos()

        # Generate IPs (private ranges)
        ip_count = random.randint(1, 3)
        ips = [cls._generate_private_ip() for _ in range(ip_count)]

        # Generate MACs
        macs = [cls._generate_mac() for _ in range(ip_count)]

        return cls(
            id=host_id,
            name=hostname,
            ip=ips,
            mac=macs,
            os=os_info,
            architecture=config.get("arch", "x86_64"),
            domain="CORPORATE" if effective_os == "windows" else None,
        )

    @staticmethod
    def _generate_private_ip() -> str:
        """Generate a valid private IP address."""
        ip_ranges = [
            lambda: f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ]
        return random.choice(ip_ranges)()

    @staticmethod
    def _generate_mac() -> str:
        """Generate a valid MAC address."""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

    def to_ecs_dict(self) -> dict:
        """
        Convert to ECS-compatible host fields dictionary.

        Returns:
            Dictionary with ECS host.* fields
        """
        result = {
            "architecture": self.architecture,
            "hostname": self.name,
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "name": self.name,
            "os": self.os.to_dict(),
        }

        if self.domain:
            result["domain"] = self.domain

        if self.geo:
            result["geo"] = self.geo

        return result

    def to_agent_dict(self) -> dict:
        """
        Convert to ECS-compatible agent fields dictionary.

        Returns:
            Dictionary with ECS agent.* fields
        """
        return {
            "id": self.agent_id,
            "type": "endpoint",
            "version": "8.17.0",
        }

    def reboot(self) -> None:
        """Simulate a host reboot by generating new boot_id."""
        self.boot_id = str(uuid.uuid4())
