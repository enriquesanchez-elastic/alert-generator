"""Endpoint network event generator for creating ECS-compliant network events with process context."""

import hashlib
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

NetworkDirection = Literal[
    "ingress", "egress", "inbound", "outbound", "internal", "external", "unknown"
]
NetworkTransport = Literal["tcp", "udp", "icmp", "sctp"]


@register_event_type(
    name="endpoint-network",
    category=GeneratorCategory.ENDPOINT,
    description="Endpoint network events with process context for C2 and lateral movement detection",
    ecs_fields=[
        "process.name",
        "process.entity_id",
        "destination.ip",
        "destination.port",
        "network.community_id",
    ],
    index_pattern="logs-endpoint.events.network-default",
    example_params={"direction": "egress", "is_malicious": True},
)
class EndpointNetworkEventGenerator:
    """
    Generator for creating ECS-compliant endpoint network events.

    Endpoint network events provide process context for network connections,
    enabling correlation between network activity and process behavior.
    This is critical for detecting:
    - C2 communications
    - Data exfiltration
    - Lateral movement
    - Malware callbacks
    """

    # Common ports by category
    COMMON_PORTS = {
        "web": [80, 443, 8080, 8443],
        "dns": [53],
        "email": [25, 465, 587, 993, 995],
        "file_transfer": [21, 22, 445, 139],
        "database": [3306, 5432, 1433, 27017, 6379],
        "remote_access": [22, 3389, 5900, 5985, 5986],
        "c2": [4444, 5555, 8888, 9999, 1234, 31337, 12345],
    }

    # Known malicious IPs (documentation ranges for testing)
    MALICIOUS_IPS = [
        "203.0.113.10",  # TEST-NET-3
        "203.0.113.20",
        "203.0.113.30",
        "198.51.100.10",  # TEST-NET-2
        "198.51.100.20",
        "198.51.100.30",
    ]

    # Known C2 domains
    C2_DOMAINS = [
        "evil-c2.badactor.com",
        "command.malicious.net",
        "control.darkweb.org",
        "payload.threat.xyz",
        "backdoor.attacker.io",
        "beacon.apt.net",
        "exfil.data.com",
    ]

    # Common legitimate domains
    LEGITIMATE_DOMAINS = [
        "www.google.com",
        "www.microsoft.com",
        "login.microsoftonline.com",
        "github.com",
        "api.github.com",
        "update.googleapis.com",
        "telemetry.microsoft.com",
    ]

    # Process patterns for network activity
    LEGITIMATE_NETWORK_PROCESSES = {
        "windows": [
            ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
            ("firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"),
            ("msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
            ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
            ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
            ("OneDrive.exe", "C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"),
        ],
        "linux": [
            ("firefox", "/usr/lib/firefox/firefox"),
            ("chrome", "/opt/google/chrome/chrome"),
            ("curl", "/usr/bin/curl"),
            ("wget", "/usr/bin/wget"),
            ("ssh", "/usr/bin/ssh"),
            ("git", "/usr/bin/git"),
        ],
        "macos": [
            ("Safari", "/Applications/Safari.app/Contents/MacOS/Safari"),
            ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            ("curl", "/usr/bin/curl"),
            ("ssh", "/usr/bin/ssh"),
        ],
    }

    # Suspicious processes that shouldn't normally make network connections
    SUSPICIOUS_NETWORK_PROCESSES = {
        "windows": [
            ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
            ("calc.exe", "C:\\Windows\\System32\\calc.exe"),
            ("mspaint.exe", "C:\\Windows\\System32\\mspaint.exe"),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe"),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe"),
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe"),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe"),
        ],
        "linux": [
            ("vi", "/usr/bin/vi"),
            ("nano", "/usr/bin/nano"),
            ("awk", "/usr/bin/awk"),
            ("sed", "/usr/bin/sed"),
        ],
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize endpoint network event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        direction: NetworkDirection | None = None,
        transport: NetworkTransport | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        destination_domain: str | None = None,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        process: Optional["ProcessNode"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        bytes_sent: int | None = None,
        bytes_received: int | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single endpoint network event.

        Args:
            direction: Network direction (egress, ingress, etc.)
            transport: Transport protocol (tcp, udp)
            destination_ip: Optional specific destination IP
            destination_port: Optional specific destination port
            destination_domain: Optional destination domain name
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            process: Optional ProcessNode for process linkage
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious network characteristics
            bytes_sent: Optional bytes sent
            bytes_received: Optional bytes received

        Returns:
            ECS-compliant endpoint network event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Determine OS family
        os_family = "linux"
        if host:
            os_family = host.os.family

        # Set defaults
        if direction is None:
            direction = "egress"
        if transport is None:
            transport = random.choice(["tcp", "udp"])

        # Generate source (local) information
        if host:
            source_ip = random.choice(host.ip)
        else:
            source_ip = self.randomizer.generate_ip()
        source_port = random.randint(49152, 65535)  # Ephemeral ports

        # Generate destination information
        if is_malicious:
            if destination_ip is None:
                destination_ip = random.choice(self.MALICIOUS_IPS)
            if destination_port is None:
                destination_port = random.choice(self.COMMON_PORTS["c2"])
            if destination_domain is None:
                destination_domain = random.choice(self.C2_DOMAINS)
        else:
            if destination_ip is None:
                # Generate a public IP
                destination_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            if destination_port is None:
                destination_port = random.choice(self.COMMON_PORTS["web"])
            if destination_domain is None and random.random() < 0.7:
                destination_domain = random.choice(self.LEGITIMATE_DOMAINS)

        # Generate bytes transferred
        if bytes_sent is None:
            bytes_sent = random.randint(100, 100000)
        if bytes_received is None:
            bytes_received = random.randint(100, 1000000)

        # Calculate community_id for cross-tool correlation
        community_id = self._generate_community_id(
            source_ip, source_port, destination_ip, destination_port, transport
        )

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["connection", "start", "end"],
                "action": "connection_attempted",
                "id": self.randomizer.generate_uuid(),
                "outcome": "success",
                "duration": random.randint(1000000, 60000000000),  # nanoseconds
            },
            "network": {
                "direction": direction,
                "transport": transport,
                "type": "ipv4",
                "community_id": community_id,
                "bytes": bytes_sent + bytes_received,
                "packets": random.randint(5, 1000),
                "protocol": self._get_protocol_from_port(destination_port),
            },
            "source": {
                "ip": source_ip,
                "port": source_port,
                "bytes": bytes_sent,
                "packets": random.randint(2, 500),
            },
            "destination": {
                "ip": destination_ip,
                "port": destination_port,
                "bytes": bytes_received,
                "packets": random.randint(2, 500),
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.network",
                "namespace": "default",
            },
        }

        # Add domain information if available
        if destination_domain:
            event["destination"]["domain"] = destination_domain
            event["dns"] = {
                "question": {
                    "name": destination_domain,
                    "registered_domain": self._extract_registered_domain(destination_domain),
                },
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
                "os": {"family": os_family},
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
                "name": self.randomizer.generate_username(),
                "id": str(random.randint(1000, 65000)),
            }

        # Add process information (critical for endpoint network events)
        if process:
            event["process"] = {
                "entity_id": process.entity_id,
                "pid": process.pid,
                "name": process.name,
                "executable": process.executable,
            }
        else:
            # Generate process based on malicious flag
            proc_name, proc_exe = self._select_process(os_family, is_malicious)
            event["process"] = {
                "entity_id": self.randomizer.generate_entity_id(),
                "pid": random.randint(1000, 65000),
                "name": proc_name,
                "executable": proc_exe,
            }

        # Add related fields for correlation
        related: dict[str, list[str]] = {
            "ip": [source_ip, destination_ip],
        }
        if user:
            related["user"] = user.to_related_user()
        if destination_domain:
            related["hosts"] = [destination_domain]
        event["related"] = related

        return event

    def _generate_community_id(
        self,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
        transport: str,
    ) -> str:
        """
        Generate a network community ID for cross-tool correlation.

        This is a simplified implementation of the Community ID spec.
        """
        # Sort IPs to ensure consistent ordering
        if source_ip < dest_ip:
            ordered = f"{source_ip}:{source_port}-{dest_ip}:{dest_port}"
        else:
            ordered = f"{dest_ip}:{dest_port}-{source_ip}:{source_port}"

        proto_num = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132}.get(transport, 6)
        data = f"{ordered}:{proto_num}"

        # Generate base64-encoded hash
        hash_bytes = hashlib.sha1(data.encode()).digest()
        import base64

        community_id = "1:" + base64.b64encode(hash_bytes[:16]).decode()

        return community_id

    def _get_protocol_from_port(self, port: int) -> str:
        """Determine likely protocol from port number."""
        protocol_map = {
            80: "http",
            443: "https",
            53: "dns",
            22: "ssh",
            21: "ftp",
            25: "smtp",
            110: "pop3",
            143: "imap",
            3389: "rdp",
            445: "smb",
            3306: "mysql",
            5432: "postgresql",
            27017: "mongodb",
        }
        return protocol_map.get(port, "unknown")

    def _extract_registered_domain(self, domain: str) -> str:
        """Extract the registered domain from a full domain name."""
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def _select_process(self, os_family: str, is_malicious: bool) -> tuple:
        """Select an appropriate process for network activity."""
        if is_malicious and os_family in self.SUSPICIOUS_NETWORK_PROCESSES:
            return random.choice(self.SUSPICIOUS_NETWORK_PROCESSES[os_family])
        elif os_family in self.LEGITIMATE_NETWORK_PROCESSES:
            return random.choice(self.LEGITIMATE_NETWORK_PROCESSES[os_family])
        return ("unknown", "/unknown")

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        process: Optional["ProcessNode"] = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of endpoint network events.

        Args:
            count: Number of events to generate
            host: Optional Host entity
            user: Optional User entity
            process: Optional ProcessNode
            malicious_ratio: Ratio of malicious events (0.0-1.0)
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of endpoint network event dictionaries
        """
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                host=host,
                user=user,
                process=process,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="c2-beacon",
        description="Command and control beaconing with regular periodic connections",
        ttps=["T1071.001", "T1573", "T1095"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process", "c2_domain", "c2_ip"],
        optional_params=["beacon_count", "interval_seconds"],
        event_types=["endpoint-network"],
        detection_recommendations=[
            "Regular periodic connections to same destination",
            "Small, consistent payload sizes",
            "Connections from suspicious processes",
        ],
    )
    def generate_c2_beacon(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        c2_domain: str,
        c2_ip: str,
        beacon_count: int = 10,
        interval_seconds: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate C2 beaconing network events.

        Beaconing is characterized by regular, periodic connections
        to the same destination.

        Args:
            host: Host entity
            user: User entity
            process: Process making C2 connections
            c2_domain: C2 domain name
            c2_ip: C2 IP address
            beacon_count: Number of beacon events
            interval_seconds: Interval between beacons

        Returns:
            List of network events representing C2 beaconing
        """
        events = []
        c2_port = random.choice([443, 8443, 8080, 4444])

        for i in range(beacon_count):
            # Add slight jitter to interval
            jitter = random.randint(-5, 5)
            timestamp_offset = (beacon_count - i) * (interval_seconds + jitter) // 60

            # Beacons typically have small, consistent payload sizes
            bytes_sent = random.randint(100, 500)  # Small request
            bytes_received = random.randint(100, 2000)  # Small response

            event = self.generate(
                direction="egress",
                transport="tcp",
                destination_ip=c2_ip,
                destination_port=c2_port,
                destination_domain=c2_domain,
                host=host,
                user=user,
                process=process,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="data-exfiltration",
        description="Data exfiltration with large outbound data transfers",
        ttps=["T1041", "T1048"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user", "process", "exfil_domain", "exfil_ip"],
        optional_params=["data_size_mb"],
        event_types=["endpoint-network"],
        detection_recommendations=[
            "Large outbound data transfers",
            "Unusual data volumes to external IPs",
            "Data transfer patterns outside business hours",
        ],
    )
    def generate_data_exfiltration(
        self,
        host: "Host",
        user: "User",
        process: "ProcessNode",
        exfil_domain: str,
        exfil_ip: str,
        data_size_mb: float = 10.0,
    ) -> list[dict[str, Any]]:
        """
        Generate data exfiltration network events.

        Exfiltration is characterized by large outbound data transfers.

        Args:
            host: Host entity
            user: User entity
            process: Process performing exfiltration
            exfil_domain: Exfiltration destination domain
            exfil_ip: Exfiltration destination IP
            data_size_mb: Total data to exfiltrate in MB

        Returns:
            List of network events representing data exfiltration
        """
        events = []
        total_bytes = int(data_size_mb * 1024 * 1024)
        remaining_bytes = total_bytes

        # Split into multiple connections
        connection_count = random.randint(3, 10)

        for i in range(connection_count):
            if i == connection_count - 1:
                bytes_sent = remaining_bytes
            else:
                bytes_sent = random.randint(
                    remaining_bytes // (connection_count - i) // 2,
                    remaining_bytes // (connection_count - i),
                )
                remaining_bytes -= bytes_sent

            timestamp_offset = (connection_count - i) * random.randint(1, 5)

            event = self.generate(
                direction="egress",
                transport="tcp",
                destination_ip=exfil_ip,
                destination_port=random.choice([443, 22, 21]),
                destination_domain=exfil_domain,
                host=host,
                user=user,
                process=process,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                bytes_sent=bytes_sent,
                bytes_received=random.randint(100, 1000),  # Small acknowledgments
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="lateral-movement",
        description="Lateral movement to another host using remote protocols",
        ttps=["T1021.002", "T1021.001", "T1021.004"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["source_host", "target_ip", "user", "process"],
        optional_params=["protocol"],
        event_types=["endpoint-network"],
        detection_recommendations=[
            "SMB/RDP/SSH connections to internal hosts",
            "Admin tool usage (PsExec, WMI)",
            "Unusual lateral network patterns",
        ],
    )
    def generate_lateral_movement(
        self,
        source_host: "Host",
        target_ip: str,
        user: "User",
        process: "ProcessNode",
        protocol: str = "smb",
    ) -> dict[str, Any]:
        """
        Generate a lateral movement network event.

        Args:
            source_host: Source host entity
            target_ip: Target host IP
            user: User performing lateral movement
            process: Process initiating the connection
            protocol: Protocol used (smb, rdp, ssh, wmi)

        Returns:
            Network event for lateral movement
        """
        protocol_ports = {
            "smb": 445,
            "rdp": 3389,
            "ssh": 22,
            "wmi": 135,
            "winrm": 5985,
            "psexec": 445,
        }

        port = protocol_ports.get(protocol, 445)

        return self.generate(
            direction="egress",
            transport="tcp",
            destination_ip=target_ip,
            destination_port=port,
            host=source_host,
            user=user,
            process=process,
            is_malicious=True,
            bytes_sent=random.randint(1000, 50000),
            bytes_received=random.randint(1000, 100000),
        )
