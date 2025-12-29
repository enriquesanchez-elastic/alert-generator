"""Network flow generator for creating ECS-compliant network flow events with geo-enrichment."""

import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host

NetworkDirection = Literal["inbound", "outbound", "internal", "external"]


@register_event_type(
    name="network-flow",
    category=GeneratorCategory.NETWORK,
    description="Network flow events with geo-enrichment for Network Map visualization",
    ecs_fields=[
        "source.ip",
        "source.geo.location",
        "destination.ip",
        "destination.geo.location",
        "network.bytes",
        "network.community_id",
    ],
    index_pattern="logs-network_traffic.flow-default",
    example_params={"direction": "outbound", "is_malicious": False},
)
class NetworkFlowGenerator:
    """
    Generator for creating ECS-compliant network flow events.

    Network flows are critical for:
    - Network Map visualization (requires geo.location)
    - Traffic analysis and anomaly detection
    - DDoS detection
    - Data exfiltration detection
    - Cross-tool correlation via community_id
    """

    # Geographic locations with realistic geo_point coordinates
    GEO_LOCATIONS = [
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "region_name": "Washington",
            "city_name": "Seattle",
            "location": {"lat": 47.6062, "lon": -122.3321},
            "as_org": "Amazon.com, Inc.",
        },
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "region_name": "California",
            "city_name": "San Francisco",
            "location": {"lat": 37.7749, "lon": -122.4194},
            "as_org": "Google LLC",
        },
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "region_name": "Virginia",
            "city_name": "Ashburn",
            "location": {"lat": 39.0438, "lon": -77.4874},
            "as_org": "Amazon.com, Inc.",
        },
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "region_name": "New York",
            "city_name": "New York",
            "location": {"lat": 40.7128, "lon": -74.0060},
            "as_org": "Verizon Business",
        },
        {
            "country_name": "United Kingdom",
            "country_iso_code": "GB",
            "region_name": "England",
            "city_name": "London",
            "location": {"lat": 51.5074, "lon": -0.1278},
            "as_org": "BT",
        },
        {
            "country_name": "Germany",
            "country_iso_code": "DE",
            "region_name": "Hesse",
            "city_name": "Frankfurt",
            "location": {"lat": 50.1109, "lon": 8.6821},
            "as_org": "Deutsche Telekom AG",
        },
        {
            "country_name": "Netherlands",
            "country_iso_code": "NL",
            "region_name": "North Holland",
            "city_name": "Amsterdam",
            "location": {"lat": 52.3676, "lon": 4.9041},
            "as_org": "DigitalOcean, LLC",
        },
        {
            "country_name": "Singapore",
            "country_iso_code": "SG",
            "region_name": "Singapore",
            "city_name": "Singapore",
            "location": {"lat": 1.3521, "lon": 103.8198},
            "as_org": "Amazon.com, Inc.",
        },
        {
            "country_name": "Japan",
            "country_iso_code": "JP",
            "region_name": "Tokyo",
            "city_name": "Tokyo",
            "location": {"lat": 35.6762, "lon": 139.6503},
            "as_org": "Amazon.com, Inc.",
        },
        {
            "country_name": "Australia",
            "country_iso_code": "AU",
            "region_name": "New South Wales",
            "city_name": "Sydney",
            "location": {"lat": -33.8688, "lon": 151.2093},
            "as_org": "Amazon.com, Inc.",
        },
        {
            "country_name": "Brazil",
            "country_iso_code": "BR",
            "region_name": "São Paulo",
            "city_name": "São Paulo",
            "location": {"lat": -23.5505, "lon": -46.6333},
            "as_org": "Claro S.A.",
        },
        {
            "country_name": "Russia",
            "country_iso_code": "RU",
            "region_name": "Moscow",
            "city_name": "Moscow",
            "location": {"lat": 55.7558, "lon": 37.6173},
            "as_org": "PJSC Rostelecom",
        },
        {
            "country_name": "China",
            "country_iso_code": "CN",
            "region_name": "Beijing",
            "city_name": "Beijing",
            "location": {"lat": 39.9042, "lon": 116.4074},
            "as_org": "Alibaba (US) Technology Co., Ltd.",
        },
        {
            "country_name": "India",
            "country_iso_code": "IN",
            "region_name": "Maharashtra",
            "city_name": "Mumbai",
            "location": {"lat": 19.0760, "lon": 72.8777},
            "as_org": "Reliance Jio Infocomm Limited",
        },
    ]

    # Suspicious country codes
    SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP", "IR"]

    # Common services and their port ranges
    SERVICE_PORTS = {
        "http": [80, 8080, 8000],
        "https": [443, 8443],
        "dns": [53],
        "ssh": [22],
        "rdp": [3389],
        "smtp": [25, 587],
        "ftp": [21, 20],
        "mysql": [3306],
        "postgresql": [5432],
        "mongodb": [27017],
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize network flow generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        source_ip: str | None = None,
        source_geo: dict[str, Any] | None = None,
        destination_ip: str | None = None,
        destination_geo: dict[str, Any] | None = None,
        destination_port: int | None = None,
        transport: str = "tcp",
        host: Optional["Host"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        bytes_in: int | None = None,
        bytes_out: int | None = None,
        duration_ms: int | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single network flow event.

        Args:
            source_ip: Source IP address
            source_geo: Source geographic information
            destination_ip: Destination IP address
            destination_geo: Destination geographic information
            destination_port: Destination port
            transport: Transport protocol (tcp, udp)
            host: Optional Host entity (observer)
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious characteristics
            bytes_in: Bytes received
            bytes_out: Bytes sent
            duration_ms: Flow duration in milliseconds

        Returns:
            ECS-compliant network flow event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Generate source information
        if source_ip is None:
            source_ip = self._generate_public_ip()
        if source_geo is None:
            source_geo = random.choice(self.GEO_LOCATIONS)

        # Generate destination information
        if destination_ip is None:
            destination_ip = self._generate_public_ip()
        if destination_geo is None:
            if is_malicious:
                # Prefer suspicious countries for malicious traffic
                suspicious_geos = [
                    g
                    for g in self.GEO_LOCATIONS
                    if g["country_iso_code"] in self.SUSPICIOUS_COUNTRIES
                ]
                destination_geo = (
                    random.choice(suspicious_geos)
                    if suspicious_geos
                    else random.choice(self.GEO_LOCATIONS)
                )
            else:
                destination_geo = random.choice(self.GEO_LOCATIONS)

        # Generate port
        if destination_port is None:
            destination_port = random.choice([80, 443, 22, 3389, 53])
        source_port = random.randint(49152, 65535)

        # Generate traffic metrics
        if bytes_in is None:
            bytes_in = random.randint(100, 1000000)
        if bytes_out is None:
            bytes_out = random.randint(100, 1000000)
        if duration_ms is None:
            duration_ms = random.randint(100, 300000)

        # Calculate community_id
        community_id = self._generate_community_id(
            source_ip, source_port, destination_ip, destination_port, transport
        )

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["connection", "end"],
                "action": "network_flow",
                "outcome": "success",
                "duration": duration_ms * 1000000,  # Convert to nanoseconds
                "id": self.randomizer.generate_uuid(),
            },
            "network": {
                "transport": transport,
                "type": "ipv4",
                "direction": "external",
                "community_id": community_id,
                "bytes": bytes_in + bytes_out,
                "packets": random.randint(10, 10000),
                "protocol": self._get_protocol(destination_port),
            },
            "source": {
                "ip": source_ip,
                "port": source_port,
                "bytes": bytes_out,
                "packets": random.randint(5, 5000),
                "geo": {
                    "country_name": source_geo["country_name"],
                    "country_iso_code": source_geo["country_iso_code"],
                    "region_name": source_geo.get("region_name", ""),
                    "city_name": source_geo["city_name"],
                    "location": source_geo["location"],  # geo_point for Network Map
                },
                "as": {
                    "organization": {"name": source_geo.get("as_org", "Unknown")},
                    "number": random.randint(1000, 65000),
                },
            },
            "destination": {
                "ip": destination_ip,
                "port": destination_port,
                "bytes": bytes_in,
                "packets": random.randint(5, 5000),
                "geo": {
                    "country_name": destination_geo["country_name"],
                    "country_iso_code": destination_geo["country_iso_code"],
                    "region_name": destination_geo.get("region_name", ""),
                    "city_name": destination_geo["city_name"],
                    "location": destination_geo["location"],  # geo_point for Network Map
                },
                "as": {
                    "organization": {"name": destination_geo.get("as_org", "Unknown")},
                    "number": random.randint(1000, 65000),
                },
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "network_traffic.flow",
                "namespace": "default",
            },
        }

        # Add observer (network device that captured the flow)
        if host:
            event["observer"] = {
                "hostname": host.name,
                "ip": host.ip,
                "type": "firewall",
            }
        else:
            event["observer"] = {
                "hostname": "firewall-01",
                "ip": ["10.0.0.1"],
                "type": "firewall",
            }

        # Add related fields
        event["related"] = {
            "ip": [source_ip, destination_ip],
        }

        return event

    def _generate_public_ip(self) -> str:
        """Generate a realistic public IP address."""
        # Avoid private ranges
        first_octet = random.choice(
            [
                random.randint(1, 9),
                random.randint(11, 126),
                random.randint(128, 191),
                random.randint(193, 223),
            ]
        )
        return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _generate_community_id(
        self,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
        transport: str,
    ) -> str:
        """Generate a network community ID for cross-tool correlation."""
        if source_ip < dest_ip:
            ordered = f"{source_ip}:{source_port}-{dest_ip}:{dest_port}"
        else:
            ordered = f"{dest_ip}:{dest_port}-{source_ip}:{source_port}"

        proto_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(transport, 6)
        data = f"{ordered}:{proto_num}"

        hash_bytes = hashlib.sha1(data.encode()).digest()
        import base64

        return "1:" + base64.b64encode(hash_bytes[:16]).decode()

    def _get_protocol(self, port: int) -> str:
        """Get protocol name from port."""
        for proto, ports in self.SERVICE_PORTS.items():
            if port in ports:
                return proto
        return "unknown"

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of network flow events.

        Args:
            count: Number of events to generate
            host: Optional Host entity
            malicious_ratio: Ratio of malicious events
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of network flow event dictionaries
        """
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                host=host,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            events.append(event)

        return events

    def generate_data_exfiltration(
        self,
        source_ip: str,
        source_geo: dict[str, Any],
        destination_ip: str,
        destination_geo: dict[str, Any],
        total_mb: float = 100.0,
        flow_count: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate data exfiltration flow events.

        Large outbound data transfers to suspicious destinations.

        Args:
            source_ip: Source IP (internal)
            source_geo: Source geo information
            destination_ip: Exfil destination IP
            destination_geo: Destination geo information
            total_mb: Total data to exfiltrate in MB
            flow_count: Number of flows

        Returns:
            List of network flow events
        """
        events = []
        total_bytes = int(total_mb * 1024 * 1024)
        remaining = total_bytes

        for i in range(flow_count):
            if i == flow_count - 1:
                bytes_out = remaining
            else:
                bytes_out = random.randint(
                    remaining // (flow_count - i) // 2, remaining // (flow_count - i)
                )
                remaining -= bytes_out

            timestamp_offset = (flow_count - i) * random.randint(1, 5)

            event = self.generate(
                source_ip=source_ip,
                source_geo=source_geo,
                destination_ip=destination_ip,
                destination_geo=destination_geo,
                destination_port=random.choice([443, 22, 21]),
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                bytes_out=bytes_out,
                bytes_in=random.randint(100, 1000),
                duration_ms=random.randint(10000, 60000),
            )
            events.append(event)

        return events

    def generate_port_scan(
        self,
        source_ip: str,
        source_geo: dict[str, Any],
        target_ip: str,
        target_geo: dict[str, Any],
        port_count: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Generate port scan flow events.

        Many short-lived connections to different ports.

        Args:
            source_ip: Scanner IP
            source_geo: Scanner geo
            target_ip: Target IP
            target_geo: Target geo
            port_count: Number of ports to scan

        Returns:
            List of network flow events
        """
        events = []
        ports = random.sample(range(1, 65535), port_count)

        for i, port in enumerate(ports):
            timestamp_offset = port_count - i

            event = self.generate(
                source_ip=source_ip,
                source_geo=source_geo,
                destination_ip=target_ip,
                destination_geo=target_geo,
                destination_port=port,
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                bytes_out=random.randint(40, 100),  # Small probe packets
                bytes_in=random.randint(0, 100),  # Small or no response
                duration_ms=random.randint(10, 1000),  # Short duration
            )
            events.append(event)

        return events

    def generate_ddos_traffic(
        self,
        target_ip: str,
        target_geo: dict[str, Any],
        target_port: int = 80,
        source_count: int = 100,
        packets_per_source: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Generate DDoS attack flow events.

        Many sources sending traffic to single destination.

        Args:
            target_ip: Target IP being attacked
            target_geo: Target geo information
            target_port: Target port
            source_count: Number of attacking sources
            packets_per_source: Packets from each source

        Returns:
            List of network flow events
        """
        events = []

        for i in range(source_count):
            source_ip = self._generate_public_ip()
            source_geo = random.choice(self.GEO_LOCATIONS)
            timestamp_offset = random.randint(0, 5)

            event = self.generate(
                source_ip=source_ip,
                source_geo=source_geo,
                destination_ip=target_ip,
                destination_geo=target_geo,
                destination_port=target_port,
                transport=random.choice(["tcp", "udp"]),
                timestamp_offset=timestamp_offset,
                is_malicious=True,
                bytes_out=packets_per_source * random.randint(40, 1500),
                bytes_in=random.randint(0, 1000),
                duration_ms=random.randint(1000, 10000),
            )
            events.append(event)

        return events
