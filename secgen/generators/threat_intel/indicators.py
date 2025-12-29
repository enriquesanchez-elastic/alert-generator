"""Threat indicator generator for creating coordinated IOCs."""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

IndicatorType = Literal["ip", "domain", "url", "file_hash_md5", "file_hash_sha256", "email"]


@register_event_type(
    name="threat-indicator",
    category=GeneratorCategory.THREAT_INTEL,
    description="Threat indicators (IOCs) for indicator match rule testing",
    ecs_fields=[
        "threat.indicator.type",
        "threat.indicator.ip",
        "threat.indicator.url.full",
        "threat.indicator.file.hash.sha256",
        "threat.feed.name",
    ],
    index_pattern="logs-ti_util.logs-default",
    example_params={"indicator_type": "ip", "threat_type": "c2"},
)
class ThreatIndicatorGenerator:
    """
    Generator for creating threat indicators that match generated events.

    Creates coordinated IOCs that will trigger indicator match rules when
    correlated with generated network, DNS, and file events.

    Supports:
    - IP address indicators
    - Domain indicators
    - URL indicators
    - File hash indicators (MD5, SHA256)
    - Email address indicators
    """

    # Threat indicator feeds
    INDICATOR_FEEDS = [
        "AlienVault OTX",
        "Abuse.ch",
        "MalwareBazaar",
        "URLhaus",
        "ThreatFox",
        "MISP",
        "Custom Feed",
    ]

    # Threat types
    THREAT_TYPES = [
        "malware",
        "c2",
        "phishing",
        "exploit",
        "botnet",
        "ransomware",
        "apt",
        "cryptominer",
    ]

    # Confidence levels
    CONFIDENCE_LEVELS = ["Low", "Medium", "High"]

    # TLP markings
    TLP_MARKINGS = ["WHITE", "GREEN", "AMBER", "RED"]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize threat indicator generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()
        # Store generated indicators for coordination
        self._generated_indicators: dict[str, list[str]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "file_hash_md5": [],
            "file_hash_sha256": [],
            "email": [],
        }

    def generate(
        self,
        indicator_type: IndicatorType,
        indicator_value: str | None = None,
        threat_type: str | None = None,
        feed_name: str | None = None,
        confidence: str | None = None,
        tlp: str | None = None,
        timestamp_offset: int = 0,
        description: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single threat indicator.

        Args:
            indicator_type: Type of indicator (ip, domain, url, file_hash_md5, etc.)
            indicator_value: The indicator value (generated if not provided)
            threat_type: Type of threat
            feed_name: Source feed name
            confidence: Confidence level
            tlp: TLP marking
            timestamp_offset: Minutes to offset timestamp
            description: Indicator description

        Returns:
            ECS-compliant threat indicator event
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Generate indicator value if not provided
        if indicator_value is None:
            indicator_value = self._generate_indicator_value(indicator_type)

        # Store for coordination
        self._generated_indicators[indicator_type].append(indicator_value)

        # Set defaults
        if threat_type is None:
            threat_type = random.choice(self.THREAT_TYPES)
        if feed_name is None:
            feed_name = random.choice(self.INDICATOR_FEEDS)
        if confidence is None:
            confidence = random.choice(self.CONFIDENCE_LEVELS)
        if tlp is None:
            tlp = random.choice(self.TLP_MARKINGS)
        if description is None:
            description = f"Known {threat_type} indicator from {feed_name}"

        # Map indicator type to ECS field
        indicator_field = self._get_indicator_field(indicator_type)

        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "enrichment",
                "category": ["threat"],
                "type": ["indicator"],
                "dataset": "ti_util.logs",
                "id": self.randomizer.generate_uuid(),
            },
            "threat": {
                "indicator": {
                    "type": self._map_to_stix_type(indicator_type),
                    indicator_field: indicator_value,
                    "description": description,
                    "confidence": confidence,
                    "provider": feed_name,
                    "first_seen": (now - timedelta(days=random.randint(1, 365))).isoformat(),
                    "last_seen": timestamp,
                    "marking": {
                        "tlp": tlp,
                    },
                },
                "feed": {
                    "name": feed_name,
                },
            },
            "tags": [threat_type, f"tlp:{tlp.lower()}", feed_name.lower().replace(" ", "_")],
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "ti_util.logs",
                "namespace": "default",
            },
        }

        # Add hash-specific fields
        if indicator_type in ["file_hash_md5", "file_hash_sha256"]:
            hash_type = indicator_type.replace("file_hash_", "")
            event["threat"]["indicator"]["file"] = {
                "hash": {
                    hash_type: indicator_value,
                },
            }

        return event

    def _generate_indicator_value(self, indicator_type: IndicatorType) -> str:
        """Generate an indicator value based on type."""
        if indicator_type == "ip":
            # Generate public IP (TEST-NET ranges for testing)
            return f"203.0.113.{random.randint(1, 254)}"
        elif indicator_type == "domain":
            names = ["malware", "c2", "phish", "evil", "badactor", "threat"]
            tlds = [".com", ".net", ".org", ".xyz", ".top", ".info"]
            return f"{random.choice(names)}{random.randint(1, 999)}{random.choice(tlds)}"
        elif indicator_type == "url":
            domain = self._generate_indicator_value("domain")
            paths = ["/download", "/payload", "/shell", "/update", "/config"]
            return f"https://{domain}{random.choice(paths)}"
        elif indicator_type == "file_hash_md5":
            return self.randomizer.generate_hash("md5")
        elif indicator_type == "file_hash_sha256":
            return self.randomizer.generate_hash("sha256")
        elif indicator_type == "email":
            names = ["phisher", "attacker", "scammer", "malware"]
            domains = ["evil.com", "badactor.net", "phish.org"]
            return f"{random.choice(names)}{random.randint(1, 99)}@{random.choice(domains)}"
        return ""

    def _get_indicator_field(self, indicator_type: IndicatorType) -> str:
        """Map indicator type to ECS field name."""
        field_map = {
            "ip": "ip",
            "domain": "domain",
            "url": "url.full",
            "file_hash_md5": "file.hash.md5",
            "file_hash_sha256": "file.hash.sha256",
            "email": "email.address",
        }
        return field_map.get(indicator_type, "value")

    def _map_to_stix_type(self, indicator_type: IndicatorType) -> str:
        """Map indicator type to STIX type."""
        stix_map = {
            "ip": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "file_hash_md5": "file",
            "file_hash_sha256": "file",
            "email": "email-addr",
        }
        return stix_map.get(indicator_type, "unknown")

    def generate_batch(
        self,
        count: int,
        indicator_types: list[IndicatorType] | None = None,
        timestamp_spread_minutes: int = 1440,  # 24 hours
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of threat indicators.

        Args:
            count: Number of indicators to generate
            indicator_types: Types to generate (random if not specified)
            timestamp_spread_minutes: Time spread for indicators

        Returns:
            List of indicator events
        """
        events = []

        if indicator_types is None:
            indicator_types = ["ip", "domain", "url", "file_hash_md5", "file_hash_sha256"]

        for i in range(count):
            indicator_type = random.choice(indicator_types)
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                indicator_type=indicator_type,
                timestamp_offset=timestamp_offset,
            )
            events.append(event)

        return events

    def generate_coordinated_iocs(
        self,
        c2_domain: str,
        c2_ip: str,
        malware_hashes: list[str],
        threat_actor: str = "APT29",
        campaign_name: str = "Operation Dark Eagle",
    ) -> list[dict[str, Any]]:
        """
        Generate coordinated IOCs for a campaign.

        Creates a set of related indicators that will match
        generated campaign events.

        Args:
            c2_domain: C2 domain to create indicator for
            c2_ip: C2 IP address
            malware_hashes: List of malware file hashes
            threat_actor: Threat actor name
            campaign_name: Campaign name

        Returns:
            List of coordinated indicator events
        """
        events = []
        description_base = f"{threat_actor} - {campaign_name}"

        # C2 domain indicator
        domain_event = self.generate(
            indicator_type="domain",
            indicator_value=c2_domain,
            threat_type="c2",
            confidence="High",
            description=f"{description_base} - C2 domain",
        )
        events.append(domain_event)

        # C2 IP indicator
        ip_event = self.generate(
            indicator_type="ip",
            indicator_value=c2_ip,
            threat_type="c2",
            confidence="High",
            description=f"{description_base} - C2 IP address",
        )
        events.append(ip_event)

        # C2 URL indicator
        url_event = self.generate(
            indicator_type="url",
            indicator_value=f"https://{c2_domain}/beacon",
            threat_type="c2",
            confidence="High",
            description=f"{description_base} - C2 beacon URL",
        )
        events.append(url_event)

        # Malware hash indicators
        for hash_value in malware_hashes:
            hash_type: IndicatorType = (
                "file_hash_sha256" if len(hash_value) == 64 else "file_hash_md5"
            )
            hash_event = self.generate(
                indicator_type=hash_type,
                indicator_value=hash_value,
                threat_type="malware",
                confidence="High",
                description=f"{description_base} - Malware sample",
            )
            events.append(hash_event)

        return events

    def get_generated_indicators(self) -> dict[str, list[str]]:
        """
        Get all generated indicator values for coordination with events.

        Returns:
            Dictionary of indicator_type -> list of values
        """
        return self._generated_indicators.copy()

    def clear_generated_indicators(self) -> None:
        """Clear stored generated indicators."""
        for key in self._generated_indicators:
            self._generated_indicators[key] = []

    def generate_from_events(
        self,
        dns_events: list[dict[str, Any]] | None = None,
        network_events: list[dict[str, Any]] | None = None,
        file_events: list[dict[str, Any]] | None = None,
        match_ratio: float = 0.3,
    ) -> list[dict[str, Any]]:
        """
        Generate threat indicators that will match existing events.

        Extracts IOCs from generated events and creates indicators
        for a subset of them.

        Args:
            dns_events: List of DNS events to extract domains from
            network_events: List of network events to extract IPs from
            file_events: List of file events to extract hashes from
            match_ratio: Ratio of events to create matching indicators for

        Returns:
            List of indicator events
        """
        events = []

        # Extract and create domain indicators from DNS events
        if dns_events:
            domains = [
                e.get("dns", {}).get("question", {}).get("name")
                for e in dns_events
                if e.get("dns", {}).get("question", {}).get("name")
            ]
            sample_size = max(1, int(len(domains) * match_ratio))
            for domain in random.sample(domains, min(sample_size, len(domains))):
                event = self.generate(
                    indicator_type="domain",
                    indicator_value=domain,
                    threat_type="malware",
                )
                events.append(event)

        # Extract and create IP indicators from network events
        if network_events:
            ips = [
                e.get("destination", {}).get("ip")
                for e in network_events
                if e.get("destination", {}).get("ip")
            ]
            sample_size = max(1, int(len(ips) * match_ratio))
            for ip in random.sample(ips, min(sample_size, len(ips))):
                event = self.generate(
                    indicator_type="ip",
                    indicator_value=ip,
                    threat_type="c2",
                )
                events.append(event)

        # Extract and create hash indicators from file events
        if file_events:
            hashes = []
            for e in file_events:
                file_hash = e.get("file", {}).get("hash", {})
                if file_hash.get("sha256"):
                    hashes.append(("file_hash_sha256", file_hash["sha256"]))
                elif file_hash.get("md5"):
                    hashes.append(("file_hash_md5", file_hash["md5"]))

            sample_size = max(1, int(len(hashes) * match_ratio))
            for hash_type, hash_value in random.sample(hashes, min(sample_size, len(hashes))):
                event = self.generate(
                    indicator_type=hash_type,
                    indicator_value=hash_value,
                    threat_type="malware",
                )
                events.append(event)

        return events
