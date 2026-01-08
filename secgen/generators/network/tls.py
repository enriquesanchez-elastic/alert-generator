"""TLS event generator for creating ECS-compliant TLS/SSL events with JA3 fingerprints."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host


@register_event_type(
    name="tls",
    category=GeneratorCategory.NETWORK,
    description="TLS/SSL events with JA3 fingerprints for malware detection",
    ecs_fields=[
        "tls.version",
        "tls.cipher",
        "tls.client.ja3",
        "tls.server.ja3s",
        "tls.server.certificate",
    ],
    index_pattern="logs-network_traffic.tls-default",
    example_params={"is_malicious": True},
)
class TLSEventGenerator:
    """
    Generator for creating ECS-compliant TLS/SSL events.

    TLS events with JA3/JA3S fingerprints are critical for detecting:
    - Malware families by TLS fingerprint
    - C2 communications
    - Man-in-the-middle attacks
    - Suspicious certificate usage
    - Protocol downgrade attacks
    """

    # TLS versions
    TLS_VERSIONS = ["1.2", "1.3"]

    # Common cipher suites
    CIPHER_SUITES = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ]

    # Known malware JA3 fingerprints (examples - real ones would be from threat intel)
    MALICIOUS_JA3 = [
        "51c64c77e60f3980eea90869b68c58a8",  # Generic malware
        "bd0bf25947d4a37404f0424edf4db9ad",  # CobaltStrike
        "a0e9f5d64349fb13191bc781f81f42e1",  # Metasploit
        "3b5074b1b5d032e5620f69f9f700ff0e",  # TrickBot
        "72a589da586844d7f0818ce684948eea",  # Emotet
    ]

    # Legitimate JA3 fingerprints
    LEGITIMATE_JA3 = [
        "b32309a26951912be7dba376398abc3b",  # Chrome
        "eb1d94daa7e0344597e756a1fb6e7054",  # Firefox
        "42a799c2ec4d0b7d2d9af89c5a7c3a36",  # Safari
        "e7d705a3286e19ea42f587b344ee6865",  # Edge
    ]

    # Common certificate issuers
    CERTIFICATE_ISSUERS = [
        "DigiCert Inc",
        "Let's Encrypt",
        "Sectigo Limited",
        "GlobalSign nv-sa",
        "Comodo CA Limited",
        "Amazon",
        "Google Trust Services LLC",
    ]

    # Suspicious certificate issuers
    SUSPICIOUS_ISSUERS = [
        "Self-signed",
        "Unknown CA",
        "localhost",
        "",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize TLS event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        server_name: str | None = None,
        host: Optional["Host"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        ja3: str | None = None,
        ja3s: str | None = None,
        tls_version: str | None = None,
        cipher: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single TLS event.

        Args:
            server_name: Server name (SNI)
            host: Optional Host entity
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious characteristics
            ja3: Client JA3 fingerprint
            ja3s: Server JA3S fingerprint
            tls_version: TLS version
            cipher: Cipher suite

        Returns:
            ECS-compliant TLS event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Set defaults
        if server_name is None:
            server_name = f"{'malicious' if is_malicious else 'www.example'}.com"

        if tls_version is None:
            tls_version = random.choice(self.TLS_VERSIONS)

        if cipher is None:
            cipher = random.choice(self.CIPHER_SUITES)

        if ja3 is None:
            ja3 = random.choice(self.MALICIOUS_JA3 if is_malicious else self.LEGITIMATE_JA3)

        if ja3s is None:
            ja3s = self.randomizer.generate_hash("md5")

        # Generate IPs
        if host:
            source_ip = random.choice(host.ip)
        else:
            source_ip = self.randomizer.generate_ip()
        destination_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Generate certificate info
        cert_issuer = random.choice(
            self.SUSPICIOUS_ISSUERS if is_malicious else self.CERTIFICATE_ISSUERS
        )
        cert_not_before = (now - timedelta(days=random.randint(1, 365))).isoformat()
        cert_not_after = (now + timedelta(days=random.randint(30, 365))).isoformat()

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["connection", "protocol"],
                "action": "tls-handshake",
                "outcome": "success",
                "id": self.randomizer.generate_uuid(),
            },
            "tls": {
                "version": tls_version,
                "version_protocol": "tls",
                "cipher": cipher,
                "established": True,
                "resumed": random.choice([True, False]),
                "client": {
                    "ja3": ja3,
                    "server_name": server_name,
                    "supported_ciphers": random.sample(self.CIPHER_SUITES, 3),
                },
                "server": {
                    "ja3s": ja3s,
                    "certificate": self.randomizer.generate_hash("sha256"),
                    "certificate_chain": [self.randomizer.generate_hash("sha256")],
                    "hash": {
                        "sha256": self.randomizer.generate_hash("sha256"),
                        "sha1": self.randomizer.generate_hash("sha1"),
                    },
                    "issuer": cert_issuer,
                    "subject": server_name,
                    "not_before": cert_not_before,
                    "not_after": cert_not_after,
                    "x509": {
                        "issuer": {
                            "common_name": cert_issuer,
                            "organization": [cert_issuer],
                        },
                        "subject": {
                            "common_name": server_name,
                        },
                        "serial_number": str(random.randint(10000000, 99999999)),
                        "version_number": 3,
                    },
                },
            },
            "source": {
                "ip": source_ip,
                "port": random.randint(49152, 65535),
            },
            "destination": {
                "ip": destination_ip,
                "port": 443,
                "domain": server_name,
            },
            "network": {
                "transport": "tcp",
                "protocol": "tls",
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "network_traffic.tls",
                "namespace": "default",
            },
        }

        # Add host information
        if host:
            event["host"] = host.to_ecs_dict()

        # Add related fields
        event["related"] = {
            "ip": [source_ip, destination_ip],
            "hosts": [server_name],
            "hash": [ja3, ja3s],
        }

        return event

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Generate a batch of TLS events."""
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

    def generate_c2_tls_session(
        self,
        host: "Host",
        c2_domain: str,
        malware_ja3: str,
        session_count: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate C2 TLS session events.

        Args:
            host: Infected host
            c2_domain: C2 server domain
            malware_ja3: Malware's JA3 fingerprint
            session_count: Number of sessions

        Returns:
            List of TLS events
        """
        events = []

        for i in range(session_count):
            event = self.generate(
                server_name=c2_domain,
                host=host,
                timestamp_offset=session_count - i,
                is_malicious=True,
                ja3=malware_ja3,
            )
            events.append(event)

        return events

    def generate_self_signed_certificate(
        self,
        host: "Host",
        server_name: str,
    ) -> dict[str, Any]:
        """
        Generate TLS event with self-signed certificate.

        Args:
            host: Client host
            server_name: Server name

        Returns:
            TLS event with suspicious self-signed cert
        """
        event = self.generate(
            server_name=server_name,
            host=host,
            is_malicious=True,
        )

        # Override with self-signed indicators
        event["tls"]["server"]["issuer"] = server_name  # Issuer equals subject
        event["tls"]["server"]["x509"]["issuer"]["common_name"] = server_name
        event["tls"]["server"]["x509"]["issuer"]["organization"] = ["Self-signed"]

        return event
