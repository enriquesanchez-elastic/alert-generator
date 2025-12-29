"""Random data generation utilities."""

import random
import uuid
from typing import Literal

HashType = Literal["md5", "sha1", "sha256"]


class RandomDataGenerator:
    """Utility class for generating random data used in alerts."""

    HOSTNAME_PREFIXES = [
        "web-server",
        "db-prod",
        "app-server",
        "workstation",
        "mail-server",
        "file-server",
        "backup",
        "dev-machine",
        "jenkins",
        "docker-host",
    ]

    USERNAMES = [
        "root",
        "admin",
        "user",
        "postgres",
        "www-data",
        "nobody",
        "system",
        "administrator",
        "service",
        "daemon",
        "operator",
        "victim",
        "analyst",
    ]

    SEVERITY_RISK_MAP = {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99,
    }

    @staticmethod
    def generate_uuid() -> str:
        """Generate a UUID string for identifiers."""
        return str(uuid.uuid4())

    @staticmethod
    def generate_entity_id() -> str:
        """Generate a 10-character entity ID."""
        return str(uuid.uuid4())[:10]

    @staticmethod
    def generate_hostname() -> str:
        """Generate a realistic hostname."""
        prefix = random.choice(RandomDataGenerator.HOSTNAME_PREFIXES)
        suffix = str(random.randint(1, 99)).zfill(2)
        return f"{prefix}-{suffix}"

    @staticmethod
    def generate_ip() -> str:
        """Generate a valid private IP address."""
        ip_ranges = [
            lambda: f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            lambda: f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ]
        return random.choice(ip_ranges)()

    @staticmethod
    def generate_mac() -> str:
        """Generate a valid MAC address."""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

    @staticmethod
    def generate_hash(hash_type: HashType = "md5") -> str:
        """
        Generate a random hash value.

        Args:
            hash_type: Type of hash (md5, sha1, sha256)

        Returns:
            Hex string representing the hash
        """
        length_map = {
            "md5": 16,
            "sha1": 20,
            "sha256": 32,
        }
        length = length_map.get(hash_type, 16)
        return "".join([f"{random.randint(0, 255):02x}" for _ in range(length)])

    @staticmethod
    def generate_username() -> str:
        """Generate a realistic username."""
        return random.choice(RandomDataGenerator.USERNAMES)

    @staticmethod
    def severity_to_risk_score(severity: str) -> int:
        """
        Map severity name to risk score.

        Args:
            severity: Severity level (low, medium, high, critical)

        Returns:
            Risk score (21, 47, 73, or 99)
        """
        return RandomDataGenerator.SEVERITY_RISK_MAP.get(severity.lower(), 47)
