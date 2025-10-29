"""Campaign model representing correlated attack campaigns."""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Campaign:
    """
    Represents a correlated attack campaign across multiple hosts.

    Attributes:
        id: Unique campaign identifier (8-character string)
        attacker_ip: Common attacker IP address used across campaign
        c2_domain: Command and control domain
        c2_ip: Command and control IP address
        malware_family: Malware family name
        target_hosts: List of target hostnames
        file_hash_base: Base hash prefix for related malware variants
    """

    id: str
    attacker_ip: str
    c2_domain: str
    c2_ip: str
    malware_family: str
    target_hosts: List[str]
    file_hash_base: str

    def __post_init__(self) -> None:
        """Validate campaign attributes."""
        if not self.id:
            raise ValueError("Campaign ID cannot be empty")
        if not self.attacker_ip:
            raise ValueError("Attacker IP cannot be empty")
        if not self.target_hosts:
            raise ValueError("Campaign must have at least one target host")
