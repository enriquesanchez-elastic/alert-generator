"""Campaign generator for creating correlated attack campaigns."""

import random
from typing import List, Optional

from alerts_generator.generators.randomizers import RandomDataGenerator
from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import Scenario


class CampaignGenerator:
    """Generator for creating attack campaigns with shared infrastructure."""

    C2_DOMAINS = [
        "evil-c2.badactor.com",
        "command.malicious.net",
        "control.darkweb.org",
        "payload.threat.xyz",
        "backdoor.attacker.io",
    ]

    MALWARE_FAMILIES = [
        "RedTeam-Ransomware",
        "APT-Backdoor",
        "CryptoMiner-XMR",
        "WebShell-PHP",
        "Trojan-Stealer",
        "Rootkit-Advanced",
    ]

    PHASE_SCENARIOS = {
        "initial": ["Web Shell Deployment", "Backdoor Installation"],
        "execution": [
            "Crypto Miner",
            "Ransomware",
            "Privilege Escalation",
            "Backdoor Installation",
        ],
        "lateral": [
            "Lateral Movement",
            "Privilege Escalation",
            "Backdoor Installation",
        ],
        "exfiltration": ["Data Exfiltration", "Ransomware"],
    }

    def __init__(self, randomizer: Optional[RandomDataGenerator] = None) -> None:
        """
        Initialize campaign generator.

        Args:
            randomizer: Optional RandomDataGenerator instance (creates new if None)
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(self, num_hosts: int) -> Campaign:
        """
        Generate a new attack campaign with shared infrastructure.

        Args:
            num_hosts: Number of hosts to target in this campaign

        Returns:
            Campaign object with generated attributes
        """
        campaign_id = self.randomizer.generate_uuid()[:8]

        # Generate attacker infrastructure
        attacker_ip = f"203.0.113.{random.randint(1, 254)}"  # TEST-NET-3
        c2_domain = random.choice(self.C2_DOMAINS)
        c2_ip = f"198.51.100.{random.randint(1, 254)}"  # TEST-NET-2
        malware_family = random.choice(self.MALWARE_FAMILIES)

        # Generate target hosts
        target_hosts = [self.randomizer.generate_hostname() for _ in range(num_hosts)]

        # Base hash for malware variants (same family, slight variations)
        file_hash_base = self.randomizer.generate_hash("md5")[:20]

        return Campaign(
            id=campaign_id,
            attacker_ip=attacker_ip,
            c2_domain=c2_domain,
            c2_ip=c2_ip,
            malware_family=malware_family,
            target_hosts=target_hosts,
            file_hash_base=file_hash_base,
        )

    def select_scenario_for_phase(self, phase: str, scenarios: List[Scenario]) -> Scenario:
        """
        Select an appropriate scenario for the campaign phase.

        Args:
            phase: Attack phase ('initial', 'execution', 'lateral', 'exfiltration')
            scenarios: List of available scenarios

        Returns:
            Selected scenario
        """
        # Get preferred scenario names for this phase
        preferred_names = self.PHASE_SCENARIOS.get(phase, [])

        # Filter scenarios by preferred names
        preferred = [s for s in scenarios if s.name in preferred_names]

        # If no preferred scenarios match, use any
        if not preferred:
            preferred = scenarios

        return random.choice(preferred)

    def determine_phase(self, index: int, total: int) -> str:
        """
        Determine attack phase based on alert progress.

        Args:
            index: Current alert index (0-based)
            total: Total number of alerts

        Returns:
            Phase name: 'initial', 'execution', 'lateral', or 'exfiltration'
        """
        progress = index / total
        if progress < 0.1:
            return "initial"
        elif progress < 0.4:
            return "execution"
        elif progress < 0.8:
            return "lateral"
        else:
            return "exfiltration"
