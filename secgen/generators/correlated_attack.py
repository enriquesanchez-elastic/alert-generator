"""Correlated attack orchestrator for generating linked security data chains."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.config.settings import Settings
from secgen.core.world import World
from secgen.generators.alert import AlertGenerator
from secgen.generators.attack_discovery import AttackDiscoveryGenerator
from secgen.generators.beats.auditbeat import AuditbeatEventGenerator
from secgen.generators.beats.filebeat import FilebeatEventGenerator
from secgen.generators.beats.packetbeat import PacketbeatEventGenerator
from secgen.generators.case import CaseGenerator
from secgen.generators.randomizers import RandomDataGenerator
from secgen.models.attack_discovery import AttackDiscovery
from secgen.models.case import SecurityCase

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

logger = logging.getLogger(__name__)

AttackType = Literal[
    "brute-force",
    "c2-beacon",
    "dga",
    "lateral-movement",
    "data-exfiltration",
    "malware-drop",
    "ransomware",
    "webshell",
]


@dataclass
class CorrelatedAttackResult:
    """
    Result of a correlated attack generation.

    Contains all linked components: source events, alerts,
    attack discovery, and case.
    """

    attack_type: str
    source_events: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    attack_discovery: AttackDiscovery | None = None
    case: SecurityCase | None = None

    # Correlation IDs
    source_event_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    discovery_id: str = ""
    case_id: str = ""

    # Affected entities
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_type": self.attack_type,
            "source_events_count": len(self.source_events),
            "alerts_count": len(self.alerts),
            "source_event_ids": self.source_event_ids,
            "alert_ids": self.alert_ids,
            "discovery_id": self.discovery_id,
            "case_id": self.case_id,
            "hosts": self.hosts,
            "users": self.users,
            "has_attack_discovery": self.attack_discovery is not None,
            "has_case": self.case is not None,
        }


class CorrelatedAttackOrchestrator:
    """
    Orchestrates generation of fully correlated attack data chains.

    Generates the complete chain:
    1. Source Beat events (Auditbeat, Packetbeat, Filebeat)
    2. Detection alerts linked to source events
    3. Attack Discovery analyzing the alerts
    4. Security Case containing everything

    All components share correlation IDs for proper linkage.
    """

    # Attack type to Beat generator mapping
    ATTACK_BEAT_MAPPING = {
        "brute-force": "auditbeat",
        "c2-beacon": "packetbeat",
        "dga": "packetbeat",
        "lateral-movement": "auditbeat",
        "data-exfiltration": "packetbeat",
        "malware-drop": "auditbeat",
        "webshell": "filebeat",
    }

    def __init__(
        self,
        settings: Settings,
        world: World | None = None,
        randomizer: RandomDataGenerator | None = None,
    ) -> None:
        """
        Initialize the orchestrator.

        Args:
            settings: Application settings
            world: Optional World state for entity correlation
            randomizer: Optional RandomDataGenerator instance
        """
        self.settings = settings
        self.world = world or World()
        self.randomizer = randomizer or RandomDataGenerator()

        # Initialize generators
        self.auditbeat_gen = AuditbeatEventGenerator(self.randomizer)
        self.packetbeat_gen = PacketbeatEventGenerator(self.randomizer)
        self.filebeat_gen = FilebeatEventGenerator(self.randomizer)
        self.alert_gen = AlertGenerator(settings, self.randomizer)
        self.discovery_gen = AttackDiscoveryGenerator(self.randomizer)
        self.case_gen = CaseGenerator(self.randomizer)

    def generate_correlated_attack(
        self,
        attack_type: AttackType,
        source_event_count: int = 20,
        generate_discovery: bool = True,
        generate_case: bool = True,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
    ) -> CorrelatedAttackResult:
        """
        Generate a complete correlated attack chain.

        Args:
            attack_type: Type of attack to simulate
            source_event_count: Number of source events to generate
            generate_discovery: Whether to generate Attack Discovery
            generate_case: Whether to generate a Case
            host: Optional Host entity (auto-generated if not provided)
            user: Optional User entity (auto-generated if not provided)

        Returns:
            CorrelatedAttackResult with all linked components
        """
        logger.info(f"Generating correlated {attack_type} attack chain...")

        result = CorrelatedAttackResult(attack_type=attack_type)

        # Get or create entities
        if not host:
            host = self.world.get_or_create_host(template="workstation")
        if not user:
            user = self.world.get_or_create_user(template="standard")
            self.world.assign_user_to_host(user, host)

        result.hosts = [host.name]
        result.users = [user.name]

        # Step 1: Generate source Beat events
        logger.info(f"Step 1: Generating {source_event_count} source events...")
        source_events = self._generate_source_events(
            attack_type, source_event_count, host, user
        )
        result.source_events = source_events
        result.source_event_ids = [
            e.get("event", {}).get("id", "") for e in source_events
        ]

        # Step 2: Generate alerts linked to source events
        logger.info("Step 2: Generating linked alerts...")
        alerts = self._generate_alerts(attack_type, source_events, host, user)
        result.alerts = alerts
        result.alert_ids = [
            a.get("kibana.alert.uuid", "") for a in alerts
        ]

        # Step 3: Generate Attack Discovery (if requested)
        if generate_discovery and alerts:
            logger.info("Step 3: Generating Attack Discovery...")
            discovery = self._generate_attack_discovery(
                attack_type, alerts, [host], [user]
            )
            result.attack_discovery = discovery
            result.discovery_id = discovery.id

        # Step 4: Generate Case (if requested)
        if generate_case and alerts:
            logger.info("Step 4: Generating Case...")
            case = self._generate_case(
                attack_type,
                alerts,
                result.attack_discovery,
                user,
            )
            result.case = case
            result.case_id = case.id

        logger.info(
            f"Generated attack chain: {len(source_events)} events, "
            f"{len(alerts)} alerts, "
            f"discovery={result.discovery_id[:8] if result.discovery_id else 'N/A'}, "
            f"case={result.case_id[:8] if result.case_id else 'N/A'}"
        )

        return result

    def _generate_source_events(
        self,
        attack_type: AttackType,
        count: int,
        host: "Host",
        user: "User",
    ) -> list[dict[str, Any]]:
        """Generate source Beat events for the attack type."""
        beat_type = self.ATTACK_BEAT_MAPPING.get(attack_type, "auditbeat")

        if beat_type == "auditbeat":
            return self._generate_auditbeat_events(attack_type, count, host, user)
        elif beat_type == "packetbeat":
            return self._generate_packetbeat_events(attack_type, count, host)
        elif beat_type == "filebeat":
            return self._generate_filebeat_events(attack_type, count, host, user)
        else:
            return []

    def _generate_auditbeat_events(
        self,
        attack_type: AttackType,
        count: int,
        host: "Host",
        user: "User",
    ) -> list[dict[str, Any]]:
        """Generate Auditbeat events for the attack type."""
        if attack_type == "brute-force":
            return self.auditbeat_gen.generate_brute_force(
                host=host, user=user, attempts=count
            )
        elif attack_type == "malware-drop":
            return self.auditbeat_gen.generate_suspicious_process(
                host=host, user=user, count=count
            )
        elif attack_type == "lateral-movement":
            # Generate mix of auth and process events
            auth_events = self.auditbeat_gen.generate_batch(
                count=count // 2,
                host=host,
                user=user,
                dataset="system.login",
            )
            process_events = self.auditbeat_gen.generate_batch(
                count=count // 2,
                host=host,
                user=user,
                dataset="system.process",
                is_malicious=True,
            )
            return auth_events + process_events
        else:
            return self.auditbeat_gen.generate_batch(
                count=count, host=host, user=user, is_malicious=True
            )

    def _generate_packetbeat_events(
        self,
        attack_type: AttackType,
        count: int,
        host: "Host",
    ) -> list[dict[str, Any]]:
        """Generate Packetbeat events for the attack type."""
        if attack_type == "c2-beacon":
            return self.packetbeat_gen.generate_c2_beacon(
                host=host, beacon_count=count // 3
            )
        elif attack_type == "dga":
            return self.packetbeat_gen.generate_dga_activity(
                host=host, count=count
            )
        elif attack_type == "data-exfiltration":
            # Generate mix of DNS, HTTP, and flow events
            dns_events = self.packetbeat_gen.generate_batch(
                count=count // 3, host=host, dataset="dns", is_malicious=True
            )
            http_events = self.packetbeat_gen.generate_batch(
                count=count // 3, host=host, dataset="http", is_malicious=True
            )
            flow_events = self.packetbeat_gen.generate_batch(
                count=count // 3, host=host, dataset="flow", is_malicious=True
            )
            return dns_events + http_events + flow_events
        else:
            return self.packetbeat_gen.generate_batch(
                count=count, host=host, is_malicious=True
            )

    def _generate_filebeat_events(
        self,
        attack_type: AttackType,
        count: int,
        host: "Host",
        user: "User",
    ) -> list[dict[str, Any]]:
        """Generate Filebeat events for the attack type."""
        if attack_type == "webshell":
            return self.filebeat_gen.generate_web_attack(
                host=host, count=count
            )
        else:
            return self.filebeat_gen.generate_batch(
                count=count, host=host, user=user, is_malicious=True
            )

    def _generate_alerts(
        self,
        attack_type: AttackType,
        source_events: list[dict[str, Any]],
        host: "Host",
        user: "User",
    ) -> list[dict[str, Any]]:
        """Generate alerts linked to source events."""
        alerts = []

        # Generate 1 alert per ~5 source events (simulating rule triggers)
        alert_count = max(1, len(source_events) // 5)

        # Select source events for alerts
        events_for_alerts = source_events[:alert_count * 5:5]

        for i, source_event in enumerate(events_for_alerts):
            alert = self.alert_gen.generate_from_source_events(
                source_events=[source_event],
                attack_pattern=attack_type,
                host=host,
                user=user,
                timestamp_offset=alert_count - i,
            )
            alerts.append(alert)

        return alerts

    def _generate_attack_discovery(
        self,
        attack_type: AttackType,
        alerts: list[dict[str, Any]],
        hosts: list["Host"],
        users: list["User"],
    ) -> AttackDiscovery:
        """Generate Attack Discovery from alerts."""
        alert_ids = [a.get("kibana.alert.uuid", "") for a in alerts]

        discovery = self.discovery_gen.generate(
            attack_pattern=attack_type,
            alert_ids=alert_ids,
            hosts=hosts,
            users=users,
        )

        return discovery

    def _generate_case(
        self,
        attack_type: AttackType,
        alerts: list[dict[str, Any]],
        discovery: AttackDiscovery | None,
        assignee: "User",
    ) -> SecurityCase:
        """Generate a Case from alerts and discovery."""
        if discovery:
            case = self.case_gen.generate_from_attack_discovery(
                discovery=discovery,
                assignee=assignee,
            )
            # Link case back to discovery for bidirectional navigation
            discovery.link_case(case.id)
        else:
            case = self.case_gen.generate_from_alerts(
                alerts=alerts,
                attack_pattern=attack_type,
                assignee=assignee,
            )

        return case

    def generate_multi_attack_campaign(
        self,
        attack_types: list[AttackType],
        events_per_attack: int = 20,
        shared_host: bool = True,
    ) -> list[CorrelatedAttackResult]:
        """
        Generate a multi-phase attack campaign with multiple attack types.

        Args:
            attack_types: List of attack types to include
            events_per_attack: Number of source events per attack type
            shared_host: Whether attacks share the same host (APT-style)

        Returns:
            List of CorrelatedAttackResult for each attack phase
        """
        results = []

        # Get shared entities if needed
        shared_host_entity = None
        shared_user_entity = None
        if shared_host:
            shared_host_entity = self.world.get_or_create_host(template="workstation")
            shared_user_entity = self.world.get_or_create_user(template="standard")
            self.world.assign_user_to_host(shared_user_entity, shared_host_entity)

        for i, attack_type in enumerate(attack_types):
            logger.info(f"Generating phase {i + 1}/{len(attack_types)}: {attack_type}")

            result = self.generate_correlated_attack(
                attack_type=attack_type,
                source_event_count=events_per_attack,
                generate_discovery=True,
                generate_case=True,
                host=shared_host_entity,
                user=shared_user_entity,
            )
            results.append(result)

        logger.info(f"Generated {len(results)} attack phases in campaign")
        return results

    def get_all_events(
        self,
        result: CorrelatedAttackResult,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Get all events from a result organized by type.

        Args:
            result: CorrelatedAttackResult

        Returns:
            Dictionary mapping event type to list of events
        """
        events: dict[str, list[dict[str, Any]]] = {
            "source_events": result.source_events,
            "alerts": result.alerts,
        }

        if result.attack_discovery:
            events["attack_discovery"] = [result.attack_discovery.to_dict()]

        if result.case:
            events["case"] = [result.case.to_dict()]

        return events

