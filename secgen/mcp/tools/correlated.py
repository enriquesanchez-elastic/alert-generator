"""MCP tools for correlated attack generation."""

import logging
from typing import Any

from secgen.config.settings import get_settings
from secgen.mcp.formatters import format_error_response, format_success_response
from secgen.mcp.state import MCPState

logger = logging.getLogger(__name__)


async def generate_correlated_attack(
    state: MCPState,
    args: dict[str, Any],
) -> str:
    """
    Generate a fully correlated attack chain.

    Creates source Beat events, alerts, attack discovery, and case
    with proper linkage between all components.
    """
    try:
        from secgen.generators.correlated_attack import CorrelatedAttackOrchestrator

        attack_type = args.get("attack_type")
        source_event_count = args.get("source_event_count", 20)
        generate_discovery = args.get("generate_discovery", True)
        generate_case = args.get("generate_case", True)

        settings = get_settings()

        # Get or create world
        world = state.get_or_create_world()

        # Create orchestrator
        orchestrator = CorrelatedAttackOrchestrator(settings, world)

        # Generate attack chain
        result = orchestrator.generate_correlated_attack(
            attack_type=attack_type,
            source_event_count=source_event_count,
            generate_discovery=generate_discovery,
            generate_case=generate_case,
        )

        # Store events in state
        state.add_events(result.source_events)
        state.add_events(result.alerts)

        return format_success_response(
            "correlated_attack_generated",
            {
                "attack_type": result.attack_type,
                "source_events_count": len(result.source_events),
                "alerts_count": len(result.alerts),
                "source_event_ids": result.source_event_ids[:5],  # First 5
                "alert_ids": result.alert_ids,
                "discovery_id": result.discovery_id,
                "case_id": result.case_id,
                "hosts": result.hosts,
                "users": result.users,
                "has_discovery": result.attack_discovery is not None,
                "has_case": result.case is not None,
            },
        )

    except Exception as e:
        logger.error(f"Error generating correlated attack: {e}", exc_info=True)
        return format_error_response(str(e))


async def generate_attack_discovery(
    state: MCPState,
    args: dict[str, Any],
) -> str:
    """
    Generate an Attack Discovery document.

    Creates an AI-style attack discovery analyzing alerts.
    """
    try:
        from secgen.generators.attack_discovery import AttackDiscoveryGenerator
        from secgen.generators.randomizers import RandomDataGenerator

        attack_pattern = args.get("attack_pattern")
        alert_ids = args.get("alert_ids", [])

        # Generate fake alert IDs if none provided
        if not alert_ids:
            randomizer = RandomDataGenerator()
            alert_ids = [randomizer.generate_uuid() for _ in range(5)]

        # Get hosts and users from world if available
        world = state.get_or_create_world()
        hosts = [world.get_random_host()] if world.hosts else None
        users = [world.get_random_user()] if world.users else None

        # Generate discovery
        generator = AttackDiscoveryGenerator()
        discovery = generator.generate(
            attack_pattern=attack_pattern,
            alert_ids=alert_ids,
            hosts=hosts,
            users=users,
        )

        return format_success_response(
            "attack_discovery_generated",
            {
                "discovery_id": discovery.id,
                "title": discovery.title,
                "summary": discovery.summary_markdown[:200] + "..." if len(discovery.summary_markdown) > 200 else discovery.summary_markdown,
                "alert_ids": discovery.alert_ids,
                "mitre_tactics": discovery.mitre_attack_tactics,
                "mitre_techniques": discovery.mitre_attack_techniques,
                "risk_score": discovery.risk_score,
                "status": discovery.status,
            },
        )

    except Exception as e:
        logger.error(f"Error generating attack discovery: {e}", exc_info=True)
        return format_error_response(str(e))


async def generate_case(
    state: MCPState,
    args: dict[str, Any],
) -> str:
    """
    Generate a Security Case.

    Creates a case for investigation with optional alert attachments.
    """
    try:
        from secgen.generators.case import CaseGenerator

        template = args.get("template")
        title = args.get("title")
        severity = args.get("severity", "medium")
        alert_ids = args.get("alert_ids", [])
        discovery_ids = args.get("attack_discovery_ids", [])

        # Get assignee from world if available
        world = state.get_or_create_world()
        assignees = []
        if world.users:
            user = world.get_random_user()
            assignees = [user.name]

        # Generate case
        generator = CaseGenerator()
        case = generator.generate(
            template=template,
            title=title,
            severity=severity,
            assignees=assignees,
            alert_ids=alert_ids,
            attack_discovery_ids=discovery_ids,
        )

        return format_success_response(
            "case_generated",
            {
                "case_id": case.id,
                "title": case.title,
                "description": case.description[:200] + "..." if len(case.description) > 200 else case.description,
                "status": case.status,
                "severity": case.severity,
                "tags": case.tags,
                "assignees": case.assignees,
                "total_alerts": case.total_alerts,
                "total_comments": case.total_comments,
                "attack_discovery_ids": case.attack_discovery_ids,
            },
        )

    except Exception as e:
        logger.error(f"Error generating case: {e}", exc_info=True)
        return format_error_response(str(e))


async def generate_beat_events(
    state: MCPState,
    args: dict[str, Any],
) -> str:
    """
    Generate Beat-format events (Auditbeat, Packetbeat, Filebeat).

    Creates events matching the format of Elastic Beats.
    """
    try:
        beat_type = args.get("beat_type")
        count = args.get("count", 20)
        is_malicious = args.get("is_malicious", False)
        dataset = args.get("dataset")

        # Get world for entity correlation
        world = state.get_or_create_world()
        host = world.get_random_host() if world.hosts else None
        user = world.get_random_user() if world.users else None

        # Select appropriate generator
        if beat_type == "auditbeat":
            from secgen.generators.beats.auditbeat import AuditbeatEventGenerator
            generator = AuditbeatEventGenerator()
        elif beat_type == "packetbeat":
            from secgen.generators.beats.packetbeat import PacketbeatEventGenerator
            generator = PacketbeatEventGenerator()
        elif beat_type == "filebeat":
            from secgen.generators.beats.filebeat import FilebeatEventGenerator
            generator = FilebeatEventGenerator()
        else:
            return format_error_response(f"Unknown beat type: {beat_type}")

        # Generate events
        kwargs: dict[str, Any] = {"is_malicious": is_malicious}
        if dataset:
            kwargs["dataset"] = dataset

        events = generator.generate_batch(
            count=count,
            host=host,
            user=user,
            **kwargs,
        )

        # Store in state
        state.add_events(events)

        # Get sample event IDs
        event_ids = [e.get("event", {}).get("id", "")[:8] for e in events[:5]]

        return format_success_response(
            "beat_events_generated",
            {
                "beat_type": beat_type,
                "count": len(events),
                "is_malicious": is_malicious,
                "dataset": dataset or "various",
                "sample_event_ids": event_ids,
                "index_pattern": f"{beat_type}-*",
                "host": host.name if host else "random",
                "user": user.name if user else "random",
            },
        )

    except Exception as e:
        logger.error(f"Error generating beat events: {e}", exc_info=True)
        return format_error_response(str(e))

