"""Generation tools for MCP server.

This module implements tools for generating events and executing attacks:
- generate_events: Generate events by type
- execute_attack: Execute attack patterns
- generate_campaign: Generate correlated attack campaigns
"""

import logging
from typing import Any

from secgen.config.settings import Settings
from secgen.generators.core_operations import (
    AttackExecutionResult,
    GenerationResult,
    execute_attack_pattern,
    generate_events_by_type,
    group_events_by_type,
    map_event_type_to_index,
)
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.mcp import formatters
from secgen.mcp.state import MCPState

logger = logging.getLogger(__name__)


async def handle_tool(
    name: str,
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Route generation tool calls to appropriate handlers.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with tool response
    """
    if name == "generate_events":
        return await _handle_generate_events(arguments, state, settings)
    elif name == "execute_attack":
        return await _handle_execute_attack(arguments, state, settings)
    elif name == "generate_campaign":
        return await _handle_generate_campaign(arguments, state, settings)
    else:
        return formatters.format_error_response(
            error=f"Unknown generation tool: {name}",
            tool=name,
        )


async def _handle_generate_events(
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Handle generate_events tool.

    Args:
        arguments: Tool arguments with event_type (required), count, use_world, params
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with generation result
    """
    try:
        event_type = arguments.get("event_type")
        if not event_type:
            return formatters.format_error_response(
                error="Missing required argument: event_type",
                tool="generate_events",
                suggestion="Provide event type name (e.g., 'dns', 'file', 'process')",
            )

        count = arguments.get("count", 10)
        use_world = arguments.get("use_world", True)
        params = arguments.get("params", {})

        # Validate count
        if count < 1 or count > 10000:
            return formatters.format_error_response(
                error=f"count must be between 1 and 10000, got {count}",
                tool="generate_events",
            )

        # Get or create World state
        world = None
        if use_world:
            world = state.get_or_create_world()

        # Generate events using shared logic
        result: GenerationResult = generate_events_by_type(
            event_type=event_type,
            count=count,
            world=world,
            params=params,
            settings=settings,
        )

        # Track events in state
        state.add_events(result.events)

        # Index if enabled
        indexed = False
        index_pattern = result.index_pattern
        if state.enable_indexing and not state.dry_run:
            try:
                indexer = ElasticsearchIndexer(settings)
                index_type = map_event_type_to_index(event_type)
                index_result = indexer.index_typed_events(result.events, index_type)
                indexed = index_result is not None
                if indexed:
                    logger.info(f"Indexed {len(result.events)} events to {index_pattern}")
            except Exception as e:
                logger.error(f"Failed to index events: {e}")

        logger.info(f"Generated {len(result.events)} {event_type} events")

        return formatters.format_generation_summary(
            event_type=event_type,
            count=len(result.events),
            events_summary={
                "total": result.event_stats.total,
                "by_dataset": result.event_stats.by_dataset,
                "by_type": result.event_stats.by_type,
                "indexed": indexed,
                "index_pattern": index_pattern if indexed else None,
                "dry_run": state.dry_run,
            },
            world_summary=result.world_summary,
        )

    except ValueError as e:
        return formatters.format_error_response(
            error=str(e),
            tool="generate_events",
        )
    except Exception as e:
        logger.error(f"Error generating events: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="generate_events",
        )


async def _handle_execute_attack(
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Handle execute_attack tool.

    Args:
        arguments: Tool arguments with pattern (required), count, use_world
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with attack execution result
    """
    try:
        pattern = arguments.get("pattern")
        if not pattern:
            return formatters.format_error_response(
                error="Missing required argument: pattern",
                tool="execute_attack",
                suggestion="Provide attack pattern name (e.g., 'brute-force', 'c2-beacon')",
            )

        count = arguments.get("count", 1)
        use_world = arguments.get("use_world", True)

        # Validate count
        if count < 1 or count > 100:
            return formatters.format_error_response(
                error=f"count must be between 1 and 100, got {count}",
                tool="execute_attack",
            )

        # Get or create World state (attack patterns need entities)
        world = None
        if use_world:
            world = state.get_or_create_world()

        # Execute attack pattern using shared logic
        result: AttackExecutionResult = execute_attack_pattern(
            pattern=pattern,
            count=count,
            world=world,
            settings=settings,
        )

        # Track events in state
        state.add_events(result.events)

        # Index if enabled
        indexed = False
        if state.enable_indexing and not state.dry_run:
            try:
                indexer = ElasticsearchIndexer(settings)
                events_by_type = group_events_by_type(result.events)
                index_result = indexer.index_multi_type_events(events_by_type)
                indexed = index_result.get("success", False)
                if indexed:
                    logger.info(f"Indexed {len(result.events)} attack events")
            except Exception as e:
                logger.error(f"Failed to index attack events: {e}")

        logger.info(
            f"Executed attack pattern '{pattern}': {len(result.events)} events, "
            f"{count} iterations"
        )

        return formatters.format_attack_execution_summary(
            pattern=result.pattern_name,
            iterations=result.iterations,
            total_events=len(result.events),
            events_by_type=result.event_stats.by_dataset,
            ttps=result.ttps,
            detection_recommendations=result.detection_recommendations,
            world_summary=result.world_summary,
        )

    except ValueError as e:
        return formatters.format_error_response(
            error=str(e),
            tool="execute_attack",
        )
    except Exception as e:
        logger.error(f"Error executing attack: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="execute_attack",
        )


async def _handle_generate_campaign(
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Handle generate_campaign tool.

    Generates a coordinated attack campaign with multiple phases.

    Args:
        arguments: Tool arguments with num_hosts, num_alerts, attack_speed, time_spread
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with campaign generation result
    """
    try:
        num_hosts = arguments.get("num_hosts", 5)
        num_alerts = arguments.get("num_alerts", 20)
        attack_speed = arguments.get("attack_speed", "medium")
        time_spread = arguments.get("time_spread", "hours")

        # Validate parameters
        if num_hosts < 1 or num_hosts > 100:
            return formatters.format_error_response(
                error=f"num_hosts must be between 1 and 100, got {num_hosts}",
                tool="generate_campaign",
            )

        if num_alerts < 5 or num_alerts > 1000:
            return formatters.format_error_response(
                error=f"num_alerts must be between 5 and 1000, got {num_alerts}",
                tool="generate_campaign",
            )

        if attack_speed not in ["fast", "medium", "slow"]:
            return formatters.format_error_response(
                error=f"attack_speed must be 'fast', 'medium', or 'slow', got '{attack_speed}'",
                tool="generate_campaign",
            )

        if time_spread not in ["minutes", "hours", "days", "weeks"]:
            return formatters.format_error_response(
                error="time_spread must be 'minutes', 'hours', 'days', or 'weeks'",
                tool="generate_campaign",
            )

        # Create World with specified number of hosts
        world = state.get_or_create_world(
            num_hosts=max(num_hosts, 10),
            num_users=max(num_hosts * 2, 20),
            reset=True,
        )

        # Import campaign generator
        from secgen.generators.campaign import CampaignGenerator
        from secgen.generators.randomizers import RandomDataGenerator

        randomizer = RandomDataGenerator()
        campaign_gen = CampaignGenerator(randomizer)

        # Generate campaign
        campaign = campaign_gen.generate(num_hosts)

        # Generate events for each attack phase
        all_events: list[dict[str, Any]] = []
        phase_stats: dict[str, int] = {}

        # Define phases and their attack patterns
        phases = [
            ("initial", ["malware-drop"]),
            ("execution", ["registry-persistence", "c2-beacon"]),
            ("lateral", ["lateral-movement"]),
            ("exfiltration", ["data-exfiltration"]),
        ]

        # Distribute alerts across phases
        alerts_per_phase = num_alerts // len(phases)
        remaining = num_alerts % len(phases)

        for phase_name, patterns in phases:
            phase_alerts = alerts_per_phase + (1 if remaining > 0 else 0)
            remaining = max(0, remaining - 1)

            phase_events: list[dict[str, Any]] = []

            for pattern in patterns:
                try:
                    result = execute_attack_pattern(
                        pattern=pattern,
                        count=max(1, phase_alerts // len(patterns)),
                        world=world,
                        settings=settings,
                    )
                    phase_events.extend(result.events)
                except ValueError as e:
                    logger.warning(f"Skipping unavailable pattern '{pattern}': {e}")

            all_events.extend(phase_events)
            phase_stats[phase_name] = len(phase_events)

        # Track events in state
        state.add_events(all_events)

        # Index if enabled
        indexed = False
        if state.enable_indexing and not state.dry_run:
            try:
                indexer = ElasticsearchIndexer(settings)
                events_by_type = group_events_by_type(all_events)
                index_result = indexer.index_multi_type_events(events_by_type)
                indexed = index_result.get("success", False)
                if indexed:
                    logger.info(f"Indexed {len(all_events)} campaign events")
            except Exception as e:
                logger.error(f"Failed to index campaign events: {e}")

        logger.info(
            f"Generated campaign '{campaign.id}': {len(all_events)} events across "
            f"{len(phase_stats)} phases"
        )

        return formatters.format_success_response(
            {
                "campaign": {
                    "id": campaign.id,
                    "c2_domain": campaign.c2_domain,
                    "c2_ip": campaign.c2_ip,
                    "malware_family": campaign.malware_family,
                    "attacker_ip": campaign.attacker_ip,
                    "target_hosts": campaign.target_hosts[:10],  # Limit for response size
                },
                "generation": {
                    "total_events": len(all_events),
                    "phases": phase_stats,
                    "attack_speed": attack_speed,
                    "time_spread": time_spread,
                    "indexed": indexed,
                    "dry_run": state.dry_run,
                },
                "world_summary": world.summary(),
            }
        )

    except Exception as e:
        logger.error(f"Error generating campaign: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="generate_campaign",
        )
