"""Testing tools for MCP server.

This module implements tools for testing Elastic Security features:
- test_elastic_feature: Generate data for specific Elastic features
"""

import logging
from typing import Any

from secgen.config.settings import Settings
from secgen.features.definitions import FEATURE_TESTS, get_feature_test
from secgen.generators.core_operations import (
    generate_events_by_type,
    group_events_by_type,
)
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.mcp import formatters
from secgen.mcp.state import MCPState
from secgen.output.formatter import EventStats

logger = logging.getLogger(__name__)


async def handle_tool(
    name: str,
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Route testing tool calls to appropriate handlers.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with tool response
    """
    if name == "test_elastic_feature":
        return await _handle_test_elastic_feature(arguments, state, settings)
    else:
        return formatters.format_error_response(
            error=f"Unknown testing tool: {name}",
            tool=name,
        )


async def _handle_test_elastic_feature(
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Handle test_elastic_feature tool.

    Generates data specifically designed to test Elastic Security features.

    Args:
        arguments: Tool arguments with feature (required), count (optional)
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with feature test result
    """
    try:
        feature_name = arguments.get("feature")
        if not feature_name:
            return formatters.format_error_response(
                error="Missing required argument: feature",
                tool="test_elastic_feature",
                suggestion=(
                    "Provide a feature name. Available features: " + ", ".join(FEATURE_TESTS.keys())
                ),
            )

        # Get feature definition
        feature = get_feature_test(feature_name)
        if not feature:
            return formatters.format_error_response(
                error=f"Feature test '{feature_name}' not found",
                tool="test_elastic_feature",
                suggestion=("Available feature tests: " + ", ".join(FEATURE_TESTS.keys())),
            )

        # Get count (use provided or default)
        count = arguments.get("count", feature.default_count)

        # Validate count
        if count < 10 or count > 10000:
            return formatters.format_error_response(
                error=f"count must be between 10 and 10000, got {count}",
                tool="test_elastic_feature",
            )

        # Create World state for feature test
        world = state.get_or_create_world(
            num_hosts=15,
            num_users=30,
            reset=True,
        )

        # Generate events for each event type
        all_events: list[dict[str, Any]] = []
        event_stats = EventStats()
        events_per_type = max(count // len(feature.event_types), 10)
        type_counts: dict[str, int] = {}

        logger.info(
            f"Generating {count} events for feature test '{feature_name}' "
            f"across {len(feature.event_types)} event types"
        )

        for event_type in feature.event_types:
            try:
                # Prepare params based on feature configuration
                params: dict[str, Any] = {}
                if feature.configuration.get("malicious_ratio"):
                    params["malicious_ratio"] = feature.configuration["malicious_ratio"]

                result = generate_events_by_type(
                    event_type=event_type,
                    count=events_per_type,
                    world=world,
                    params=params,
                    settings=settings,
                )

                all_events.extend(result.events)
                type_counts[event_type] = len(result.events)

            except ValueError as e:
                logger.warning(f"Skipping event type '{event_type}': {e}")
                type_counts[event_type] = 0
            except TypeError as e:
                # Some generators (like AlertGenerator) require additional parameters
                logger.warning(f"Skipping event type '{event_type}': incompatible generator ({e})")
                type_counts[event_type] = 0

        # Collect statistics
        for event in all_events:
            event_stats.add_event(event)

        # Track events in state
        state.add_events(all_events)

        # Index if enabled
        indexed = False
        indices_written: list[str] = []
        if state.enable_indexing and not state.dry_run:
            try:
                indexer = ElasticsearchIndexer(settings)
                events_by_type = group_events_by_type(all_events)
                result = indexer.index_multi_type_events(events_by_type)
                indexed = result.get("success", False)
                if indexed:
                    indices_written = list(result.get("indexed", {}).keys())
                    logger.info(f"Indexed {len(all_events)} feature test events")
            except Exception as e:
                logger.error(f"Failed to index feature test events: {e}")

        # Collect correlation IDs for queries
        correlation_ids: dict[str, list[str]] = {}
        for event in all_events[:100]:  # Sample first 100 for IDs
            host_id = event.get("host", {}).get("id")
            if host_id:
                if "host.id" not in correlation_ids:
                    correlation_ids["host.id"] = []
                if host_id not in correlation_ids["host.id"]:
                    correlation_ids["host.id"].append(host_id)

            user_name = event.get("user", {}).get("name")
            if user_name:
                if "user.name" not in correlation_ids:
                    correlation_ids["user.name"] = []
                if user_name not in correlation_ids["user.name"]:
                    correlation_ids["user.name"].append(user_name)

        # Limit to 5 IDs each for response
        correlation_ids = {k: v[:5] for k, v in correlation_ids.items()}

        logger.info(f"Feature test '{feature_name}': {len(all_events)} events generated")

        # Build response
        kibana_url = getattr(settings, "kibana_url", "http://localhost:5601")

        return formatters.format_success_response(
            {
                "feature": {
                    "name": feature.name,
                    "description": feature.description,
                    "kibana_url": f"{kibana_url}{feature.kibana_path}",
                },
                "generation": {
                    "total_events": len(all_events),
                    "events_by_type": type_counts,
                    "events_by_dataset": event_stats.by_dataset,
                    "indexed": indexed,
                    "indices_written": indices_written,
                    "dry_run": state.dry_run,
                },
                "verification": {
                    "steps": feature.verification_steps,
                    "correlation_ids": correlation_ids,
                    "useful_queries": _build_useful_queries(correlation_ids),
                },
                "world_summary": world.summary(),
            }
        )

    except Exception as e:
        logger.error(f"Error in feature test: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="test_elastic_feature",
        )


def _build_useful_queries(correlation_ids: dict[str, list[str]]) -> list[str]:
    """Build useful KQL queries from correlation IDs.

    Args:
        correlation_ids: Dictionary of field name to list of IDs

    Returns:
        List of KQL query strings
    """
    queries = []

    if correlation_ids.get("host.id"):
        host_ids = correlation_ids["host.id"][:3]
        query = "host.id:(" + " OR ".join(host_ids) + ")"
        queries.append(f"Filter by hosts: {query}")

    if correlation_ids.get("user.name"):
        user_names = correlation_ids["user.name"][:3]
        query = "user.name:(" + " OR ".join(user_names) + ")"
        queries.append(f"Filter by users: {query}")

    return queries
