"""Handler for generate commands with direct event type support."""

import argparse
import json
import logging
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.generators.core_operations import (
    GenerationResult,
    generate_events_by_type,
    map_event_type_to_index,
    parse_params,
)
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import GenerationSummary, OutputFormatter
from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def handle_generate(args: argparse.Namespace) -> None:
    """
    Handle generate command for specific event types.

    Args:
        args: Parsed command line arguments with:
            - event_type: Name of event type to generate
            - count: Number of events
            - params: List of key=value parameter strings
            - use_world: Whether to use World state
            - world_file: Path to World state file
            - index: Whether to index to Elasticsearch
            - output: Output file path
            - dry_run: Don't index, just generate
            - json: Output JSON format
    """
    ensure_bootstrapped()
    settings = get_settings()
    registry = get_registry()

    start_time = time.time()
    event_type_name = args.event_type

    # Look up event type in registry (for error messages)
    metadata = registry.get_event_type(event_type_name)
    if not metadata:
        logger.error(f"Unknown event type: {event_type_name}")
        print(f"Event type '{event_type_name}' not found.")
        print("\nAvailable event types:")
        for evt in registry.list_event_types():
            print(f"  - {evt.name}")
        return

    # Parse parameters from CLI args
    param_list = getattr(args, "param", []) or []
    params = _parse_cli_params(param_list)

    # Setup World state if requested
    world = None
    if getattr(args, "world_file", None):
        logger.info(f"Loading World from: {args.world_file}")
        world = World.load(args.world_file)
    elif getattr(args, "use_world", False):
        logger.info("Creating ephemeral World state...")
        world = World()
        world.populate(num_hosts=10, num_users=20)

    # Generate events using shared logic
    count = getattr(args, "count", 10)

    try:
        result: GenerationResult = generate_events_by_type(
            event_type=event_type_name,
            count=count,
            world=world,
            params=params,
            settings=settings,
        )
    except ValueError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        return

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen generate {event_type_name}",
        duration_seconds=duration,
        event_stats=result.event_stats,
        kibana_base_url=getattr(settings, "kibana_url", "http://localhost:5601"),
    )
    summary.collect_correlation_ids(result.events)

    if world:
        summary.world_summary = world.summary()

    # Index if requested
    if getattr(args, "index", False) and not getattr(args, "dry_run", False):
        indexer = ElasticsearchIndexer(settings)

        # Determine event type for indexer
        index_event_type = map_event_type_to_index(event_type_name)

        index_result = indexer.index_typed_events(result.events, index_event_type)
        if index_result:
            summary.indices_written.append(result.index_pattern)
            logger.info(f"Indexed {len(result.events)} events to {result.index_pattern}")

    # Output to file if requested
    output_file = getattr(args, "output", None)
    if output_file:
        with open(output_file, "w") as f:
            json.dump(result.events, f, indent=2, default=str)
        logger.info(f"Saved {len(result.events)} events to {output_file}")

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _parse_cli_params(param_list: list[str]) -> dict[str, Any]:
    """Parse --param key=value arguments into a dictionary.

    Args:
        param_list: List of key=value strings from CLI

    Returns:
        Dictionary of parsed parameters with converted types
    """
    raw_params = {}
    for param in param_list:
        if "=" in param:
            key, value = param.split("=", 1)
            raw_params[key] = value

    # Use shared parse_params for type conversion
    return parse_params(raw_params)
