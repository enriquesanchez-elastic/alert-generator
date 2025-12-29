"""Handler for generate commands with direct event type support."""

import argparse
import logging
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import EventStats, GenerationSummary, OutputFormatter
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

    # Look up event type in registry
    metadata = registry.get_event_type(event_type_name)
    if not metadata:
        logger.error(f"Unknown event type: {event_type_name}")
        print(f"Event type '{event_type_name}' not found.")
        print("\nAvailable event types:")
        for evt in registry.list_event_types():
            print(f"  - {evt.name}")
        return

    # Parse parameters
    params = _parse_params(getattr(args, "param", []) or [])

    # Setup World state if requested
    world = None
    host = None
    user = None

    if getattr(args, "world_file", None):
        logger.info(f"Loading World from: {args.world_file}")
        world = World.load(args.world_file)
    elif getattr(args, "use_world", False):
        logger.info("Creating ephemeral World state...")
        world = World()
        world.populate(num_hosts=10, num_users=20)

    if world:
        host = world.get_random_host()
        user = world.get_random_user()
        if host and user:
            world.assign_user_to_host(user, host)

    # Instantiate generator
    generator_class = metadata.generator_class
    try:
        generator = generator_class()
    except TypeError:
        # Some generators require settings (like AlertGenerator)
        generator = generator_class(settings)

    # Generate events
    count = getattr(args, "count", 10)
    events = []
    event_stats = EventStats()

    logger.info(f"Generating {count} {event_type_name} events...")

    # Check if generator has generate_batch method
    if hasattr(generator, "generate_batch"):
        # Use batch generation
        batch_params = {"count": count}
        if host:
            batch_params["host"] = host
        if user:
            batch_params["user"] = user

        # Add malicious ratio if specified
        if "is_malicious" in params:
            if params["is_malicious"] in ["true", "True", True, "1"]:
                batch_params["malicious_ratio"] = 1.0
            else:
                batch_params["malicious_ratio"] = 0.0

        events = generator.generate_batch(**batch_params)
    else:
        # Generate one at a time
        for i in range(count):
            gen_params: dict[str, Any] = {}
            if host:
                gen_params["host"] = host
            if user:
                gen_params["user"] = user

            # Add custom params
            for key, value in params.items():
                # Convert string booleans
                if value in ["true", "True"]:
                    gen_params[key] = True
                elif value in ["false", "False"]:
                    gen_params[key] = False
                elif value.isdigit():
                    gen_params[key] = int(value)
                else:
                    gen_params[key] = value

            gen_params["timestamp_offset"] = count - i

            try:
                event = generator.generate(**gen_params)
                if event:  # Some generators return empty for non-applicable hosts
                    events.append(event)
            except TypeError as e:
                # Handle generators with different signatures
                logger.debug(f"Generator signature mismatch: {e}")
                event = generator.generate()
                if event:
                    events.append(event)

    # Collect statistics
    for event in events:
        event_stats.add_event(event)

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen generate {event_type_name}",
        duration_seconds=duration,
        event_stats=event_stats,
        kibana_base_url=getattr(settings, "kibana_url", "http://localhost:5601"),
    )
    summary.collect_correlation_ids(events)

    if world:
        summary.world_summary = world.summary()

    # Index if requested
    if getattr(args, "index", False) and not getattr(args, "dry_run", False):
        indexer = ElasticsearchIndexer(settings)

        # Determine event type for indexer
        index_event_type = _map_event_type_to_index(event_type_name)

        result = indexer.index_typed_events(events, index_event_type)
        if result:
            summary.indices_written.append(metadata.index_pattern)
            logger.info(f"Indexed {len(events)} events to {metadata.index_pattern}")

    # Output to file if requested
    output_file = getattr(args, "output", None)
    if output_file:
        import json

        with open(output_file, "w") as f:
            json.dump(events, f, indent=2, default=str)
        logger.info(f"Saved {len(events)} events to {output_file}")

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _parse_params(param_list: list[str]) -> dict[str, str]:
    """Parse --param key=value arguments into a dictionary."""
    params = {}
    for param in param_list:
        if "=" in param:
            key, value = param.split("=", 1)
            params[key] = value
    return params


def _map_event_type_to_index(event_type_name: str) -> str:
    """Map event type name to indexer event type."""
    mapping = {
        "dns": "dns",
        "file": "file",
        "registry": "registry",
        "process": "process",
        "endpoint-network": "network",
        "network-flow": "network_flow",
        "http": "http",
        "tls": "tls",
        "authentication": "authentication",
        "iam": "authentication",
        "aws-cloudtrail": "aws_cloudtrail",
        "azure-audit": "azure_audit",
        "gcp-audit": "gcp_audit",
        "threat-indicator": "threat_indicator",
        "alert": "endpoint_alert",
    }
    return mapping.get(event_type_name, event_type_name)

