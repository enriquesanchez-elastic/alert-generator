"""Handler for feature testing commands."""

import argparse
import logging
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.features.definitions import FEATURE_TESTS, get_feature_test
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import EventStats, GenerationSummary, OutputFormatter
from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def handle_test(args: argparse.Namespace) -> None:
    """
    Handle feature test commands.

    Args:
        args: Parsed command line arguments with:
            - feature: Feature test name
            - count: Override default count
            - index: Whether to index to Elasticsearch
            - dry_run: Don't index, just generate
            - output: Output file path
            - json: Output JSON format
    """
    ensure_bootstrapped()
    settings = get_settings()
    registry = get_registry()

    start_time = time.time()
    feature_name = args.feature

    # Get feature test definition
    feature = get_feature_test(feature_name)
    if not feature:
        logger.error(f"Unknown feature test: {feature_name}")
        print(f"Feature test '{feature_name}' not found.")
        print("\nAvailable feature tests:")
        for name, ft in FEATURE_TESTS.items():
            print(f"  - {name}: {ft.description}")
        return

    print(f"\n{'=' * 70}")
    print(f"FEATURE TEST: {feature.name}")
    print("=" * 70)
    print(f"\nDescription: {feature.description}")
    print(f"Kibana Path: {feature.kibana_path}")
    print(f"Event Types: {', '.join(feature.event_types)}")

    # Create World state
    logger.info("Creating World state for feature test...")
    world = World()
    world.populate(num_hosts=15, num_users=30)

    # Override count if provided
    count = getattr(args, "count", None) or feature.default_count

    # Generate events for each event type
    all_events: list[dict[str, Any]] = []
    event_stats = EventStats()

    events_per_type = max(count // len(feature.event_types), 10)

    print(f"\nGenerating {count} total events across {len(feature.event_types)} event types...")

    for event_type in feature.event_types:
        print(f"  Generating {events_per_type} {event_type} events...")

        events = _generate_events_for_feature(
            event_type=event_type,
            count=events_per_type,
            world=world,
            registry=registry,
            settings=settings,
            feature_config=feature.configuration,
        )

        all_events.extend(events)

    # Collect statistics
    for event in all_events:
        event_stats.add_event(event)

    print(f"\nTotal events generated: {len(all_events)}")

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen test {feature_name}",
        duration_seconds=duration,
        event_stats=event_stats,
        kibana_base_url=getattr(settings, "kibana_url", "http://localhost:5601"),
    )
    summary.collect_correlation_ids(all_events)

    if world:
        summary.world_summary = world.summary()

    # Index if requested
    if getattr(args, "index", False) and not getattr(args, "dry_run", False):
        indexer = ElasticsearchIndexer(settings)

        # Group events by type and index
        events_by_type = _group_events_by_type(all_events)
        result = indexer.index_multi_type_events(events_by_type)

        if result.get("success"):
            for event_type in events_by_type:
                summary.indices_written.append(f"logs-{event_type}-default")
            logger.info(f"Indexed {len(all_events)} events")

    # Output to file if requested
    output_file = getattr(args, "output", None)
    if output_file:
        import json

        with open(output_file, "w") as f:
            json.dump(all_events, f, indent=2, default=str)
        logger.info(f"Saved {len(all_events)} events to {output_file}")

    # Print verification steps
    _print_verification_steps(feature, summary)

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _generate_events_for_feature(
    event_type: str,
    count: int,
    world: World,
    registry,
    settings,
    feature_config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate events for a specific event type based on feature requirements."""
    events: list[dict[str, Any]] = []

    # Get host and user from world
    host = world.get_random_host()
    user = world.get_random_user()
    if host and user:
        world.assign_user_to_host(user, host)

    # Get generator from registry
    metadata = registry.get_event_type(event_type)
    if not metadata:
        logger.warning(f"Event type {event_type} not found in registry")
        return events

    generator_class = metadata.generator_class

    try:
        generator = generator_class()
    except TypeError:
        generator = generator_class(settings)

    # Check for batch generation
    if hasattr(generator, "generate_batch"):
        batch_params = {"count": count}

        # Add host/user if supported
        if host:
            batch_params["host"] = host
        if user:
            batch_params["user"] = user

        # Apply feature-specific configuration
        if feature_config.get("malicious_ratio"):
            batch_params["malicious_ratio"] = feature_config["malicious_ratio"]

        try:
            events = generator.generate_batch(**batch_params)
        except TypeError:
            # Fallback to individual generation
            pass

    # Fall back to individual generation
    if not events:
        for i in range(count):
            gen_params: dict[str, Any] = {}
            if host:
                gen_params["host"] = host
            if user:
                gen_params["user"] = user
            gen_params["timestamp_offset"] = count - i

            try:
                event = generator.generate(**gen_params)
                if event:
                    events.append(event)
            except TypeError as e:
                # Some generators (like ProcessEventGenerator) have different signatures
                # that require additional context like Scenario objects
                logger.warning(
                    f"Skipping generator {type(generator).__name__}: incompatible signature ({e})"
                )
                break  # Don't retry for this generator

    return events


def _group_events_by_type(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events by their dataset for indexing."""
    grouped: dict[str, list[dict[str, Any]]] = {}

    for event in events:
        dataset = event.get("data_stream", {}).get("dataset", "unknown")

        type_mapping = {
            "endpoint.events.process": "process",
            "endpoint.events.file": "file",
            "endpoint.events.registry": "registry",
            "endpoint.events.network": "network",
            "dns.query": "dns",
            "network_traffic.flow": "network_flow",
            "network_traffic.http": "http",
            "network_traffic.tls": "tls",
            "system.auth": "authentication",
            "vulnerability.scan": "vulnerability",
            "cloud_security_posture.findings": "cspm",
            "entity_analytics.risk": "risk_score",
        }

        event_type = type_mapping.get(dataset, "process")
        if event_type not in grouped:
            grouped[event_type] = []
        grouped[event_type].append(event)

    return grouped


def _print_verification_steps(feature, summary: GenerationSummary) -> None:
    """Print verification steps for the feature test."""
    print("\n" + "=" * 70)
    print("VERIFICATION STEPS")
    print("=" * 70)

    print(f"\nNavigate to: {summary.kibana_base_url}{feature.kibana_path}")
    print("\nSteps:")

    for i, step in enumerate(feature.verification_steps, 1):
        print(f"  {i}. {step}")

    # Add query hints
    print("\nUseful Queries:")
    if summary.correlation_ids.get("host.id"):
        host_ids = summary.correlation_ids["host.id"][:3]
        query = "host.id:(" + " OR ".join(host_ids) + ")"
        print(f"  Filter by host: {query}")

    if summary.correlation_ids.get("user.name"):
        user_names = summary.correlation_ids["user.name"][:3]
        query = "user.name:(" + " OR ".join(user_names) + ")"
        print(f"  Filter by user: {query}")

