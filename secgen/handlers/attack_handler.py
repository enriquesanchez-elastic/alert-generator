"""Handler for attack pattern execution commands."""

import argparse
import json
import logging
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.generators.core_operations import (
    AttackExecutionResult,
    execute_attack_pattern,
    group_events_by_type,
)
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import GenerationSummary, OutputFormatter
from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def handle_attack(args: argparse.Namespace) -> None:
    """
    Handle attack pattern execution.

    Args:
        args: Parsed command line arguments with:
            - pattern: Attack pattern name
            - count: Number of iterations
            - world_file: Path to World state file
            - use_world: Whether to create ephemeral World
            - index: Whether to index to Elasticsearch
            - dry_run: Don't index, just generate
            - output: Output file path
            - json: Output JSON format
    """
    ensure_bootstrapped()
    settings = get_settings()
    registry = get_registry()

    start_time = time.time()
    pattern_name = args.pattern

    # Look up attack pattern in registry (for error messages and metadata)
    metadata = registry.get_attack_pattern(pattern_name)
    if not metadata:
        logger.error(f"Unknown attack pattern: {pattern_name}")
        print(f"Attack pattern '{pattern_name}' not found.")
        print("\nAvailable attack patterns:")
        for pattern in registry.list_attack_patterns():
            print(f"  - {pattern.name}")
        return

    # Setup World state
    world = None
    if getattr(args, "world_file", None):
        logger.info(f"Loading World from: {args.world_file}")
        world = World.load(args.world_file)
    elif getattr(args, "use_world", False) or not getattr(args, "world_file", None):
        # Create ephemeral World for attack patterns (they need entities)
        logger.info("Creating ephemeral World state for attack pattern...")
        world = World()
        world.populate(num_hosts=10, num_users=20)

    count = getattr(args, "count", 1)

    print(f"\n{'=' * 70}")
    print(f"ATTACK PATTERN: {metadata.name}")
    print("=" * 70)
    print(f"\nDescription: {metadata.description}")
    print(f"MITRE ATT&CK TTPs: {', '.join(metadata.ttps)}")
    print(f"\nExecuting {count} iteration(s)...\n")

    # Execute attack pattern using shared logic
    try:
        result: AttackExecutionResult = execute_attack_pattern(
            pattern=pattern_name,
            count=count,
            world=world,
            settings=settings,
        )
    except ValueError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        return

    print(f"\nTotal events: {len(result.events)}")

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen attack {pattern_name}",
        duration_seconds=duration,
        event_stats=result.event_stats,
        attack_pattern=result.pattern_name,
        attack_ttps=result.ttps,
        detection_recommendations=result.detection_recommendations,
        kibana_base_url=getattr(settings, "kibana_url", "http://localhost:5601"),
    )
    summary.collect_correlation_ids(result.events)

    if world:
        summary.world_summary = world.summary()

    # Index if requested
    if getattr(args, "index", False) and not getattr(args, "dry_run", False):
        indexer = ElasticsearchIndexer(settings)

        # Group events by type and index
        events_by_type = group_events_by_type(result.events)
        index_result = indexer.index_multi_type_events(events_by_type)

        if index_result.get("success"):
            for event_type in events_by_type:
                summary.indices_written.append(f"logs-{event_type}-default")
            logger.info(f"Indexed {len(result.events)} events")

    # Output to file if requested
    output_file = getattr(args, "output", None)
    if output_file:
        with open(output_file, "w") as f:
            json.dump(result.events, f, indent=2, default=str)
        logger.info(f"Saved {len(result.events)} events to {output_file}")

    # Print attack insights
    _print_attack_insights(metadata, summary)

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _print_attack_insights(metadata: Any, summary: GenerationSummary) -> None:
    """Print attack-specific insights."""
    print("\n" + "=" * 70)
    print("ATTACK INSIGHTS")
    print("=" * 70)

    # Event timeline
    print("\nEvent Timeline:")
    for dataset, count in sorted(summary.event_stats.by_dataset.items()):
        print(f"  {dataset}: {count}")

    # Detection opportunities
    print("\nDetection Opportunities:")
    print(f"  MITRE ATT&CK TTPs: {', '.join(metadata.ttps)}")
    if metadata.detection_recommendations:
        print("  Recommended Detection Rules:")
        for rec in metadata.detection_recommendations:
            print(f"    - {rec}")

    # MITRE ATT&CK references
    print("\nMITRE ATT&CK References:")
    for ttp in metadata.ttps:
        technique_id = ttp.split(".")[0]
        print(f"  {ttp}: https://attack.mitre.org/techniques/{technique_id}/")
