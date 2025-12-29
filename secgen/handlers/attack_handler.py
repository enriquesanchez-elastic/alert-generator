"""Handler for attack pattern execution commands."""

import argparse
import logging
import random
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import EventStats, GenerationSummary, OutputFormatter
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

    # Look up attack pattern in registry
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

    # Get entities for attack
    host = world.get_random_host() if world else None
    user = world.get_random_user() if world else None

    if host and user and world:
        world.assign_user_to_host(user, host)

    # Instantiate generator
    generator_class = metadata.generator_class
    try:
        generator = generator_class()
    except TypeError:
        # Some generators require settings
        generator = generator_class(settings)

    # Get the attack method
    attack_method = getattr(generator, metadata.method_name, None)
    if not attack_method:
        logger.error(f"Attack method {metadata.method_name} not found on generator")
        return

    # Execute attack pattern
    count = getattr(args, "count", 1)
    all_events: list[dict[str, Any]] = []
    event_stats = EventStats()

    print(f"\n{'=' * 70}")
    print(f"ATTACK PATTERN: {metadata.name}")
    print("=" * 70)
    print(f"\nDescription: {metadata.description}")
    print(f"MITRE ATT&CK TTPs: {', '.join(metadata.ttps)}")
    print(f"\nExecuting {count} iteration(s)...\n")

    for i in range(count):
        print(f"Iteration {i + 1}/{count}...")

        # Build attack parameters
        attack_params = _build_attack_params(metadata, host, user, world)

        try:
            # Execute attack pattern
            events = attack_method(**attack_params)

            # Handle single event vs list
            if isinstance(events, dict):
                events = [events]

            # Filter out empty events
            events = [e for e in events if e]

            all_events.extend(events)
            print(f"  Generated {len(events)} events")

        except Exception as e:
            logger.error(f"Error executing attack pattern: {e}")
            print(f"  Error: {e}")

    # Collect statistics
    for event in all_events:
        event_stats.add_event(event)

    print(f"\nTotal events: {len(all_events)}")

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen attack {pattern_name}",
        duration_seconds=duration,
        event_stats=event_stats,
        attack_pattern=metadata.name,
        attack_ttps=metadata.ttps,
        detection_recommendations=metadata.detection_recommendations,
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

    # Print attack insights
    _print_attack_insights(metadata, summary)

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _build_attack_params(metadata, host, user, world) -> dict[str, Any]:
    """Build parameters for attack method based on required params."""
    params: dict[str, Any] = {}

    # Map common parameter names
    if "host" in metadata.required_params and host:
        params["host"] = host
    if "source_host" in metadata.required_params and host:
        params["source_host"] = host
    if "user" in metadata.required_params and user:
        params["user"] = user
    if "target_user" in metadata.required_params and user:
        params["target_user"] = user
    if "source_ip" in metadata.required_params:
        params["source_ip"] = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    if "target_ip" in metadata.required_params and world:
        # Get a different host as target
        target_host = world.get_random_host()
        if target_host and target_host.ip:
            params["target_ip"] = target_host.ip[0]
        else:
            params["target_ip"] = "10.0.0.100"
    if "c2_domain" in metadata.required_params:
        params["c2_domain"] = "evil-c2.badactor.com"
    if "c2_ip" in metadata.required_params:
        params["c2_ip"] = "198.51.100.10"
    if "tunnel_domain" in metadata.required_params:
        params["tunnel_domain"] = "exfil.tunnel.net"
    if "exfil_domain" in metadata.required_params:
        params["exfil_domain"] = "data.exfil.com"
    if "exfil_ip" in metadata.required_params:
        params["exfil_ip"] = "198.51.100.20"
    if "usernames" in metadata.required_params:
        params["usernames"] = [f"user{i}" for i in range(20)]
    if "process" in metadata.required_params and host and world:
        # Spawn a process for the attack
        process = world.spawn_process(
            host_id=host.id,
            name="powershell.exe",
            executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            args=["-enc", "malicious"],
            working_directory="C:\\Users\\victim",
            user=user,
        )
        params["process"] = process

    return params


def _group_events_by_type(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events by their dataset/type for indexing."""
    grouped: dict[str, list[dict[str, Any]]] = {}

    for event in events:
        dataset = event.get("data_stream", {}).get("dataset", "unknown")

        # Map dataset to event type
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
        }

        event_type = type_mapping.get(dataset, "process")
        if event_type not in grouped:
            grouped[event_type] = []
        grouped[event_type].append(event)

    return grouped


def _print_attack_insights(metadata, summary: GenerationSummary) -> None:
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

