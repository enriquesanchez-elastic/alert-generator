"""Handler for preset execution commands."""

import argparse
import logging
import time
from typing import Any

from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.output.formatter import EventStats, GenerationSummary, OutputFormatter
from secgen.presets.schema import list_builtin_presets, load_preset
from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def _list_presets() -> None:
    """List all available built-in presets."""
    presets = list_builtin_presets()

    # Group presets by category
    categories = {
        "Quick Start & Testing": ["quick-start", "siem-demo", "load-test"],
        "Attack Simulation": [
            "attack-simulation",
            "ransomware-attack",
            "apt-campaign",
            "insider-threat",
            "credential-attack",
        ],
        "Feature-Specific": [
            "timeline-investigation",
            "analyzer-showcase",
            "network-map-demo",
            "vulnerability-dashboard",
            "cspm-compliance",
            "entity-analytics-showcase",
        ],
        "Cloud Security": ["cloud-security", "aws-security", "azure-security"],
        "Specialized Use Cases": [
            "demo-cluster",
            "detection-engineering",
            "threat-hunting",
            "incident-response",
            "soc-training",
            "endpoint-telemetry",
            "dns-security",
            "network-visibility",
        ],
    }

    print("\n" + "=" * 70)
    print("AVAILABLE PRESETS")
    print("=" * 70)

    for category, preset_names in categories.items():
        print(f"\n  {category}")
        print("  " + "-" * 40)
        for name in preset_names:
            if name in presets:
                desc = presets[name][:45] + "..." if len(presets[name]) > 45 else presets[name]
                print(f"    {name:25} {desc}")

    # Show any uncategorized presets
    all_categorized = set()
    for names in categories.values():
        all_categorized.update(names)

    uncategorized = set(presets.keys()) - all_categorized
    if uncategorized:
        print("\n  Other")
        print("  " + "-" * 40)
        for name in sorted(uncategorized):
            desc = presets[name][:45] + "..." if len(presets[name]) > 45 else presets[name]
            print(f"    {name:25} {desc}")

    print(f"\n{'=' * 70}")
    print(f"Total: {len(presets)} presets")
    print("=" * 70)
    print("\nUsage: secgen preset <preset-name>")
    print("       secgen preset <preset-name> --no-index")
    print("       secgen preset <preset-name> --output events.json\n")


def handle_preset(args: argparse.Namespace) -> None:
    """
    Handle preset execution commands.

    Args:
        args: Parsed command line arguments with:
            - preset_name: Preset name or YAML file path
            - list: List all available presets
            - no_index: Don't index to Elasticsearch
            - output: Output file path
            - json: Output JSON format
    """
    # Handle --list flag
    if getattr(args, "list", False):
        _list_presets()
        return

    # Check if preset_name is provided
    if not args.preset_name:
        print("Error: preset_name is required. Use --list to see available presets.")
        print("\nUsage: secgen preset <preset_name>")
        print("       secgen preset --list")
        return

    ensure_bootstrapped()
    settings = get_settings()
    registry = get_registry()

    start_time = time.time()
    preset_name = args.preset_name

    # Load preset
    try:
        preset = load_preset(preset_name)
    except ValueError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        _list_presets()
        return

    print(f"\n{'=' * 70}")
    print(f"PRESET: {preset.name}")
    print("=" * 70)
    print(f"\nDescription: {preset.description}")
    print(f"Steps: {len(preset.steps)}")
    print(f"Time Spread: {preset.time_spread_hours} hours")

    # Create World state
    world_config = preset.world_config
    num_hosts = world_config.get("hosts", 20)
    num_users = world_config.get("users", 40)

    logger.info(f"Creating World with {num_hosts} hosts and {num_users} users...")
    world = World()
    world.populate(num_hosts=num_hosts, num_users=num_users)

    print(f"World: {num_hosts} hosts, {num_users} users")

    # Execute steps
    all_events: list[dict[str, Any]] = []
    event_stats = EventStats()

    print("\nExecuting steps:")

    for i, step in enumerate(preset.steps, 1):
        print(f"  [{i}/{len(preset.steps)}] {step.type}: {step.name} (count={step.count})")

        events = _execute_step(
            step_type=step.type,
            name=step.name,
            count=step.count,
            params=step.params,
            world=world,
            registry=registry,
            settings=settings,
        )

        all_events.extend(events)
        print(f"           Generated {len(events)} events")

    # Collect statistics
    for event in all_events:
        event_stats.add_event(event)

    print(f"\nTotal events: {len(all_events)}")

    # Build summary
    duration = time.time() - start_time
    summary = GenerationSummary(
        command=f"secgen preset {preset_name}",
        duration_seconds=duration,
        event_stats=event_stats,
        kibana_base_url=getattr(settings, "kibana_url", "http://localhost:5601"),
    )
    summary.collect_correlation_ids(all_events)
    summary.world_summary = world.summary()

    # Index if requested
    should_index = not getattr(args, "no_index", False)
    if should_index and preset.index:
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

    # Format and print output
    use_json = getattr(args, "json", False)
    formatter = OutputFormatter(use_colors=True, json_output=use_json)
    print(formatter.format_summary(summary))


def _execute_step(
    step_type: str,
    name: str,
    count: int,
    params: dict[str, Any],
    world: World,
    registry,
    settings,
) -> list[dict[str, Any]]:
    """Execute a single preset step."""
    events: list[dict[str, Any]] = []

    # Get host and user from world
    host = world.get_random_host()
    user = world.get_random_user()
    if host and user:
        world.assign_user_to_host(user, host)

    if step_type == "event":
        events = _generate_events(name, count, params, host, user, world, registry, settings)
    elif step_type == "attack":
        events = _execute_attack(name, count, params, host, user, world, registry, settings)
    elif step_type == "feature":
        # Feature tests generate their own events
        logger.warning(f"Feature step '{name}' not supported in presets yet")

    return events


def _generate_events(
    event_type: str,
    count: int,
    params: dict[str, Any],
    host,
    user,
    world: World,
    registry,
    settings,
) -> list[dict[str, Any]]:
    """Generate events for an event type."""
    events: list[dict[str, Any]] = []

    import inspect

    metadata = registry.get_event_type(event_type)
    if not metadata:
        logger.warning(f"Event type {event_type} not found in registry")
        return events

    generator_class = metadata.generator_class

    try:
        generator = generator_class()
    except TypeError:
        generator = generator_class(settings)

    # Use batch generation if available (preferred)
    if hasattr(generator, "generate_batch"):
        batch_sig = inspect.signature(generator.generate_batch)
        batch_accepted = set(batch_sig.parameters.keys()) - {"self"}

        batch_params: dict[str, Any] = {"count": count}
        if host and "host" in batch_accepted:
            batch_params["host"] = host
        if user and "user" in batch_accepted:
            batch_params["user"] = user

        # Apply params that are accepted
        for key, value in params.items():
            if key in batch_accepted:
                batch_params[key] = value

        try:
            events = generator.generate_batch(**batch_params)
            if events:
                return events  # Success with batch generation
        except TypeError as e:
            logger.debug(f"Batch generation failed for {type(generator).__name__}: {e}")

    # Get accepted parameters from the generate method signature
    accepted_params: set[str] = set()
    if hasattr(generator, "generate"):
        sig = inspect.signature(generator.generate)
        accepted_params = set(sig.parameters.keys()) - {"self"}

        # Fall back to individual generation
        for i in range(count):
            gen_params: dict[str, Any] = {}
            if host and "host" in accepted_params:
                gen_params["host"] = host
            if user and "user" in accepted_params:
                gen_params["user"] = user
            if "timestamp_offset" in accepted_params:
                gen_params["timestamp_offset"] = count - i

            # Apply params that are accepted
            for key, value in params.items():
                if key in accepted_params:
                    gen_params[key] = value

            try:
                event = generator.generate(**gen_params)
                if event:
                    events.append(event)
            except (TypeError, AttributeError) as e:
                # Some generators have different signatures or missing methods
                logger.warning(f"Skipping generator {type(generator).__name__}: incompatible ({e})")
                break  # Don't retry for this generator
    else:
        logger.warning(
            f"Generator {type(generator).__name__} has no generate method, "
            "use generate_batch or specific event methods"
        )

    return events


def _execute_attack(
    pattern_name: str,
    count: int,
    params: dict[str, Any],
    host,
    user,
    world: World,
    registry,
    settings,
) -> list[dict[str, Any]]:
    """Execute an attack pattern."""

    events: list[dict[str, Any]] = []

    metadata = registry.get_attack_pattern(pattern_name)
    if not metadata:
        logger.warning(f"Attack pattern {pattern_name} not found in registry")
        return events

    generator_class = metadata.generator_class

    try:
        generator = generator_class()
    except TypeError:
        generator = generator_class(settings)

    attack_method = getattr(generator, metadata.method_name, None)
    if not attack_method:
        logger.warning(f"Attack method {metadata.method_name} not found")
        return events

    for _ in range(count):
        # Build attack parameters
        attack_params = _build_attack_params(metadata, host, user, world)
        attack_params.update(params)

        try:
            result = attack_method(**attack_params)
            if isinstance(result, dict):
                events.append(result)
            elif isinstance(result, list):
                events.extend([e for e in result if e])
        except Exception as e:
            logger.warning(f"Error executing attack pattern {pattern_name}: {e}")

    return events


def _build_attack_params(metadata, host, user, world) -> dict[str, Any]:
    """Build parameters for attack method based on required params."""
    import random

    params: dict[str, Any] = {}

    if "host" in metadata.required_params and host:
        params["host"] = host
    if "source_host" in metadata.required_params and host:
        params["source_host"] = host
    if "user" in metadata.required_params and user:
        params["user"] = user
    if "target_user" in metadata.required_params and user:
        params["target_user"] = user
    if "source_ip" in metadata.required_params:
        params["source_ip"] = (
            f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
    if "target_ip" in metadata.required_params and world:
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
            "aws.cloudtrail": "aws_cloudtrail",
            "azure.auditlogs": "azure_audit",
            "gcp.audit": "gcp_audit",
        }

        event_type = type_mapping.get(dataset, "process")
        if event_type not in grouped:
            grouped[event_type] = []
        grouped[event_type].append(event)

    return grouped
