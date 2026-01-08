"""Core generation operations shared between CLI and MCP handlers.

This module provides shared business logic for event generation and attack
pattern execution, avoiding code duplication between CLI handlers and MCP tools.
"""

import logging
import random
from dataclasses import dataclass, field
from typing import Any

from secgen.config.settings import Settings
from secgen.core.world import World
from secgen.output.formatter import EventStats
from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


@dataclass
class GenerationResult:
    """Result of event generation operation."""

    events: list[dict[str, Any]]
    event_stats: EventStats
    world_summary: dict[str, Any] | None = None
    event_type: str = ""
    index_pattern: str = ""


@dataclass
class AttackExecutionResult:
    """Result of attack pattern execution."""

    events: list[dict[str, Any]]
    event_stats: EventStats
    pattern_name: str = ""
    ttps: list[str] = field(default_factory=list)
    detection_recommendations: list[str] = field(default_factory=list)
    iterations: int = 1
    world_summary: dict[str, Any] | None = None


def parse_params(params: dict[str, Any]) -> dict[str, Any]:
    """Parse and convert parameter values.

    Converts string booleans and numbers to proper types.

    Args:
        params: Raw parameter dictionary

    Returns:
        Dictionary with converted values
    """
    converted = {}
    for key, value in params.items():
        if isinstance(value, str):
            # Convert string booleans
            if value.lower() in ["true", "1", "yes"]:
                converted[key] = True
            elif value.lower() in ["false", "0", "no"]:
                converted[key] = False
            elif value.isdigit():
                converted[key] = int(value)
            elif value.replace(".", "").isdigit() and value.count(".") == 1:
                converted[key] = float(value)
            else:
                converted[key] = value
        else:
            converted[key] = value
    return converted


def generate_events_by_type(
    event_type: str,
    count: int,
    world: World | None = None,
    params: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> GenerationResult:
    """Generate events of a specific type.

    Shared logic for CLI and MCP event generation.

    Args:
        event_type: Name of event type to generate
        count: Number of events to generate
        world: Optional World state for entity correlation
        params: Optional generator parameters
        settings: Optional application settings

    Returns:
        GenerationResult with events and statistics

    Raises:
        ValueError: If event type is not found
    """
    ensure_bootstrapped()
    registry = get_registry()

    # Look up event type
    metadata = registry.get_event_type(event_type)
    if not metadata:
        available = [et.name for et in registry.list_event_types()]
        raise ValueError(
            f"Event type '{event_type}' not found. "
            f"Available: {', '.join(available[:10])}{'...' if len(available) > 10 else ''}"
        )

    # Parse parameters
    parsed_params = parse_params(params or {})

    # Get entities from World
    host = None
    user = None
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
        # Some generators require settings
        from secgen.config.settings import get_settings

        actual_settings = settings or get_settings()
        generator = generator_class(actual_settings)

    # Generate events
    events: list[dict[str, Any]] = []
    event_stats = EventStats()

    logger.info(f"Generating {count} {event_type} events...")

    # Check if generator has generate_batch method
    if hasattr(generator, "generate_batch"):
        batch_params: dict[str, Any] = {"count": count}
        if host:
            batch_params["host"] = host

        # Handle malicious ratio
        if "is_malicious" in parsed_params:
            if parsed_params["is_malicious"]:
                batch_params["malicious_ratio"] = 1.0
            else:
                batch_params["malicious_ratio"] = 0.0

        try:
            events = generator.generate_batch(**batch_params)
        except TypeError:
            # Some generators don't support all batch params - fallback to fewer params
            batch_params = {"count": count}
            if host:
                batch_params["host"] = host
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
            gen_params.update(parsed_params)
            gen_params["timestamp_offset"] = count - i

            try:
                event = generator.generate(**gen_params)
                if event:
                    events.append(event)
            except TypeError as e:
                logger.debug(f"Generator signature mismatch: {e}")
                event = generator.generate()
                if event:
                    events.append(event)

    # Collect statistics
    for event in events:
        event_stats.add_event(event)

    return GenerationResult(
        events=events,
        event_stats=event_stats,
        world_summary=world.summary() if world else None,
        event_type=event_type,
        index_pattern=metadata.index_pattern,
    )


def execute_attack_pattern(
    pattern: str,
    count: int = 1,
    world: World | None = None,
    settings: Settings | None = None,
) -> AttackExecutionResult:
    """Execute an attack pattern.

    Shared logic for CLI and MCP attack execution.

    Args:
        pattern: Attack pattern name
        count: Number of iterations
        world: Optional World state (will be created if not provided)
        settings: Optional application settings

    Returns:
        AttackExecutionResult with events and statistics

    Raises:
        ValueError: If attack pattern is not found
    """
    ensure_bootstrapped()
    registry = get_registry()

    # Look up attack pattern
    metadata = registry.get_attack_pattern(pattern)
    if not metadata:
        available = [ap.name for ap in registry.list_attack_patterns()]
        raise ValueError(
            f"Attack pattern '{pattern}' not found. "
            f"Available: {', '.join(available[:10])}{'...' if len(available) > 10 else ''}"
        )

    # Ensure World state exists
    if world is None:
        world = World()
        world.populate(num_hosts=10, num_users=20)

    # Get entities for attack
    host = world.get_random_host()
    user = world.get_random_user()

    if host and user:
        world.assign_user_to_host(user, host)

    # Instantiate generator
    generator_class = metadata.generator_class
    try:
        generator = generator_class()
    except TypeError:
        from secgen.config.settings import get_settings

        actual_settings = settings or get_settings()
        generator = generator_class(actual_settings)

    # Get the attack method
    attack_method = getattr(generator, metadata.method_name, None)
    if not attack_method:
        raise ValueError(f"Attack method {metadata.method_name} not found on generator")

    # Execute attack pattern
    all_events: list[dict[str, Any]] = []
    event_stats = EventStats()

    logger.info(f"Executing attack pattern: {pattern} ({count} iterations)")

    for i in range(count):
        # Build attack parameters
        attack_params = _build_attack_params(metadata, host, user, world)

        try:
            events = attack_method(**attack_params)

            # Handle single event vs list
            if isinstance(events, dict):
                events = [events]

            # Filter out empty events
            events = [e for e in events if e]
            all_events.extend(events)

            logger.debug(f"Iteration {i + 1}/{count}: {len(events)} events")

        except Exception as e:
            logger.error(f"Error in attack iteration {i + 1}: {e}")

    # Collect statistics
    for event in all_events:
        event_stats.add_event(event)

    return AttackExecutionResult(
        events=all_events,
        event_stats=event_stats,
        pattern_name=metadata.name,
        ttps=metadata.ttps,
        detection_recommendations=metadata.detection_recommendations,
        iterations=count,
        world_summary=world.summary(),
    )


def _build_attack_params(
    metadata: Any,
    host: Any,
    user: Any,
    world: World,
) -> dict[str, Any]:
    """Build parameters for attack method based on required params.

    Args:
        metadata: Attack pattern metadata
        host: Host entity
        user: User entity
        world: World state

    Returns:
        Dictionary of attack parameters
    """
    params: dict[str, Any] = {}

    required = metadata.required_params

    # Map common parameter names
    if "host" in required and host:
        params["host"] = host
    if "source_host" in required and host:
        params["source_host"] = host
    if "user" in required and user:
        params["user"] = user
    if "target_user" in required and user:
        params["target_user"] = user
    if "source_ip" in required:
        params["source_ip"] = (
            f"{random.randint(1, 223)}.{random.randint(0, 255)}."
            f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
    if "target_ip" in required:
        target_host = world.get_random_host()
        if target_host and target_host.ip:
            params["target_ip"] = target_host.ip[0]
        else:
            params["target_ip"] = "10.0.0.100"
    if "c2_domain" in required:
        params["c2_domain"] = "evil-c2.badactor.com"
    if "c2_ip" in required:
        params["c2_ip"] = "198.51.100.10"
    if "tunnel_domain" in required:
        params["tunnel_domain"] = "exfil.tunnel.net"
    if "exfil_domain" in required:
        params["exfil_domain"] = "data.exfil.com"
    if "exfil_ip" in required:
        params["exfil_ip"] = "198.51.100.20"
    if "usernames" in required:
        params["usernames"] = [f"user{i}" for i in range(20)]
    if "process" in required and host and user:
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


def group_events_by_type(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events by their dataset/type for indexing.

    Args:
        events: List of events to group

    Returns:
        Dictionary mapping event type to list of events
    """
    grouped: dict[str, list[dict[str, Any]]] = {}

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

    for event in events:
        dataset = event.get("data_stream", {}).get("dataset", "unknown")
        event_type = type_mapping.get(dataset, "process")

        if event_type not in grouped:
            grouped[event_type] = []
        grouped[event_type].append(event)

    return grouped


def map_event_type_to_index(event_type_name: str) -> str:
    """Map event type name to indexer event type.

    Args:
        event_type_name: Event type name from registry

    Returns:
        Indexer event type string
    """
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
