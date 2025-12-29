"""Handler for describe commands."""

import argparse
import logging

from secgen.registry import get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def handle_describe(args: argparse.Namespace) -> None:
    """
    Handle describe subcommands.

    Args:
        args: Parsed command line arguments
    """
    ensure_bootstrapped()

    describe_type = args.describe_type
    name = args.name

    if describe_type == "event-type":
        _describe_event_type(name)
    elif describe_type == "attack":
        _describe_attack_pattern(name)
    else:
        logger.error(f"Unknown describe type: {describe_type}")


def _describe_event_type(name: str) -> None:
    """Describe an event type in detail."""
    registry = get_registry()
    metadata = registry.get_event_type(name)

    if not metadata:
        print(f"Event type '{name}' not found.")
        print("\nAvailable event types:")
        for evt in registry.list_event_types():
            print(f"  - {evt.name}")
        return

    print("\n" + "=" * 70)
    print(f"EVENT TYPE: {metadata.name}")
    print("=" * 70)

    print(f"\nCategory:    {metadata.category.value}")
    print(f"Description: {metadata.description}")

    if metadata.index_pattern:
        print(f"Index:       {metadata.index_pattern}")

    if metadata.ecs_fields:
        print("\nECS Fields:")
        for field in metadata.ecs_fields:
            print(f"  - {field}")

    if metadata.example_params:
        print("\nExample Parameters:")
        for param, value in metadata.example_params.items():
            print(f"  {param}: {value}")

    # Show generator class info
    print(f"\nGenerator Class: {metadata.generator_class.__name__}")

    # Show usage examples
    print("\n" + "-" * 70)
    print("USAGE EXAMPLES")
    print("-" * 70)
    print(f"\n# Generate 50 {name} events")
    print(f"secgen generate {name} --count 50")
    print(f"\n# Generate with World state correlation")
    print(f"secgen generate {name} --count 50 --use-world")
    print(f"\n# Generate and index to Elasticsearch")
    print(f"secgen generate {name} --count 100 --index")

    if metadata.example_params:
        params_str = " ".join(
            f"--param {k}={v}" for k, v in list(metadata.example_params.items())[:2]
        )
        print(f"\n# Generate with parameters")
        print(f"secgen generate {name} --count 50 {params_str}")

    print("\n" + "=" * 70)


def _describe_attack_pattern(name: str) -> None:
    """Describe an attack pattern in detail."""
    registry = get_registry()
    metadata = registry.get_attack_pattern(name)

    if not metadata:
        print(f"Attack pattern '{name}' not found.")
        print("\nAvailable attack patterns:")
        for pattern in registry.list_attack_patterns():
            print(f"  - {pattern.name}")
        return

    print("\n" + "=" * 70)
    print(f"ATTACK PATTERN: {metadata.name}")
    print("=" * 70)

    print(f"\nCategory:    {metadata.category.value}")
    print(f"Description: {metadata.description}")

    if metadata.ttps:
        print("\nMITRE ATT&CK TTPs:")
        for ttp in metadata.ttps:
            print(f"  - {ttp}")

    if metadata.event_types:
        print("\nGenerated Event Types:")
        for evt_type in metadata.event_types:
            print(f"  - {evt_type}")

    if metadata.required_params:
        print("\nRequired Parameters:")
        for param in metadata.required_params:
            print(f"  - {param}")

    if metadata.optional_params:
        print("\nOptional Parameters:")
        for param in metadata.optional_params:
            print(f"  - {param}")

    if metadata.detection_recommendations:
        print("\nDetection Recommendations:")
        for rec in metadata.detection_recommendations:
            print(f"  - {rec}")

    # Show generator info
    print(f"\nGenerator: {metadata.generator_class.__name__}.{metadata.method_name}()")

    # Show usage examples
    print("\n" + "-" * 70)
    print("USAGE EXAMPLES")
    print("-" * 70)
    print(f"\n# Execute {name} attack pattern")
    print(f"secgen attack {name} --index")
    print(f"\n# Execute multiple iterations")
    print(f"secgen attack {name} --count 3 --index")
    print(f"\n# Use with World state")
    print(f"secgen attack {name} --world-file qa-world.json --index")

    # Show MITRE ATT&CK reference
    if metadata.ttps:
        print("\n" + "-" * 70)
        print("MITRE ATT&CK REFERENCES")
        print("-" * 70)
        for ttp in metadata.ttps:
            technique_id = ttp.split(".")[0]
            print(f"  {ttp}: https://attack.mitre.org/techniques/{technique_id}/")

    print("\n" + "=" * 70)

