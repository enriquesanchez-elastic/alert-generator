"""Handler for list commands."""

import argparse
import logging

from secgen.registry import GeneratorCategory, get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


def handle_list(args: argparse.Namespace) -> None:
    """
    Handle list subcommands.

    Args:
        args: Parsed command line arguments
    """
    ensure_bootstrapped()
    registry = get_registry()

    list_type = args.list_type

    if list_type == "event-types":
        _list_event_types(registry, args)
    elif list_type == "attack-patterns":
        _list_attack_patterns(registry, args)
    elif list_type == "generators":
        _list_generators(registry, args)
    elif list_type == "feature-tests":
        _list_feature_tests(args)
    else:
        logger.error(f"Unknown list type: {list_type}")


def _list_event_types(registry, args: argparse.Namespace) -> None:
    """List all registered event types."""
    category_filter = None
    if hasattr(args, "filter") and args.filter:
        try:
            category_filter = GeneratorCategory(args.filter.lower())
        except ValueError:
            logger.error(f"Unknown category: {args.filter}")
            print(f"Valid categories: {', '.join(c.value for c in GeneratorCategory)}")
            return

    event_types = registry.list_event_types(category=category_filter)

    if not event_types:
        print("No event types registered.")
        return

    print("\n" + "=" * 70)
    print("EVENT TYPES")
    print("=" * 70)

    # Group by category
    current_category = None
    for evt in event_types:
        if evt.category != current_category:
            current_category = evt.category
            print(f"\n  {current_category.value.upper()}")
            print("  " + "-" * 40)

        print(f"    {evt.name:20s} - {evt.description[:45]}")

    print("\n" + "=" * 70)
    print(f"Total: {len(event_types)} event types")
    print("=" * 70)
    print("\nUse 'secgen describe event-type <name>' for details")


def _list_attack_patterns(registry, args: argparse.Namespace) -> None:
    """List all registered attack patterns."""
    category_filter = None
    ttp_filter = None

    if hasattr(args, "filter") and args.filter:
        try:
            category_filter = GeneratorCategory(args.filter.lower())
        except ValueError:
            # Not a category, treat as TTP filter
            pass

    if hasattr(args, "ttp") and args.ttp:
        ttp_filter = args.ttp

    patterns = registry.list_attack_patterns(category=category_filter, ttp=ttp_filter)

    if not patterns:
        print("No attack patterns registered.")
        if ttp_filter:
            print(f"No patterns found for TTP: {ttp_filter}")
        return

    print("\n" + "=" * 70)
    print("ATTACK PATTERNS")
    print("=" * 70)

    # Group by category
    current_category = None
    for pattern in patterns:
        if pattern.category != current_category:
            current_category = pattern.category
            print(f"\n  {current_category.value.upper()}")
            print("  " + "-" * 40)

        ttps_str = ", ".join(pattern.ttps[:3])
        if len(pattern.ttps) > 3:
            ttps_str += "..."
        print(f"    {pattern.name:25s} [{ttps_str}]")

    print("\n" + "=" * 70)
    print(f"Total: {len(patterns)} attack patterns")
    print("=" * 70)
    print("\nUse 'secgen describe attack <name>' for details")


def _list_generators(registry, args: argparse.Namespace) -> None:
    """List all generators grouped by category."""
    categories = registry.list_categories()

    if not categories:
        print("No generators registered.")
        return

    print("\n" + "=" * 70)
    print("GENERATORS BY CATEGORY")
    print("=" * 70)

    for category in categories:
        generators = registry.get_generators_by_category(category)
        event_count = len(generators["event_types"])
        attack_count = len(generators["attack_patterns"])

        print(f"\n  {category.value.upper()}")
        print("  " + "-" * 40)
        print(f"    Event Types:     {event_count}")
        print(f"    Attack Patterns: {attack_count}")

        if generators["event_types"]:
            print(f"    Events: {', '.join(generators['event_types'][:5])}")
            if len(generators["event_types"]) > 5:
                print(f"            ... and {len(generators['event_types']) - 5} more")

    print("\n" + "=" * 70)


def _list_feature_tests(args: argparse.Namespace) -> None:
    """List available feature tests."""
    # Import here to avoid circular imports
    try:
        from secgen.features.definitions import get_feature_tests
        features = get_feature_tests()
    except ImportError:
        # Features module not yet implemented
        features = {
            "network-map": "Network Map visualization with geo-diverse flows",
            "timeline": "Correlated events for Timeline investigation",
            "analyzer": "Process tree for Analyzer visualization",
            "entity-analytics": "Entity Analytics with risk scores",
            "detection-rule": "Malicious events for detection rule testing",
            "vulnerability-management": "Vulnerability scan events",
            "cloud-posture": "CSPM compliance findings",
        }

    print("\n" + "=" * 70)
    print("FEATURE TESTS")
    print("=" * 70)
    print("\nAvailable feature tests for Elastic Security:")
    print()

    for name, description in features.items():
        print(f"  {name:30s} - {description}")

    print("\n" + "=" * 70)
    print("\nUse 'secgen test <feature-name> --index' to generate test data")

