"""Command-line interface for alerts generator."""

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any

from secgen.config.loader import (
    create_sample_multi_event_scenario,
    load_scenarios_from_file,
)
from secgen.config.settings import get_settings
from secgen.core import AlertOrchestrator
from secgen.core.world import World
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.models.scenario import Scenario
from secgen.utils.logger import setup_logging


def load_scenarios(logger: logging.Logger, scenarios_file: str | None) -> list[Scenario]:
    """
    Load scenarios from file or default.

    Args:
        logger: Logger instance
        scenarios_file: Optional path to scenarios YAML file

    Returns:
        List of Scenario objects
    """
    if scenarios_file:
        scenarios = load_scenarios_from_file(scenarios_file)
        if scenarios is None:
            logger.error(f"Failed to load scenarios from {scenarios_file}")
            sys.exit(1)
        return scenarios

    # Try to load default scenarios
    default_file = Path(__file__).parent.parent / "alert_scenarios.yaml"
    if default_file.exists():
        scenarios = load_scenarios_from_file(str(default_file))
        if scenarios:
            return scenarios

    logger.error(
        "No scenarios available. Please provide --scenarios-file or ensure alert_scenarios.yaml exists."
    )
    sys.exit(1)


def print_summary(results: dict, dry_run: bool, count: int, logger: logging.Logger) -> None:
    """Print generation summary."""
    alerts = results["alerts"]
    campaign = results.get("campaign")
    phase_counts = results.get("phase_counts")

    logger.info("=" * 70)
    logger.info("GENERATION SUMMARY")
    logger.info("=" * 70)

    # Campaign-specific summary
    if campaign:
        logger.info("Campaign Details:")
        logger.info(f"  Campaign ID: {campaign.id}")
        logger.info(f"  Attacker IP: {campaign.attacker_ip}")
        logger.info(f"  C2 Server: {campaign.c2_domain} ({campaign.c2_ip})")
        logger.info(f"  Malware Family: {campaign.malware_family}")
        logger.info(f"  Affected Hosts: {len(campaign.target_hosts)}")
        for host in campaign.target_hosts:
            logger.info(f"    - {host}")

        if phase_counts:
            logger.info("Phase Distribution:")
            max_count = max(phase_counts.values()) if phase_counts else 1
            for phase, phase_count in phase_counts.items():
                bar_length = int((phase_count / max_count) * 30)
                bar = "█" * bar_length
                logger.info(f"    {phase:15s} [{bar:30s}] {phase_count:3d} alerts")

    # Count by scenario
    scenario_counts: dict = {}
    severity_counts: dict = {}
    for alert_data in alerts:
        scenario = alert_data.scenario_name
        severity = alert_data.severity
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    logger.info("Scenario Distribution:")
    for scenario, count in sorted(scenario_counts.items()):
        logger.info(f"  {scenario:30s}: {count:3d} alerts")

    logger.info("Severity Distribution:")
    for severity, count in sorted(severity_counts.items()):
        logger.info(f"  {severity:10s}: {count:3d} alerts")

    if not dry_run:
        indexed_count = sum(1 for a in alerts if a.indexed)
        logger.info(f"Successfully indexed: {indexed_count}/{count} alerts")
        logger.info("To view in Kibana:")
        logger.info("   1. Go to Security → Alerts")
        logger.info("   2. Filter by 'Endpoint Security' rule")
        logger.info("   3. Click on any alert to view details")
    else:
        logger.info(f"Dry run complete - {count} alerts generated (not indexed)")


def cmd_world(args: argparse.Namespace, logger: logging.Logger) -> None:
    """Handle world management commands."""
    if args.world_action == "create":
        logger.info("Creating new World state...")
        world = World()
        world.populate(
            num_hosts=args.hosts,
            num_users=args.users,
        )

        summary = world.summary()
        logger.info("World created:")
        logger.info(f"  Hosts: {summary['total_hosts']}")
        for os, count in summary["hosts_by_os"].items():
            logger.info(f"    - {os}: {count}")
        logger.info(f"  Users: {summary['total_users']}")
        for utype, count in summary["users_by_type"].items():
            logger.info(f"    - {utype}: {count}")
        logger.info(f"  Threat Actors: {summary['threat_actors']}")

        if args.save:
            world.save(args.save)
            logger.info(f"World saved to: {args.save}")

    elif args.world_action == "load":
        if not args.load:
            logger.error("--load required for load action")
            return

        logger.info(f"Loading World from: {args.load}")
        world = World.load(args.load)
        summary = world.summary()
        logger.info("World loaded:")
        logger.info(f"  Created: {summary['created_at']}")
        logger.info(f"  Hosts: {summary['total_hosts']}")
        logger.info(f"  Users: {summary['total_users']}")
        logger.info(f"  Threat Actors: {summary['threat_actors']}")

    elif args.world_action == "info":
        if not args.load:
            logger.error("--load required for info action")
            return

        world = World.load(args.load)
        summary = world.summary()

        print("\n" + "=" * 50)
        print("WORLD STATE INFORMATION")
        print("=" * 50)
        print(f"Created: {summary['created_at']}")
        print(f"\nHosts ({summary['total_hosts']} total):")
        for os, count in summary["hosts_by_os"].items():
            print(f"  {os}: {count}")
        print(f"\nUsers ({summary['total_users']} total):")
        for utype, count in summary["users_by_type"].items():
            print(f"  {utype}: {count}")
        print(f"\nThreat Actors: {summary['threat_actors']}")
        print(f"Active Campaigns: {summary['active_campaigns']}")
        print("=" * 50)


def cmd_generate(args: argparse.Namespace, logger: logging.Logger, settings: Any) -> None:
    """Handle advanced generate command with World state."""
    # Check for LLM features - full-llm implies use_llm_artifacts
    full_llm = getattr(args, "full_llm", False)
    use_llm = getattr(args, "use_llm_artifacts", False) or full_llm
    llm_industry = getattr(args, "industry", "technology")
    llm_threat_actor = getattr(args, "threat_actor", "APT29")
    llm_target_os = getattr(args, "target_os", "windows")
    force_regenerate = getattr(args, "force_regenerate", False)

    if use_llm and not settings.gemini_api_key:
        logger.warning(
            "LLM artifacts requested but GEMINI_API_KEY not set. "
            "Continuing without LLM features."
        )
        use_llm = False
        full_llm = False

    # Load or create world
    world = None
    if args.world_file:
        logger.info(f"Loading World from: {args.world_file}")
        world = World.load(args.world_file)
    elif args.use_world or use_llm:
        logger.info("Creating ephemeral World state...")
        world = World()
        world.populate(num_hosts=args.hosts, num_users=args.users)

    # Load scenarios
    scenarios = load_scenarios(logger, args.scenario)

    # Create orchestrator with world
    indexer = ElasticsearchIndexer(settings)
    orchestrator = AlertOrchestrator(settings, indexer, scenarios, world)

    # Full LLM mode: prepare ALL artifacts first (commands, scenarios, profiles, campaigns)
    if full_llm:
        logger.info("=" * 70)
        logger.info("FULL LLM MODE: Preparing all artifacts...")
        logger.info("=" * 70)

        llm_results = orchestrator.prepare_all_llm_artifacts(
            industry=llm_industry,
            org_size="medium",
            target_os=llm_target_os,
            threat_actor=llm_threat_actor,
            target_sector=llm_industry,
            campaign_days=14,
            force_regenerate=force_regenerate,
        )

        if llm_results.get("success"):
            logger.info(f"  Commands: {llm_results['commands']}")
            logger.info(f"  Scenarios: {llm_results['scenarios']}")
            logger.info(f"  Profiles: {llm_results['profiles']}")
            logger.info(f"  Campaign: {'Yes' if llm_results['campaign'] else 'No'}")
            tokens = llm_results.get("token_usage", {})
            if tokens.get("total", 0) > 0:
                logger.info(f"  Token usage: {tokens['total']} total")
        else:
            logger.warning(f"LLM artifact preparation failed: {llm_results.get('error')}")

        logger.info("=" * 70)
    elif use_llm:
        logger.info(f"LLM artifacts: Enabled (industry: {llm_industry})")

    # Generate and index events
    results = orchestrator.generate_multiple(
        count=args.count,
        dry_run=args.dry_run,
        output_file=args.output,
        campaign_mode=args.campaign,
        campaign_hosts=args.hosts,
        time_spread=args.time_spread,
        working_hours=args.working_hours,
        attack_speed=args.speed,
        use_world=args.use_world or args.world_file is not None or use_llm,
        use_llm_artifacts=use_llm,
        llm_industry=llm_industry,
    )

    # Save world if requested
    if results.get("world") and args.save_world:
        results["world"].save(args.save_world)
        logger.info(f"World state saved to: {args.save_world}")

    print_summary(results, args.dry_run, args.count, logger)


def cmd_perf_test(args: argparse.Namespace, logger: logging.Logger, settings: Any) -> None:
    """Run performance test for event generation."""
    from secgen.generators.endpoint import (
        EndpointNetworkEventGenerator,
        FileEventGenerator,
    )
    from secgen.generators.identity import AuthenticationEventGenerator
    from secgen.generators.network import DNSEventGenerator, NetworkFlowGenerator

    logger.info("=" * 70)
    logger.info("PERFORMANCE TEST")
    logger.info("=" * 70)

    event_count = args.events
    generators = {
        "file": FileEventGenerator(),
        "network": EndpointNetworkEventGenerator(),
        "dns": DNSEventGenerator(),
        "flow": NetworkFlowGenerator(),
        "auth": AuthenticationEventGenerator(),
    }

    if args.types:
        generators = {k: v for k, v in generators.items() if k in args.types}

    results: dict[str, dict[str, Any]] = {}

    for name, gen in generators.items():
        logger.info(f"Testing {name} generator...")

        start_time = time.time()
        if hasattr(gen, "generate_batch"):
            events = gen.generate_batch(event_count)
        else:
            events = [gen.generate() for _ in range(event_count)]
        elapsed = time.time() - start_time

        results[name] = {
            "count": len(events),
            "time_seconds": elapsed,
            "events_per_second": len(events) / elapsed if elapsed > 0 else 0,
        }

        logger.info(f"  Generated {len(events)} events in {elapsed:.2f}s")
        logger.info(f"  Rate: {results[name]['events_per_second']:.0f} events/second")

    # Index if requested
    if not args.dry_run:
        indexer = ElasticsearchIndexer(settings)
        logger.info("\nIndexing test events...")

        for name, gen in generators.items():
            events = gen.generate_batch(min(1000, event_count))
            event_type = {
                "file": "file",
                "network": "network",
                "dns": "dns",
                "flow": "network_flow",
                "auth": "authentication",
            }.get(name, name)

            start_time = time.time()
            result = indexer.index_typed_events(events, event_type)
            elapsed = time.time() - start_time

            if result:
                logger.info(f"  {name}: indexed {len(events)} events in {elapsed:.2f}s")

    # Print summary
    print("\n" + "=" * 50)
    print("PERFORMANCE TEST RESULTS")
    print("=" * 50)
    for name, data in results.items():
        print(
            f"{name:15s}: {data['events_per_second']:8.0f} events/sec ({data['count']} in {data['time_seconds']:.2f}s)"
        )
    print("=" * 50)


def cmd_sample_scenario(args: argparse.Namespace, logger: logging.Logger) -> None:
    """Generate sample multi-event scenario YAML."""
    sample = create_sample_multi_event_scenario()

    if args.output:
        Path(args.output).write_text(sample)
        logger.info(f"Sample scenario saved to: {args.output}")
    else:
        print(sample)


def cmd_llm(args: argparse.Namespace, logger: logging.Logger, settings: Any) -> None:
    """Handle LLM artifact generation commands."""
    # Check for API key
    if not settings.gemini_api_key:
        logger.error("Gemini API key not configured. Set GEMINI_API_KEY environment variable.")
        return

    try:
        from secgen.llm.cache import ArtifactCache
        from secgen.llm.client import GeminiClient
        from secgen.llm.generators import (
            CampaignNarrativeGenerator,
            CommandLibraryGenerator,
            EntityProfileGenerator,
            ScenarioVariationGenerator,
        )
    except ImportError as e:
        logger.error(f"LLM dependencies not installed: {e}")
        logger.error("Install with: pip install google-generativeai")
        return

    # Initialize client and cache
    client = GeminiClient(
        api_key=settings.gemini_api_key,
        model=settings.gemini_model,
    )
    cache = ArtifactCache(
        base_dir=settings.llm_artifacts_path,
        enabled=settings.llm_cache_enabled,
    )

    action = args.llm_action

    if action == "commands":
        generator = CommandLibraryGenerator(client=client, cache=cache)

        if args.list_tactics:
            print("Available tactics:")
            for tactic in generator.list_tactics():
                print(f"  - {tactic}")
            return

        logger.info(f"Generating command library for tactic: {args.tactic}")
        data = generator.generate_or_load(
            force_regenerate=args.force,
            tactic=args.tactic,
            count=args.count,
            threat_actor_style=args.actor,
            os_family=args.os,
        )

        print(f"\nGenerated {data.get('count_generated', 0)} commands for '{args.tactic}'")
        for category, cmds in data.get("commands", {}).items():
            print(f"\n  {category}:")
            for cmd in cmds[:3]:  # Show first 3
                print(f"    - {cmd[:80]}...")
            if len(cmds) > 3:
                print(f"    ... and {len(cmds) - 3} more")

    elif action == "scenarios":
        generator = ScenarioVariationGenerator(client=client, cache=cache)

        logger.info(f"Generating {args.variations} scenario variations for: {args.base}")
        data = generator.generate_or_load(
            force_regenerate=args.force,
            base_name=args.base,
            base_description=f"{args.base} attack scenario",
            base_severity="high",
            variation_count=args.variations,
            target_os=args.os,
        )

        print(f"\nGenerated {data.get('variation_count_generated', 0)} variations:")
        for scenario in data.get("scenarios", []):
            print(f"  - {scenario.get('name', 'Unknown')}")
            if scenario.get("ttps"):
                print(f"    TTPs: {', '.join(scenario['ttps'][:3])}")

    elif action == "profiles":
        generator = EntityProfileGenerator(client=client, cache=cache)

        if args.list_industries:
            print("Available industries:")
            for industry in generator.list_industries():
                print(f"  - {industry}")
            return

        logger.info(f"Generating {args.roles} entity profiles for {args.industry}")
        data = generator.generate_or_load(
            force_regenerate=args.force,
            industry=args.industry,
            role_count=args.roles,
            org_size=args.org_size,
        )

        print(f"\nGenerated {data.get('role_count_generated', 0)} personas:")
        for persona in data.get("personas", []):
            role = persona.get("role", "Unknown")
            dept = persona.get("department", "")
            priv = persona.get("privilege_level", "standard")
            print(f"  - {role} ({dept}) [{priv}]")

    elif action == "campaign":
        generator = CampaignNarrativeGenerator(client=client, cache=cache)

        if args.list_actors:
            print("Available threat actors:")
            for actor in generator.list_threat_actors():
                profile = generator.get_threat_actor_profile(actor)
                print(f"  - {actor}: {profile}")
            return

        if args.list_objectives:
            print("Available objectives:")
            for obj in generator.list_objectives():
                desc = generator.get_objective_description(obj)
                print(f"  - {obj}: {desc}")
            return

        logger.info(
            f"Generating campaign narrative: {args.actor} targeting {args.target} "
            f"({args.days} days, objective: {args.objective})"
        )
        data = generator.generate_or_load(
            force_regenerate=args.force,
            threat_actor=args.actor,
            target_sector=args.target,
            dwell_time_days=args.days,
            objective=args.objective,
            org_size=args.org_size,
            target_os=args.os,
        )

        campaign = data.get("campaign", {})
        print(f"\nCampaign: {campaign.get('name', 'Unknown')}")
        print(f"Threat Actor: {campaign.get('threat_actor')}")
        print(f"Objective: {campaign.get('objective')}")

        phases = campaign.get("phases", [])
        print(f"\nPhases ({len(phases)} total):")
        for phase in phases:
            day = phase.get("day", "?")
            name = phase.get("name", "unknown")
            ttp = phase.get("ttp", "")
            print(f"  Day {day}: {name} [{ttp}]")

        infra = campaign.get("infrastructure", {})
        if infra:
            print("\nInfrastructure:")
            if infra.get("c2_domains"):
                print(f"  C2 Domains: {', '.join(infra['c2_domains'][:3])}")
            if infra.get("malware_family"):
                print(f"  Malware: {infra['malware_family']}")

    elif action == "cache":
        if args.cache_action == "stats":
            stats = cache.get_stats()
            print("\nArtifact Cache Statistics:")
            print(f"  Location: {stats['base_dir']}")
            print(f"  Enabled: {stats['enabled']}")
            print(f"  Total Artifacts: {stats['total_artifacts']}")
            print(f"  Total Size: {stats['total_size_bytes'] / 1024:.1f} KB")
            print("\n  By Type:")
            for atype, info in stats.get("by_type", {}).items():
                print(f"    {atype}: {info['count']} ({info['size_bytes'] / 1024:.1f} KB)")

        elif args.cache_action == "list":
            artifact_type = args.type
            if artifact_type:
                artifacts = cache.list_artifacts(artifact_type)
                print(f"\n{artifact_type.title()} Artifacts:")
                for a in artifacts:
                    print(f"  - {a['name']}.{a['extension']} ({a['size_bytes']} bytes)")
            else:
                for atype in cache.SUBDIRS:
                    artifacts = cache.list_artifacts(atype)
                    if artifacts:
                        print(f"\n{atype.title()}:")
                        for a in artifacts:
                            print(f"  - {a['name']}.{a['extension']}")

        elif args.cache_action == "clear":
            if args.type:
                count = cache.clear(args.type)
                print(f"Cleared {count} {args.type} artifacts")
            else:
                count = cache.clear()
                print(f"Cleared {count} total artifacts")

    # Print token usage
    if hasattr(client, "total_tokens_used"):
        usage = client.total_tokens_used
        if usage["total_tokens"] > 0:
            print(
                f"\nToken usage: {usage['total_tokens']} total "
                f"({usage['prompt_tokens']} prompt, {usage['completion_tokens']} completion)"
            )


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Security Data Generator for Elastic Cloud",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (default)       Legacy alert generation mode
  world           Manage World state (entities)
  generate        Generate events (legacy or by event type)
  list            List available event types and attack patterns
  describe        Show details about event types or attacks
  attack          Execute attack patterns
  test            Test Elastic Security features
  preset          Run preset configurations
  perf-test       Performance testing
  sample-scenario Generate sample multi-event scenario YAML
  llm             LLM-powered artifact generation

Examples:
  # Discovery - list event types
  python -m secgen list event-types
  python -m secgen list attack-patterns --ttp T1110

  # Describe event type or attack
  python -m secgen describe event-type dns
  python -m secgen describe attack brute-force

  # Generate specific event types
  python -m secgen generate dns --count 50
  python -m secgen generate dns --count 50 --param is_malicious=true --index

  # Execute attack patterns
  python -m secgen attack brute-force --count 3 --index
  python -m secgen attack c2-beacon --world-file qa-world.json

  # Feature testing
  python -m secgen test network-map --index
  python -m secgen test timeline --index

  # Presets
  python -m secgen preset demo-cluster
  python -m secgen preset load-test

  # Legacy mode - generate alerts
  python -m secgen --count 20

  # Create and save a World state
  python -m secgen world create --hosts 50 --users 100 --save world.json

  # Generate with World state correlation (legacy)
  python -m secgen generate --count 30 --world-file world.json --campaign

  # Performance test
  python -m secgen perf-test --events 10000 --types file network dns
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # World subcommand
    world_parser = subparsers.add_parser("world", help="Manage World state")
    world_parser.add_argument(
        "world_action",
        choices=["create", "load", "info"],
        help="World action",
    )
    world_parser.add_argument("--hosts", type=int, default=50, help="Number of hosts")
    world_parser.add_argument("--users", type=int, default=100, help="Number of users")
    world_parser.add_argument("--save", type=str, help="Save world to file")
    world_parser.add_argument("--load", type=str, help="Load world from file")

    # Generate subcommand (supports both legacy and event-type modes)
    gen_parser = subparsers.add_parser("generate", help="Generate events (by type or legacy mode)")
    gen_parser.add_argument(
        "event_type", nargs="?", help="Event type to generate (e.g., dns, file, process)"
    )
    gen_parser.add_argument("--count", type=int, default=10, help="Number of events")
    gen_parser.add_argument("--param", action="append", help="Parameter key=value (can repeat)")
    gen_parser.add_argument("--scenario", type=str, help="Scenario file (legacy mode)")
    gen_parser.add_argument("--world-file", type=str, help="Load World from file")
    gen_parser.add_argument("--use-world", action="store_true", help="Use ephemeral World")
    gen_parser.add_argument("--hosts", type=int, default=10, help="Hosts for ephemeral World")
    gen_parser.add_argument("--users", type=int, default=20, help="Users for ephemeral World")
    gen_parser.add_argument("--save-world", type=str, help="Save World after generation")
    gen_parser.add_argument("--campaign", action="store_true", help="Campaign mode (legacy)")
    gen_parser.add_argument("--dry-run", action="store_true", help="Don't index")
    gen_parser.add_argument("--index", action="store_true", help="Index to Elasticsearch")
    gen_parser.add_argument("--output", type=str, help="Save to JSON file")
    gen_parser.add_argument("--json", action="store_true", help="Output JSON format")
    gen_parser.add_argument(
        "--time-spread", default="minutes", choices=["minutes", "hours", "days", "weeks"]
    )
    gen_parser.add_argument("--working-hours", action="store_true")
    gen_parser.add_argument("--speed", default="medium", choices=["fast", "medium", "slow"])
    gen_parser.add_argument(
        "--use-llm-artifacts", action="store_true", help="Use LLM-generated artifacts"
    )
    gen_parser.add_argument("--industry", default="technology", help="Industry for LLM profiles")
    gen_parser.add_argument(
        "--full-llm",
        action="store_true",
        help="Full LLM mode: generate ALL artifacts (commands, scenarios, profiles, campaigns) then events",
    )
    gen_parser.add_argument("--threat-actor", default="APT29", help="Threat actor for LLM campaign")
    gen_parser.add_argument("--target-os", default="windows", choices=["windows", "linux", "macos"])
    gen_parser.add_argument(
        "--force-regenerate", action="store_true", help="Force LLM artifact regeneration"
    )

    # List subcommand
    list_parser = subparsers.add_parser("list", help="List event types and attack patterns")
    list_parser.add_argument(
        "list_type",
        choices=["event-types", "attack-patterns", "generators", "feature-tests"],
        help="What to list",
    )
    list_parser.add_argument("--filter", type=str, help="Filter by category")
    list_parser.add_argument("--ttp", type=str, help="Filter attack patterns by MITRE TTP")

    # Describe subcommand
    describe_parser = subparsers.add_parser("describe", help="Describe event type or attack")
    describe_parser.add_argument(
        "describe_type",
        choices=["event-type", "attack"],
        help="What to describe",
    )
    describe_parser.add_argument("name", help="Name of event type or attack pattern")

    # Attack subcommand
    attack_parser = subparsers.add_parser("attack", help="Execute attack patterns")
    attack_parser.add_argument("pattern", help="Attack pattern name (e.g., brute-force)")
    attack_parser.add_argument("--count", type=int, default=1, help="Number of iterations")
    attack_parser.add_argument("--world-file", type=str, help="Load World from file")
    attack_parser.add_argument("--use-world", action="store_true", help="Use ephemeral World")
    attack_parser.add_argument("--index", action="store_true", help="Index to Elasticsearch")
    attack_parser.add_argument("--dry-run", action="store_true", help="Don't index")
    attack_parser.add_argument("--output", type=str, help="Save to JSON file")
    attack_parser.add_argument("--json", action="store_true", help="Output JSON format")

    # Test subcommand
    test_parser = subparsers.add_parser("test", help="Test Elastic Security features")
    test_parser.add_argument(
        "feature",
        choices=[
            "network-map",
            "timeline",
            "analyzer",
            "entity-analytics",
            "detection-rule",
            "vulnerability-management",
            "cloud-posture",
        ],
        help="Feature to test",
    )
    test_parser.add_argument("--count", type=int, help="Override default event count")
    test_parser.add_argument("--index", action="store_true", help="Index to Elasticsearch")
    test_parser.add_argument("--dry-run", action="store_true", help="Don't index")
    test_parser.add_argument("--output", type=str, help="Save to JSON file")
    test_parser.add_argument("--json", action="store_true", help="Output JSON format")

    # Preset subcommand
    preset_parser = subparsers.add_parser("preset", help="Run preset configurations")
    preset_parser.add_argument("preset_name", nargs="?", help="Preset name or YAML file path")
    preset_parser.add_argument(
        "--list", "-l", action="store_true", help="List all available presets"
    )
    preset_parser.add_argument(
        "--no-index", action="store_true", help="Don't index to Elasticsearch"
    )
    preset_parser.add_argument("--output", type=str, help="Save all events to JSON file")
    preset_parser.add_argument("--json", action="store_true", help="Output JSON format")

    # LLM subcommand
    llm_parser = subparsers.add_parser("llm", help="LLM-powered artifact generation")
    llm_subparsers = llm_parser.add_subparsers(dest="llm_action", help="LLM actions")

    # LLM commands subcommand
    llm_cmd_parser = llm_subparsers.add_parser("commands", help="Generate command libraries")
    llm_cmd_parser.add_argument("--tactic", default="execution", help="MITRE ATT&CK tactic")
    llm_cmd_parser.add_argument("--count", type=int, default=30, help="Number of commands")
    llm_cmd_parser.add_argument("--actor", default="generic_apt", help="Threat actor style")
    llm_cmd_parser.add_argument("--os", default="windows", choices=["windows", "linux", "macos"])
    llm_cmd_parser.add_argument("--force", action="store_true", help="Force regeneration")
    llm_cmd_parser.add_argument(
        "--list-tactics", action="store_true", help="List available tactics"
    )

    # LLM scenarios subcommand
    llm_scn_parser = llm_subparsers.add_parser("scenarios", help="Generate scenario variations")
    llm_scn_parser.add_argument("--base", default="Ransomware", help="Base scenario name")
    llm_scn_parser.add_argument("--variations", type=int, default=5, help="Number of variations")
    llm_scn_parser.add_argument("--os", default="windows", choices=["windows", "linux", "macos"])
    llm_scn_parser.add_argument("--force", action="store_true", help="Force regeneration")

    # LLM profiles subcommand
    llm_prof_parser = llm_subparsers.add_parser("profiles", help="Generate entity profiles")
    llm_prof_parser.add_argument("--industry", default="technology", help="Industry vertical")
    llm_prof_parser.add_argument("--roles", type=int, default=10, help="Number of roles")
    llm_prof_parser.add_argument(
        "--org-size", default="medium", choices=["small", "medium", "large"]
    )
    llm_prof_parser.add_argument("--force", action="store_true", help="Force regeneration")
    llm_prof_parser.add_argument("--list-industries", action="store_true", help="List industries")

    # LLM campaign subcommand
    llm_camp_parser = llm_subparsers.add_parser("campaign", help="Generate campaign narratives")
    llm_camp_parser.add_argument("--actor", default="APT29", help="Threat actor")
    llm_camp_parser.add_argument("--target", default="technology", help="Target sector")
    llm_camp_parser.add_argument("--days", type=int, default=14, help="Campaign duration (days)")
    llm_camp_parser.add_argument("--objective", default="data_theft", help="Campaign objective")
    llm_camp_parser.add_argument(
        "--org-size", default="medium", choices=["small", "medium", "large"]
    )
    llm_camp_parser.add_argument("--os", default="windows", choices=["windows", "linux", "macos"])
    llm_camp_parser.add_argument("--force", action="store_true", help="Force regeneration")
    llm_camp_parser.add_argument("--list-actors", action="store_true", help="List threat actors")
    llm_camp_parser.add_argument("--list-objectives", action="store_true", help="List objectives")

    # LLM cache subcommand
    llm_cache_parser = llm_subparsers.add_parser("cache", help="Manage artifact cache")
    llm_cache_parser.add_argument(
        "cache_action",
        choices=["stats", "list", "clear"],
        help="Cache action",
    )
    llm_cache_parser.add_argument(
        "--type", help="Artifact type (commands, scenarios, profiles, campaigns)"
    )

    # Perf-test subcommand
    perf_parser = subparsers.add_parser("perf-test", help="Performance testing")
    perf_parser.add_argument("--events", type=int, default=10000, help="Events to generate")
    perf_parser.add_argument("--types", nargs="+", help="Event types to test")
    perf_parser.add_argument("--dry-run", action="store_true", help="Don't index")

    # Sample-scenario subcommand
    sample_parser = subparsers.add_parser("sample-scenario", help="Generate sample scenario")
    sample_parser.add_argument("--output", type=str, help="Output file")

    # MCP subcommand
    mcp_parser = subparsers.add_parser("mcp", help="Start MCP server for Claude Desktop")
    mcp_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level for MCP server",
    )

    # Legacy arguments (for backward compatibility)
    parser.add_argument("--count", type=int, default=10, help="Number of alerts")
    parser.add_argument("--index-all", action="store_true", help="Index immediately")
    parser.add_argument("--dry-run", action="store_true", help="Don't index")
    parser.add_argument("--output", type=str, help="Save to JSON")
    parser.add_argument("--delete-all", action="store_true", help="Delete all data")
    parser.add_argument("--scenarios-file", type=str, help="Scenarios YAML")
    parser.add_argument("--campaign", action="store_true", help="Campaign mode")
    parser.add_argument("--campaign-hosts", type=int, default=5, help="Campaign hosts")
    parser.add_argument(
        "--time-spread", default="minutes", choices=["minutes", "hours", "days", "weeks"]
    )
    parser.add_argument("--working-hours", action="store_true")
    parser.add_argument("--attack-speed", default="medium", choices=["fast", "medium", "slow"])
    parser.add_argument("--use-world", action="store_true", help="Enable World state correlation")

    args = parser.parse_args()

    # Get settings and setup logging
    settings = get_settings()
    logger = setup_logging(settings.log_level, settings.log_json)

    # Route to appropriate command handler
    if args.command == "world":
        cmd_world(args, logger)
        return

    if args.command == "generate":
        # Check if this is event-type mode or legacy mode
        if hasattr(args, "event_type") and args.event_type:
            # New event-type mode
            from secgen.handlers.generate_handler import handle_generate

            handle_generate(args)
            return
        else:
            # Legacy mode
            cmd_generate(args, logger, settings)
            return

    if args.command == "list":
        from secgen.handlers.list_handler import handle_list

        handle_list(args)
        return

    if args.command == "describe":
        from secgen.handlers.describe_handler import handle_describe

        handle_describe(args)
        return

    if args.command == "attack":
        from secgen.handlers.attack_handler import handle_attack

        handle_attack(args)
        return

    if args.command == "test":
        from secgen.handlers.test_handler import handle_test

        handle_test(args)
        return

    if args.command == "preset":
        from secgen.handlers.preset_handler import handle_preset

        handle_preset(args)
        return

    if args.command == "perf-test":
        cmd_perf_test(args, logger, settings)
        return

    if args.command == "sample-scenario":
        cmd_sample_scenario(args, logger)
        return

    if args.command == "mcp":
        import asyncio

        # Import and run MCP server
        # Note: MCP server's main() handles all logging configuration internally
        # to ensure stdout remains clean for JSON-RPC protocol
        from secgen.mcp.server import main as mcp_main

        asyncio.run(mcp_main())
        return

    if args.command == "llm":
        cmd_llm(args, logger, settings)
        return

    # Legacy mode
    logger.info("=" * 70)
    logger.info("SECURITY DATA GENERATOR - ELASTIC CLOUD")
    logger.info("=" * 70)
    logger.info(f"Target: {settings.elastic_url}")
    logger.info(f"Alert count: {args.count}")
    logger.info(f"Mode: {'Dry Run' if args.dry_run else 'Index to Elasticsearch'}")
    logger.info(f"Time spread: {args.time_spread}")
    if args.working_hours:
        logger.info("Working hours: Enabled (weighted to business hours)")
    if args.campaign:
        logger.info(
            f"Campaign mode: Enabled ({args.campaign_hosts} hosts, {args.attack_speed} speed)"
        )
    if args.use_world:
        logger.info("World state: Enabled (entity correlation)")

    # Handle delete-all command first
    if args.delete_all:
        indexer = ElasticsearchIndexer(settings)
        results = indexer.delete_all()
        total_deleted = sum(r["deleted_count"] for r in results.values())
        logger.info("=" * 70)
        logger.info("DELETION SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total documents deleted: {total_deleted}")
        for name, data in results.items():
            if data["deleted_count"] > 0:
                logger.info(f"  - {name}: {data['deleted_count']}")
        return

    # Load scenarios
    scenarios = load_scenarios(logger, args.scenarios_file)

    # Create world if requested
    world = None
    if args.use_world:
        world = World()
        num_hosts = args.campaign_hosts if args.campaign else 10
        world.populate(num_hosts=num_hosts, num_users=num_hosts * 3)
        logger.info(f"Created World with {len(world.hosts)} hosts and {len(world.users)} users")

    # Create orchestrator
    indexer = ElasticsearchIndexer(settings)
    orchestrator = AlertOrchestrator(settings, indexer, scenarios, world)

    # Generate alerts
    results = orchestrator.generate_multiple(
        count=args.count,
        dry_run=args.dry_run,
        output_file=args.output,
        campaign_mode=args.campaign,
        campaign_hosts=args.campaign_hosts,
        time_spread=args.time_spread,
        working_hours=args.working_hours,
        attack_speed=args.attack_speed,
        use_world=args.use_world,
    )

    # Print summary
    print_summary(results, args.dry_run, args.count, logger)


if __name__ == "__main__":
    main()
