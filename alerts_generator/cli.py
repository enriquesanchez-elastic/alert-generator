"""Command-line interface for alerts generator."""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from alerts_generator.config.loader import load_scenarios_from_file
from alerts_generator.config.settings import get_settings
from alerts_generator.core import AlertOrchestrator
from alerts_generator.indexers.elasticsearch import ElasticsearchIndexer
from alerts_generator.models.scenario import Scenario
from alerts_generator.utils.logger import setup_logging


def load_scenarios(logger: logging.Logger, scenarios_file: Optional[str]) -> List[Scenario]:
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


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate multiple varied security alerts for Elastic Cloud",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Delete all logs and alerts from Elasticsearch
  python -m alerts_generator --delete-all

  # Generate 20 alerts and preview before indexing
  python -m alerts_generator --count 20

  # Generate and index immediately
  python -m alerts_generator --count 20 --index-all

  # Dry run - generate without indexing
  python -m alerts_generator --count 5 --dry-run

  # Save to file
  python -m alerts_generator --count 10 --output alerts.json

  # Generate a campaign with 10 hosts over a slow timeline
  python -m alerts_generator --count 30 --campaign --campaign-hosts 10 --attack-speed slow

  # Generate alerts spread over a week with business hours weighting
  python -m alerts_generator --count 50 --time-spread days --working-hours

  # Use custom scenarios from a file
  python -m alerts_generator --count 20 --scenarios-file custom_scenarios.yaml
        """,
    )

    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of alerts to generate (default: 10)",
    )

    parser.add_argument(
        "--index-all",
        action="store_true",
        help="Index all alerts immediately without preview",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate alerts but don't index them",
    )

    parser.add_argument("--output", type=str, help="Save generated alerts to JSON file")

    parser.add_argument(
        "--delete-all",
        action="store_true",
        help="Delete all data (logs and alerts) from Elasticsearch indices",
    )

    parser.add_argument(
        "--scenarios-file",
        type=str,
        help="Load scenarios from YAML file",
    )

    parser.add_argument(
        "--campaign",
        action="store_true",
        help="Generate correlated attack campaign",
    )

    parser.add_argument(
        "--campaign-hosts",
        type=int,
        default=5,
        help="Number of hosts in campaign (default: 5)",
    )

    parser.add_argument(
        "--time-spread",
        type=str,
        choices=["minutes", "hours", "days", "weeks"],
        default="minutes",
        help="Time range for alert distribution (default: minutes)",
    )

    parser.add_argument(
        "--working-hours",
        action="store_true",
        help="Weight alerts to business hours (8am-6pm)",
    )

    parser.add_argument(
        "--attack-speed",
        type=str,
        choices=["fast", "medium", "slow"],
        default="medium",
        help="Campaign attack speed: fast (minutes), medium (hours), slow (days) (default: medium)",
    )

    args = parser.parse_args()

    # Get settings and setup logging
    settings = get_settings()
    logger = setup_logging(settings.log_level, settings.log_json)

    logger.info("=" * 70)
    logger.info("MULTIPLE SECURITY ALERTS GENERATOR - ELASTIC CLOUD")
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

    # Handle delete-all command first
    if args.delete_all:
        indexer = ElasticsearchIndexer(settings)
        results = indexer.delete_all()
        total_deleted = (
            results["alerts_index"]["deleted_count"]
            + results["process_events"]["deleted_count"]
            + results["endpoint_alerts"]["deleted_count"]
        )
        logger.info("=" * 70)
        logger.info("DELETION SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total documents deleted: {total_deleted}")
        logger.info(f"  - Alerts: {results['alerts_index']['deleted_count']}")
        logger.info(f"  - Process events: {results['process_events']['deleted_count']}")
        logger.info(f"  - Endpoint alerts: {results['endpoint_alerts']['deleted_count']}")
        return

    # Load scenarios
    scenarios = load_scenarios(logger, args.scenarios_file)

    # Create orchestrator
    indexer = ElasticsearchIndexer(settings)
    orchestrator = AlertOrchestrator(settings, indexer, scenarios)

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
    )

    # Print summary
    print_summary(results, args.dry_run, args.count, logger)


if __name__ == "__main__":
    main()
