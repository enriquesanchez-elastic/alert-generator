"""Core orchestration for generating multiple alerts."""

import json
import logging
import random
from pathlib import Path
from typing import Dict, List, Optional

from alerts_generator.config.settings import Settings
from alerts_generator.generators.alert import AlertGenerator
from alerts_generator.generators.campaign import CampaignGenerator
from alerts_generator.generators.process import ProcessEventGenerator
from alerts_generator.generators.randomizers import RandomDataGenerator
from alerts_generator.indexers.base import BaseIndexer
from alerts_generator.models.alert import AlertData
from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import Scenario
from alerts_generator.time_distribution.strategies import (
    get_campaign_phase_offset,
    get_strategy,
)

logger = logging.getLogger(__name__)


class AlertOrchestrator:
    """Orchestrates the generation of multiple alerts."""

    def __init__(
        self,
        settings: Settings,
        indexer: BaseIndexer,
        scenarios: Optional[List[Scenario]] = None,
    ) -> None:
        """
        Initialize alert orchestrator.

        Args:
            settings: Application settings
            indexer: Indexer for storing alerts
            scenarios: Optional list of scenarios (loads defaults if None)
        """
        self.settings = settings
        self.indexer = indexer
        self.randomizer = RandomDataGenerator()
        self.alert_generator = AlertGenerator(settings, self.randomizer)
        self.process_generator = ProcessEventGenerator(self.randomizer)
        self.campaign_generator = CampaignGenerator(self.randomizer)
        self.scenarios = scenarios or []

    def generate_multiple(
        self,
        count: int,
        dry_run: bool = False,
        output_file: Optional[str] = None,
        campaign_mode: bool = False,
        campaign_hosts: int = 5,
        time_spread: str = "minutes",
        working_hours: bool = False,
        attack_speed: str = "medium",
    ) -> Dict:
        """
        Generate multiple varied alerts based on different attack scenarios.

        Args:
            count: Number of alerts to generate
            dry_run: If True, generate but don't index
            output_file: If provided, save alerts to JSON file
            campaign_mode: If True, generate correlated campaign
            campaign_hosts: Number of hosts in campaign
            time_spread: Time distribution type (minutes/hours/days/weeks)
            working_hours: Weight alerts to business hours
            attack_speed: Campaign speed (fast/medium/slow)

        Returns:
            Dictionary with alerts, campaign info, and phase counts
        """
        if not self.scenarios:
            logger.error("No scenarios available. Cannot generate alerts.")
            return {
                "alerts": [],
                "campaign": None,
                "phase_counts": None,
            }

        results: List[AlertData] = []
        campaign: Optional[Campaign] = None
        phase_counts = {"initial": 0, "execution": 0, "lateral": 0, "exfiltration": 0}

        # Create campaign if in campaign mode
        if campaign_mode:
            campaign = self.campaign_generator.generate(campaign_hosts)
            logger.info(
                f"Generating Campaign: {campaign.id} "
                f"(Attacker: {campaign.attacker_ip}, "
                f"C2: {campaign.c2_domain}, "
                f"Malware: {campaign.malware_family}, "
                f"Hosts: {campaign_hosts}, "
                f"Speed: {attack_speed})"
            )

        # Get time distribution strategy
        time_strategy = get_strategy(time_spread, working_hours)

        logger.info(f"Generating {count} varied security alerts...")

        for i in range(count):
            # Determine attack phase and scenario for campaign mode
            if campaign_mode:
                phase = self.campaign_generator.determine_phase(i, count)
                phase_counts[phase] += 1

                scenario = self.campaign_generator.select_scenario_for_phase(phase, self.scenarios)

                # Get timestamp offset based on phase and attack speed
                min_offset, max_offset = get_campaign_phase_offset(phase, attack_speed)
                timestamp_offset = random.randint(min_offset, max_offset)

                # Use campaign host
                hostname = random.choice(campaign.target_hosts)
            else:
                # Random scenario selection
                scenario = random.choice(self.scenarios)

                # Calculate timestamp offset based on time spread
                timestamp_offset = time_strategy.calculate_offset(i, count)

                # Generate unique hostname
                hostname = self.randomizer.generate_hostname()
                phase = None

            # Generate unique agent ID
            agent_id = self.randomizer.generate_uuid()

            # Generate the detection rule alert
            alert, entity_ids = self.alert_generator.generate(
                scenario, hostname, agent_id, timestamp_offset, campaign
            )

            # Generate process events
            events = self.process_generator.generate(
                scenario, entity_ids, hostname, agent_id, timestamp_offset
            )

            # Generate endpoint alert
            endpoint_alert = self.alert_generator.generate_endpoint_alert(alert)

            # Index if not dry run
            indexed = False
            alert_id = None
            if not dry_run:
                events_result = self.indexer.index_events(events, endpoint_alert)
                alert_result = self.indexer.index_alert(alert)

                if events_result and alert_result:
                    indexed = True
                    alert_id = alert_result.get("_id")
                    status = "✅"
                else:
                    status = "❌"
            else:
                status = "📝"

            # Create alert data object
            alert_data = AlertData(
                alert_number=i + 1,
                scenario_name=scenario.name,
                hostname=hostname,
                severity=scenario.severity,
                process_count=len(events),
                malware_file_name=scenario.malware_file.name,
                detection_alert=alert,
                process_events=events,
                endpoint_alert=endpoint_alert,
                phase=phase,
                campaign_id=campaign.id if campaign else None,
                indexed=indexed,
                alert_id=alert_id,
            )

            # Log progress
            if campaign_mode:
                logger.info(
                    f"{status} Alert {i+1}/{count}: {phase:12s} | "
                    f"{scenario.name:25s} | Host: {hostname:20s} | "
                    f"Severity: {scenario.severity:8s}"
                )
            else:
                logger.info(
                    f"{status} Alert {i+1}/{count}: {scenario.name:25s} | "
                    f"Host: {hostname:20s} | Severity: {scenario.severity:8s} | "
                    f"Processes: {len(events)}"
                )

            results.append(alert_data)

        # Save to file if requested
        if output_file:
            output_path = Path(output_file)
            with output_path.open("w") as f:
                json.dump([alert.to_dict() for alert in results], f, indent=2, default=str)
            logger.info(f"Alerts saved to: {output_file}")

        return {
            "alerts": results,
            "campaign": campaign,
            "phase_counts": phase_counts if campaign_mode else None,
        }
