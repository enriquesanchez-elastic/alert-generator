"""Core orchestration for generating multiple alerts."""

import json
import logging
import random
from pathlib import Path
from typing import TYPE_CHECKING

from secgen.config.settings import Settings
from secgen.core.world import World
from secgen.generators.alert import AlertGenerator
from secgen.generators.campaign import CampaignGenerator
from secgen.generators.process import ProcessEventGenerator
from secgen.generators.randomizers import RandomDataGenerator
from secgen.indexers.base import BaseIndexer
from secgen.models.alert import AlertData
from secgen.models.campaign import Campaign
from secgen.models.entities import Host, User
from secgen.models.scenario import Scenario
from secgen.time_distribution.strategies import (
    get_campaign_phase_offset,
    get_strategy,
)

if TYPE_CHECKING:
    from secgen.llm.cache import ArtifactCache
    from secgen.llm.client import GeminiClient
    from secgen.llm.generators import (
        CampaignNarrativeGenerator,
        CommandLibraryGenerator,
        EntityProfileGenerator,
        ScenarioVariationGenerator,
    )

logger = logging.getLogger(__name__)


class AlertOrchestrator:
    """Orchestrates the generation of multiple alerts."""

    def __init__(
        self,
        settings: Settings,
        indexer: BaseIndexer,
        scenarios: list[Scenario] | None = None,
        world: World | None = None,
    ) -> None:
        """
        Initialize alert orchestrator.

        Args:
            settings: Application settings
            indexer: Indexer for storing alerts
            scenarios: Optional list of scenarios (loads defaults if None)
            world: Optional World state for entity correlation
        """
        self.settings = settings
        self.indexer = indexer
        self.randomizer = RandomDataGenerator()
        self.alert_generator = AlertGenerator(settings, self.randomizer)
        self.process_generator = ProcessEventGenerator(self.randomizer)
        self.campaign_generator = CampaignGenerator(self.randomizer)
        self.scenarios = scenarios or []
        self.world = world

        # LLM components (initialized lazily)
        self._llm_client: GeminiClient | None = None
        self._artifact_cache: ArtifactCache | None = None
        self._command_generator: CommandLibraryGenerator | None = None
        self._scenario_generator: ScenarioVariationGenerator | None = None
        self._profile_generator: EntityProfileGenerator | None = None
        self._campaign_narrative_generator: CampaignNarrativeGenerator | None = None
        self._llm_scenarios: list[Scenario] = []

    def _init_llm_components(self) -> bool:
        """
        Initialize LLM components if API key is available.

        Returns:
            True if LLM components were initialized successfully
        """
        if self._llm_client is not None:
            return True  # Already initialized

        if not self.settings.gemini_api_key:
            logger.warning("Gemini API key not configured, LLM features disabled")
            return False

        try:
            from secgen.llm.cache import ArtifactCache
            from secgen.llm.client import GeminiClient
            from secgen.llm.generators import (
                CampaignNarrativeGenerator,
                CommandLibraryGenerator,
                EntityProfileGenerator,
                ScenarioVariationGenerator,
            )

            self._llm_client = GeminiClient(
                api_key=self.settings.gemini_api_key,
                model=self.settings.gemini_model,
            )
            self._artifact_cache = ArtifactCache(
                base_dir=self.settings.llm_artifacts_path,
                enabled=self.settings.llm_cache_enabled,
            )

            self._command_generator = CommandLibraryGenerator(
                client=self._llm_client,
                cache=self._artifact_cache,
            )
            self._scenario_generator = ScenarioVariationGenerator(
                client=self._llm_client,
                cache=self._artifact_cache,
            )
            self._profile_generator = EntityProfileGenerator(
                client=self._llm_client,
                cache=self._artifact_cache,
            )
            self._campaign_narrative_generator = CampaignNarrativeGenerator(
                client=self._llm_client,
                cache=self._artifact_cache,
            )

            logger.info("LLM components initialized successfully")
            return True

        except ImportError as e:
            logger.warning(f"LLM dependencies not available: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize LLM components: {e}")
            return False

    def load_llm_scenarios(
        self,
        base_scenarios: list[Scenario] | None = None,
        variations_per_base: int = 3,
        target_os: str = "windows",
    ) -> int:
        """
        Load scenario variations from LLM generator.

        Args:
            base_scenarios: Base scenarios to generate variations from
            variations_per_base: Number of variations per base scenario
            target_os: Target operating system

        Returns:
            Number of scenarios loaded
        """
        if not self._init_llm_components():
            return 0

        if self._scenario_generator is None:
            return 0

        base_scenarios = base_scenarios or self.scenarios

        if not base_scenarios:
            logger.warning("No base scenarios available for variation generation")
            return 0

        try:
            # Generate variations
            all_variations = self._scenario_generator.generate_for_multiple_bases(
                base_scenarios=base_scenarios,
                variations_per_base=variations_per_base,
                target_os=target_os,
            )

            # Convert to Scenario objects
            for var_data in all_variations:
                data = {"scenarios": [var_data]}
                scenario_objs = self._scenario_generator.convert_to_scenario_objects(data)
                self._llm_scenarios.extend(scenario_objs)

            logger.info(f"Loaded {len(self._llm_scenarios)} LLM-generated scenario variations")
            return len(self._llm_scenarios)

        except Exception as e:
            logger.error(f"Failed to load LLM scenarios: {e}")
            return 0

    def load_behavior_profiles(
        self,
        industry: str = "technology",
        org_size: str = "medium",
    ) -> int:
        """
        Load behavior profiles from LLM and assign to World users.

        Args:
            industry: Industry vertical
            org_size: Organization size

        Returns:
            Number of profiles assigned
        """
        if not self._init_llm_components():
            return 0

        if self._profile_generator is None or self.world is None:
            return 0

        return self.world.load_behavior_profiles(
            profile_generator=self._profile_generator,
            industry=industry,
            org_size=org_size,
        )

    def get_enhanced_command(
        self,
        tactic: str,
        os_family: str = "windows",
    ) -> str | None:
        """
        Get an LLM-generated command for a tactic.

        Args:
            tactic: MITRE ATT&CK tactic
            os_family: Target OS

        Returns:
            Command string or None
        """
        if not self._init_llm_components():
            return None

        if self._command_generator is None:
            return None

        try:
            return self._command_generator.get_random_command(
                tactic=tactic,
                os_family=os_family,
            )
        except Exception as e:
            logger.debug(f"Failed to get LLM command: {e}")
            return None

    def get_all_scenarios(self, include_llm: bool = True) -> list[Scenario]:
        """
        Get all available scenarios.

        Args:
            include_llm: Include LLM-generated scenarios

        Returns:
            Combined list of scenarios
        """
        scenarios = list(self.scenarios)
        if include_llm:
            scenarios.extend(self._llm_scenarios)
        return scenarios

    def prepare_all_llm_artifacts(
        self,
        industry: str = "technology",
        org_size: str = "medium",
        target_os: str = "windows",
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        campaign_days: int = 14,
        force_regenerate: bool = False,
    ) -> dict:
        """
        Prepare all LLM artifacts in one call (commands, scenarios, profiles, campaigns).

        This method generates or loads cached artifacts for all LLM generators,
        enabling a single-command workflow for full LLM-enhanced generation.

        Args:
            industry: Industry for user profiles (technology, healthcare, finance, etc.)
            org_size: Organization size (small, medium, large, enterprise)
            target_os: Target operating system (windows, linux, macos)
            threat_actor: Threat actor for campaign narratives
            target_sector: Target sector for campaign
            campaign_days: Campaign dwell time in days
            force_regenerate: If True, regenerate even if cached

        Returns:
            Dictionary with counts of prepared artifacts
        """
        if not self._init_llm_components():
            return {"success": False, "error": "LLM components not initialized"}

        results = {
            "success": True,
            "commands": 0,
            "scenarios": 0,
            "profiles": 0,
            "campaign": False,
            "token_usage": {"prompt": 0, "completion": 0, "total": 0},
        }

        # 1. Generate command libraries for common tactics
        tactics = ["initial_access", "execution", "persistence", "lateral_movement", "exfiltration"]
        if self._command_generator:
            logger.info("Generating command libraries...")
            for tactic in tactics:
                try:
                    data = self._command_generator.generate_or_load(
                        force_regenerate=force_regenerate,
                        tactic=tactic,
                        count=20,
                        os_family=target_os,
                    )
                    results["commands"] += data.get("count_generated", 0)
                except Exception as e:
                    logger.warning(f"Failed to generate commands for {tactic}: {e}")
            logger.info(f"Command libraries ready: {results['commands']} commands")

        # 2. Generate scenario variations from base scenarios
        if self._scenario_generator and self.scenarios:
            logger.info("Generating scenario variations...")
            try:
                loaded = self.load_llm_scenarios(
                    base_scenarios=self.scenarios[:5],  # Limit to first 5 for efficiency
                    variations_per_base=2,
                    target_os=target_os,
                )
                results["scenarios"] = loaded
                logger.info(f"Scenario variations ready: {loaded} scenarios")
            except Exception as e:
                logger.warning(f"Failed to generate scenario variations: {e}")

        # 3. Generate entity behavior profiles
        if self._profile_generator:
            logger.info(f"Generating behavior profiles for {industry}...")
            try:
                data = self._profile_generator.generate_or_load(
                    force_regenerate=force_regenerate,
                    industry=industry,
                    role_count=10,
                    org_size=org_size,
                )
                results["profiles"] = data.get("role_count_generated", 0)
                logger.info(f"Behavior profiles ready: {results['profiles']} personas")
            except Exception as e:
                logger.warning(f"Failed to generate profiles: {e}")

        # 4. Generate campaign narrative
        if self._campaign_narrative_generator:
            logger.info(f"Generating campaign narrative for {threat_actor}...")
            try:
                data = self._campaign_narrative_generator.generate_or_load(
                    force_regenerate=force_regenerate,
                    threat_actor=threat_actor,
                    target_sector=target_sector,
                    dwell_time_days=campaign_days,
                    objective="data_theft",
                    org_size=org_size,
                    target_os=target_os,
                )
                results["campaign"] = bool(data.get("campaign"))
                logger.info(
                    f"Campaign narrative ready: {data.get('campaign', {}).get('name', 'N/A')}"
                )
            except Exception as e:
                logger.warning(f"Failed to generate campaign: {e}")

        # Get token usage
        if self._llm_client:
            usage = self._llm_client.total_tokens_used
            results["token_usage"] = {
                "prompt": usage["prompt_tokens"],
                "completion": usage["completion_tokens"],
                "total": usage["total_tokens"],
            }

        return results

    def generate_multiple(
        self,
        count: int,
        dry_run: bool = False,
        output_file: str | None = None,
        campaign_mode: bool = False,
        campaign_hosts: int = 5,
        time_spread: str = "minutes",
        working_hours: bool = False,
        attack_speed: str = "medium",
        use_world: bool = False,
        use_llm_artifacts: bool = False,
        llm_industry: str = "technology",
    ) -> dict:
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
            use_world: If True, use World state for entity correlation
            use_llm_artifacts: If True, use LLM-generated artifacts
            llm_industry: Industry for LLM profile generation

        Returns:
            Dictionary with alerts, campaign info, phase counts, and world
        """
        if not self.scenarios:
            logger.error("No scenarios available. Cannot generate alerts.")
            return {
                "alerts": [],
                "campaign": None,
                "phase_counts": None,
                "world": None,
            }

        results: list[AlertData] = []
        campaign: Campaign | None = None
        phase_counts = {"initial": 0, "execution": 0, "lateral": 0, "exfiltration": 0}

        # Initialize LLM artifacts if requested
        if use_llm_artifacts:
            if self._init_llm_components():
                # Load scenario variations
                self.load_llm_scenarios(
                    base_scenarios=self.scenarios,
                    variations_per_base=3,
                )
                logger.info(f"Using LLM artifacts: {len(self._llm_scenarios)} scenario variations")

        # Initialize or use existing World state
        world = self.world
        if use_world and world is None:
            world = World()
            # Populate world with hosts and users for campaign
            num_hosts = campaign_hosts if campaign_mode else max(10, count // 5)
            num_users = max(20, count // 2)
            world.populate(num_hosts=num_hosts, num_users=num_users)
            logger.info(f"Created World with {len(world.hosts)} hosts and {len(world.users)} users")

            # Load behavior profiles if using LLM
            if use_llm_artifacts and self._profile_generator is not None:
                self.world = world  # Set for load_behavior_profiles
                profiles_loaded = self.load_behavior_profiles(
                    industry=llm_industry,
                    org_size="medium",
                )
                if profiles_loaded > 0:
                    logger.info(f"Loaded {profiles_loaded} behavior profiles for {llm_industry}")

        # Map campaign target hosts to World hosts if using world
        host_mapping: dict[str, Host] = {}
        if use_world and world:
            world_hosts = list(world.hosts.values())

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

            # Map campaign hosts to World hosts
            if use_world and world:
                for i, hostname in enumerate(campaign.target_hosts):
                    if i < len(world_hosts):
                        host_mapping[hostname] = world_hosts[i]
                    else:
                        # Create additional hosts if needed
                        host_mapping[hostname] = world.get_or_create_host(
                            template="workstation", name=hostname
                        )

        # Get time distribution strategy
        time_strategy = get_strategy(time_spread, working_hours)

        logger.info(f"Generating {count} varied security alerts...")

        for i in range(count):
            # Determine attack phase and scenario for campaign mode
            if campaign_mode:
                phase = self.campaign_generator.determine_phase(i, count)
                phase_counts[phase] += 1

                # Use combined scenarios when LLM artifacts are enabled
                available_scenarios = self.get_all_scenarios(include_llm=use_llm_artifacts)
                scenario = self.campaign_generator.select_scenario_for_phase(
                    phase, available_scenarios
                )

                # Get timestamp offset based on phase and attack speed
                min_offset, max_offset = get_campaign_phase_offset(phase, attack_speed)
                timestamp_offset = random.randint(min_offset, max_offset)

                # Use campaign host
                hostname = random.choice(campaign.target_hosts)
            else:
                # Random scenario selection (include LLM scenarios if enabled)
                available_scenarios = self.get_all_scenarios(include_llm=use_llm_artifacts)
                scenario = random.choice(available_scenarios)

                # Calculate timestamp offset based on time spread
                timestamp_offset = time_strategy.calculate_offset(i, count)

                # Generate unique hostname
                hostname = self.randomizer.generate_hostname()
                phase = None

            # Get or create Host and User entities if using World
            host: Host | None = None
            user: User | None = None

            if use_world and world:
                # Get host from mapping or create new one
                if hostname in host_mapping:
                    host = host_mapping[hostname]
                else:
                    host = world.get_or_create_host(template="workstation", name=hostname)
                    host_mapping[hostname] = host

                # Get a random user assigned to this host, or create one
                assigned_users = [
                    world.users[u_name]
                    for u_name in world.users
                    if host.id in world.users[u_name].assigned_hosts
                ]
                if assigned_users:
                    user = random.choice(assigned_users)
                else:
                    user = world.get_random_user(user_type="standard")
                    if user:
                        world.assign_user_to_host(user, host)
                    else:
                        user = world.get_or_create_user(template="standard")
                        world.assign_user_to_host(user, host)

            # Generate unique agent ID (for legacy mode)
            agent_id = host.agent_id if host else self.randomizer.generate_uuid()

            # IMPORTANT: Generate process events FIRST to get entity_ids.
            # These entity_ids MUST be passed to the alert generator for proper
            # correlation in Session View and Analyzer graph.
            if use_world and world and host and user:
                events, entity_ids = self.process_generator.generate_from_world(
                    scenario, world, host, user, timestamp_offset
                )
            else:
                # Generate entity_ids for legacy mode
                entity_ids = [
                    self.randomizer.generate_entity_id()
                    for _ in range(len(scenario.processes))
                ]
                events, entity_ids = self.process_generator.generate(
                    scenario, entity_ids, hostname, agent_id, timestamp_offset, host, user
                )

            # Generate the detection rule alert using the SAME entity_ids from process events
            alert, _ = self.alert_generator.generate(
                scenario, hostname, agent_id, timestamp_offset, campaign, host, user,
                entity_ids=entity_ids  # Pass entity_ids for correlation
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
            "world": world if use_world else None,
        }
