"""Campaign narrative generator using LLM."""

import logging
from typing import Any

from secgen.llm.generators.base import BaseArtifactGenerator
from secgen.llm.prompts import (
    CAMPAIGN_OBJECTIVES,
    THREAT_ACTOR_PROFILES,
    get_campaign_narrative_prompt,
)

logger = logging.getLogger(__name__)


class CampaignNarrativeGenerator(BaseArtifactGenerator):
    """
    Generator for complete attack campaign narratives.

    Creates detailed, multi-day attack storylines with TTPs,
    process chains, and indicators of compromise.
    """

    ARTIFACT_TYPE = "campaigns"

    # Available threat actors
    THREAT_ACTORS = list(THREAT_ACTOR_PROFILES.keys())

    # Available objectives
    OBJECTIVES = list(CAMPAIGN_OBJECTIVES.keys())

    def generate(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        dwell_time_days: int = 14,
        objective: str = "data_theft",
        org_size: str = "medium",
        target_os: str = "windows",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a complete campaign narrative.

        Args:
            threat_actor: Threat actor to emulate
            target_sector: Target industry sector
            dwell_time_days: Campaign duration in days
            objective: Primary campaign objective
            org_size: Target organization size
            target_os: Primary target OS

        Returns:
            Dictionary with campaign narrative including phases
        """
        prompt = get_campaign_narrative_prompt(
            threat_actor=threat_actor,
            target_sector=target_sector,
            dwell_time_days=dwell_time_days,
            objective=objective,
            org_size=org_size,
            target_os=target_os,
        )

        try:
            data = self.client.generate_yaml(
                prompt,
                temperature=0.8,
                max_output_tokens=16384,  # Campaigns can be long
            )

            # Validate structure
            if "campaign" not in data:
                logger.warning("LLM response missing 'campaign' key, wrapping")
                data = {"campaign": data}

            campaign = data.get("campaign", data)

            # Ensure required fields
            campaign.setdefault("name", f"Operation {threat_actor}_{target_sector}")
            campaign.setdefault("threat_actor", threat_actor)
            campaign.setdefault("target_sector", target_sector)
            campaign.setdefault("objective", objective)
            campaign.setdefault("dwell_time_days", dwell_time_days)
            campaign.setdefault("phases", [])
            campaign.setdefault("infrastructure", {})

            # Count phases
            phase_count = len(campaign.get("phases", []))

            logger.info(f"Generated campaign '{campaign.get('name')}' with {phase_count} phases")

            return {"campaign": campaign}

        except Exception as e:
            logger.error(f"Failed to generate campaign narrative: {e}")
            raise

    def get_artifact_name(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
        **kwargs: Any,
    ) -> str:
        """Generate artifact name from parameters."""
        actor_safe = threat_actor.lower().replace(" ", "_")
        sector_safe = target_sector.lower().replace(" ", "_")
        return f"{actor_safe}_{sector_safe}_{objective}"

    def get_campaign(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> dict[str, Any]:
        """
        Get campaign data from cache or generate.

        Args:
            threat_actor: Threat actor to emulate
            target_sector: Target sector
            objective: Campaign objective

        Returns:
            Campaign dictionary
        """
        data = self.generate_or_load(
            threat_actor=threat_actor,
            target_sector=target_sector,
            objective=objective,
        )
        return data.get("campaign", {})

    def get_phases(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> list[dict[str, Any]]:
        """
        Get list of phases from a campaign.

        Args:
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            List of phase dictionaries
        """
        campaign = self.get_campaign(threat_actor, target_sector, objective)
        return campaign.get("phases", [])

    def get_phase_by_day(
        self,
        day: int,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> dict[str, Any] | None:
        """
        Get phase data for a specific day.

        Args:
            day: Day number (1-indexed)
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            Phase dictionary, or None if day not found
        """
        phases = self.get_phases(threat_actor, target_sector, objective)

        for phase in phases:
            phase_day = phase.get("day")
            if phase_day is None:
                continue

            # Handle day ranges like "3-5"
            if isinstance(phase_day, str) and "-" in phase_day:
                start, end = map(int, phase_day.split("-"))
                if start <= day <= end:
                    return phase
            elif phase_day == day or str(phase_day) == str(day):
                return phase

        return None

    def get_infrastructure(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> dict[str, Any]:
        """
        Get infrastructure details from a campaign.

        Args:
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            Infrastructure dictionary with C2, tools, etc.
        """
        campaign = self.get_campaign(threat_actor, target_sector, objective)
        return campaign.get("infrastructure", {})

    def get_indicators(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> list[dict[str, Any]]:
        """
        Get all indicators of compromise from a campaign.

        Args:
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            List of indicator dictionaries
        """
        phases = self.get_phases(threat_actor, target_sector, objective)
        indicators = []

        for phase in phases:
            phase_indicators = phase.get("indicators", [])
            for indicator in phase_indicators:
                indicator["phase"] = phase.get("name", "unknown")
                indicator["day"] = phase.get("day")
                indicators.append(indicator)

        # Also get from infrastructure
        infra = self.get_infrastructure(threat_actor, target_sector, objective)
        for domain in infra.get("c2_domains", []):
            indicators.append(
                {
                    "type": "domain",
                    "value": domain,
                    "phase": "infrastructure",
                }
            )
        for ip in infra.get("c2_ips", []):
            indicators.append(
                {
                    "type": "ip",
                    "value": ip,
                    "phase": "infrastructure",
                }
            )

        return indicators

    def get_process_chains(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> list[dict[str, Any]]:
        """
        Get all process chains from campaign phases.

        Args:
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            List of process chain entries with phase context
        """
        phases = self.get_phases(threat_actor, target_sector, objective)
        chains = []

        for phase in phases:
            process_chain = phase.get("process_chain", [])
            if process_chain:
                chains.append(
                    {
                        "phase": phase.get("name", "unknown"),
                        "day": phase.get("day"),
                        "ttp": phase.get("ttp"),
                        "processes": process_chain,
                    }
                )

        return chains

    def convert_to_scenarios(
        self,
        threat_actor: str = "APT29",
        target_sector: str = "technology",
        objective: str = "data_theft",
    ) -> list[dict[str, Any]]:
        """
        Convert campaign phases to scenario-compatible format.

        Args:
            threat_actor: Threat actor
            target_sector: Target sector
            objective: Objective

        Returns:
            List of scenario dictionaries
        """
        phases = self.get_phases(threat_actor, target_sector, objective)
        campaign = self.get_campaign(threat_actor, target_sector, objective)
        scenarios = []

        for phase in phases:
            process_chain = phase.get("process_chain", [])
            if len(process_chain) < 2:
                continue

            # Determine severity based on phase
            phase_name = phase.get("name", "").lower()
            if "exfil" in phase_name or "ransom" in phase_name:
                severity = "critical"
            elif "lateral" in phase_name or "privilege" in phase_name:
                severity = "high"
            elif "execution" in phase_name or "persist" in phase_name:
                severity = "high"
            else:
                severity = "medium"

            # Build malware file from process chain (use last process)
            last_proc = process_chain[-1]
            malware_file = {
                "name": last_proc.get("name", "malware.exe"),
                "path": last_proc.get("executable", "/tmp/malware"),
                "extension": self._get_extension(last_proc.get("name", ".exe")),
            }

            scenarios.append(
                {
                    "name": f"{campaign.get('name', 'Campaign')} - {phase.get('name', 'Phase')}",
                    "description": phase.get("description", phase.get("story", "")),
                    "severity": severity,
                    "processes": process_chain,
                    "malware_file": malware_file,
                    "ttp": phase.get("ttp"),
                    "day": phase.get("day"),
                }
            )

        return scenarios

    def _get_extension(self, filename: str) -> str:
        """Extract extension from filename."""
        if "." in filename:
            return "." + filename.rsplit(".", 1)[-1]
        return ".exe"

    @staticmethod
    def list_threat_actors() -> list[str]:
        """Get list of available threat actors."""
        return list(THREAT_ACTOR_PROFILES.keys())

    @staticmethod
    def list_objectives() -> list[str]:
        """Get list of available objectives."""
        return list(CAMPAIGN_OBJECTIVES.keys())

    @staticmethod
    def get_threat_actor_profile(actor: str) -> str:
        """Get description for a threat actor."""
        return THREAT_ACTOR_PROFILES.get(actor, "Unknown threat actor")

    @staticmethod
    def get_objective_description(objective: str) -> str:
        """Get description for an objective."""
        return CAMPAIGN_OBJECTIVES.get(objective, objective)
