"""Scenario variation generator using LLM."""

import logging
from typing import TYPE_CHECKING, Any

from secgen.llm.generators.base import BaseArtifactGenerator
from secgen.llm.prompts import get_scenario_variation_prompt

if TYPE_CHECKING:
    from secgen.models.scenario import Scenario

logger = logging.getLogger(__name__)


class ScenarioVariationGenerator(BaseArtifactGenerator):
    """
    Generator for scenario variations based on existing scenarios.

    Takes a base attack scenario and generates multiple variations
    with different initial access vectors, tools, and techniques.
    """

    ARTIFACT_TYPE = "scenarios"

    def generate(
        self,
        base_scenario: "Scenario | dict[str, Any] | None" = None,
        base_name: str = "Ransomware",
        base_description: str = "Generic ransomware attack",
        base_severity: str = "critical",
        base_process_chain: list[dict[str, Any]] | None = None,
        variation_count: int = 5,
        target_os: str = "windows",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate variations of a base scenario.

        Args:
            base_scenario: Scenario object or dict to use as base
            base_name: Name of base scenario (if no object provided)
            base_description: Description (if no object provided)
            base_severity: Severity level
            base_process_chain: Process chain as list of dicts
            variation_count: Number of variations to generate
            target_os: Target operating system

        Returns:
            Dictionary with 'scenarios' list containing variations
        """
        # Extract from scenario object if provided
        if base_scenario is not None:
            if hasattr(base_scenario, "name"):
                base_name = base_scenario.name
                base_description = base_scenario.description or ""
                base_severity = base_scenario.severity
                base_process_chain = [
                    {
                        "name": p.name,
                        "executable": p.executable,
                        "args": p.args,
                        "working_dir": p.working_dir,
                        "user": p.user,
                    }
                    for p in base_scenario.processes
                ]
            elif isinstance(base_scenario, dict):
                base_name = base_scenario.get("name", base_name)
                base_description = base_scenario.get("description", base_description)
                base_severity = base_scenario.get("severity", base_severity)
                base_process_chain = base_scenario.get("processes", base_process_chain)

        # Default process chain if none provided
        if not base_process_chain:
            base_process_chain = [
                {"name": "explorer.exe", "executable": "C:\\Windows\\explorer.exe"},
                {"name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"},
                {"name": "malware.exe", "executable": "C:\\Temp\\malware.exe"},
            ]

        prompt = get_scenario_variation_prompt(
            base_name=base_name,
            base_description=base_description,
            base_severity=base_severity,
            base_process_chain=base_process_chain,
            variation_count=variation_count,
            target_os=target_os,
        )

        try:
            data = self.client.generate_yaml(
                prompt,
                temperature=0.8,
                max_output_tokens=8192,
            )

            # Validate structure
            if "scenarios" not in data:
                logger.warning("LLM response missing 'scenarios' key")
                if isinstance(data, list):
                    data = {"scenarios": data}
                else:
                    data = {"scenarios": [data]}

            # Add metadata
            data["base_scenario"] = base_name
            data["target_os"] = target_os
            data["variation_count_requested"] = variation_count
            data["variation_count_generated"] = len(data.get("scenarios", []))

            logger.info(
                f"Generated {data['variation_count_generated']} variations " f"of '{base_name}'"
            )
            return data

        except Exception as e:
            logger.error(f"Failed to generate scenario variations: {e}")
            raise

    def get_artifact_name(
        self,
        base_scenario: "Scenario | dict[str, Any] | None" = None,
        base_name: str = "Ransomware",
        target_os: str = "windows",
        **kwargs: Any,
    ) -> str:
        """Generate artifact name from parameters."""
        # Extract name from scenario if provided
        if base_scenario is not None:
            if hasattr(base_scenario, "name"):
                base_name = base_scenario.name
            elif isinstance(base_scenario, dict):
                base_name = base_scenario.get("name", base_name)

        # Sanitize name for filename
        safe_name = base_name.lower().replace(" ", "_").replace("-", "_")
        return f"{safe_name}_variations_{target_os}"

    def get_variations(
        self,
        base_name: str = "Ransomware",
        target_os: str = "windows",
    ) -> list[dict[str, Any]]:
        """
        Get list of scenario variations from cache or generate.

        Args:
            base_name: Name of base scenario
            target_os: Target OS

        Returns:
            List of scenario variation dictionaries
        """
        data = self.generate_or_load(
            base_name=base_name,
            target_os=target_os,
        )
        return data.get("scenarios", [])

    def convert_to_scenario_objects(
        self,
        variations_data: dict[str, Any],
    ) -> list["Scenario"]:
        """
        Convert variation data to Scenario objects.

        Args:
            variations_data: Data from generate() or cache

        Returns:
            List of Scenario objects
        """
        from secgen.models.scenario import (
            MalwareFile,
            ProcessInfo,
            Scenario,
        )

        scenarios = []

        for var in variations_data.get("scenarios", []):
            try:
                # Build process chain
                processes = []
                for proc in var.get("processes", []):
                    processes.append(
                        ProcessInfo(
                            name=proc.get("name", "unknown.exe"),
                            executable=proc.get("executable", "/bin/unknown"),
                            args=proc.get("args", []),
                            working_dir=proc.get("working_dir", "/"),
                            user=proc.get("user", "root"),
                        )
                    )

                # Ensure we have at least 2 processes
                if len(processes) < 2:
                    logger.warning(
                        f"Scenario '{var.get('name')}' has fewer than 2 processes, skipping"
                    )
                    continue

                # Build malware file
                malware_data = var.get("malware_file", {})
                malware_file = MalwareFile(
                    name=malware_data.get("name", "malware.exe"),
                    path=malware_data.get("path", "/tmp/malware.exe"),
                    extension=malware_data.get("extension", ".exe"),
                )

                scenario = Scenario(
                    name=var.get("name", "Unknown Variation"),
                    description=var.get("description", ""),
                    severity=var.get("severity", "high"),
                    processes=processes,
                    malware_file=malware_file,
                )
                scenarios.append(scenario)

            except Exception as e:
                logger.warning(f"Failed to convert variation to Scenario: {e}")
                continue

        return scenarios

    def generate_for_multiple_bases(
        self,
        base_scenarios: list["Scenario | dict[str, Any]"],
        variations_per_base: int = 3,
        target_os: str = "windows",
        force_regenerate: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Generate variations for multiple base scenarios.

        Args:
            base_scenarios: List of base scenarios
            variations_per_base: Number of variations per base
            target_os: Target OS
            force_regenerate: Regenerate even if cached

        Returns:
            List of all generated variations
        """
        all_variations = []

        for base in base_scenarios:
            try:
                data = self.generate_or_load(
                    force_regenerate=force_regenerate,
                    base_scenario=base,
                    variation_count=variations_per_base,
                    target_os=target_os,
                )
                all_variations.extend(data.get("scenarios", []))
            except Exception as e:
                base_name = getattr(base, "name", str(base))
                logger.error(f"Failed to generate variations for {base_name}: {e}")

        return all_variations
