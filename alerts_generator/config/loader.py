"""Scenario loading from YAML files."""

import logging
from pathlib import Path
from typing import List, Optional

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario

logger = logging.getLogger(__name__)


def load_scenarios_from_file(filepath: str) -> Optional[List[Scenario]]:
    """
    Load attack scenarios from a YAML configuration file.

    Args:
        filepath: Path to YAML file containing scenarios

    Returns:
        List of Scenario objects, or None if loading fails
    """
    if not YAML_AVAILABLE:
        logger.error("PyYAML not installed. Install with: pip install pyyaml")
        return None

    filepath_obj = Path(filepath)
    if not filepath_obj.exists():
        logger.error(f"Scenarios file not found: {filepath}")
        return None

    try:
        with filepath_obj.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        scenarios_data = data.get("scenarios", [])

        scenarios: List[Scenario] = []
        for scenario_data in scenarios_data:
            try:
                scenario = _dict_to_scenario(scenario_data)
                scenarios.append(scenario)
            except (ValueError, KeyError, TypeError) as e:
                logger.error(
                    f"Invalid scenario format for '{scenario_data.get('name', 'unknown')}': {e}"
                )
                return None

        logger.info(f"Loaded {len(scenarios)} scenarios from {filepath}")
        return scenarios

    except Exception as e:
        logger.error(f"Error loading scenarios file: {e}", exc_info=True)
        return None


def _dict_to_scenario(scenario_dict: dict) -> Scenario:
    """
    Convert dictionary to Scenario object.

    Args:
        scenario_dict: Dictionary containing scenario data

    Returns:
        Scenario object

    Raises:
        ValueError: If required fields are missing or invalid
    """
    required_fields = ["name", "severity", "processes", "malware_file"]
    missing_fields = [field for field in required_fields if field not in scenario_dict]
    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")

    # Convert processes
    processes: List[ProcessInfo] = []
    for proc_data in scenario_dict["processes"]:
        process_info = ProcessInfo(
            name=proc_data["name"],
            executable=proc_data["executable"],
            args=proc_data["args"],
            working_dir=proc_data["working_dir"],
            user=proc_data["user"],
        )
        processes.append(process_info)

    # Convert malware file
    malware_data = scenario_dict["malware_file"]
    malware_file = MalwareFile(
        name=malware_data["name"],
        path=malware_data["path"],
        extension=malware_data["extension"],
    )

    # Create scenario
    scenario = Scenario(
        name=scenario_dict["name"],
        description=scenario_dict.get("description", ""),
        severity=scenario_dict["severity"],
        processes=processes,
        malware_file=malware_file,
    )

    return scenario
