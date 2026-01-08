"""Scenario loading from YAML files."""

import logging
from pathlib import Path

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from secgen.models.scenario import (
    EVENT_TEMPLATES,
    AttackPhase,
    EnvironmentConfig,
    EventTemplate,
    MalwareFile,
    MultiEventScenario,
    PhaseCorrelation,
    ProcessInfo,
    Scenario,
)

logger = logging.getLogger(__name__)


def load_scenarios_from_file(filepath: str) -> list[Scenario] | None:
    """
    Load attack scenarios from a YAML configuration file.

    Supports both legacy single-alert scenarios and multi-event scenarios.
    Multi-event scenarios are converted to legacy format for backward compatibility.

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

        scenarios: list[Scenario] = []
        for scenario_data in scenarios_data:
            try:
                # Check if this is a multi-event scenario
                if "phases" in scenario_data:
                    multi_scenario = _dict_to_multi_event_scenario(scenario_data)
                    legacy = multi_scenario.to_legacy_scenario()
                    if legacy:
                        scenarios.append(legacy)
                    else:
                        logger.warning(
                            f"Multi-event scenario '{scenario_data.get('name')}' "
                            "could not be converted to legacy format"
                        )
                else:
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


def load_multi_event_scenarios(filepath: str) -> list[MultiEventScenario] | None:
    """
    Load multi-event scenarios from a YAML configuration file.

    Only loads scenarios in the new multi-event format with phases.

    Args:
        filepath: Path to YAML file containing scenarios

    Returns:
        List of MultiEventScenario objects, or None if loading fails
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

        scenarios: list[MultiEventScenario] = []
        for scenario_data in scenarios_data:
            try:
                if "phases" in scenario_data:
                    scenario = _dict_to_multi_event_scenario(scenario_data)
                    scenarios.append(scenario)
                else:
                    logger.debug(
                        f"Skipping legacy scenario '{scenario_data.get('name')}' "
                        "(not a multi-event scenario)"
                    )
            except (ValueError, KeyError, TypeError) as e:
                logger.error(
                    f"Invalid scenario format for '{scenario_data.get('name', 'unknown')}': {e}"
                )
                return None

        logger.info(f"Loaded {len(scenarios)} multi-event scenarios from {filepath}")
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
    processes: list[ProcessInfo] = []
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


def _dict_to_multi_event_scenario(scenario_dict: dict) -> MultiEventScenario:
    """
    Convert dictionary to MultiEventScenario object.

    Args:
        scenario_dict: Dictionary containing multi-event scenario data

    Returns:
        MultiEventScenario object

    Raises:
        ValueError: If required fields are missing or invalid
    """
    required_fields = ["name", "severity", "phases"]
    missing_fields = [field for field in required_fields if field not in scenario_dict]
    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")

    # Convert phases
    phases: list[AttackPhase] = []
    for phase_data in scenario_dict["phases"]:
        phase = _dict_to_attack_phase(phase_data)
        phases.append(phase)

    # Convert environment config if present
    env_data = scenario_dict.get("environment", {})
    environment = EnvironmentConfig(
        os_family=env_data.get("os_family", "linux"),
        host_template=env_data.get("host_template", "workstation"),
        user_template=env_data.get("user_template", "standard"),
    )

    # Create scenario
    scenario = MultiEventScenario(
        name=scenario_dict["name"],
        description=scenario_dict.get("description", ""),
        severity=scenario_dict["severity"],
        phases=phases,
        environment=environment,
        threat_actor=scenario_dict.get("threat_actor"),
        ttps=scenario_dict.get("ttps", []),
        generate_indicators=scenario_dict.get("generate_indicators", True),
    )

    return scenario


def _dict_to_attack_phase(phase_dict: dict) -> AttackPhase:
    """
    Convert dictionary to AttackPhase object.

    Args:
        phase_dict: Dictionary containing phase data

    Returns:
        AttackPhase object
    """
    # Convert events
    events: list[EventTemplate] = []
    for event_data in phase_dict.get("events", []):
        event = _dict_to_event_template(event_data)
        events.append(event)

    # Convert correlation settings if present
    correlation_data = phase_dict.get("correlation", {})
    correlation = PhaseCorrelation(
        same_host=correlation_data.get("same_host", True),
        same_user=correlation_data.get("same_user", True),
        process_tree=correlation_data.get("process_tree", True),
    )

    return AttackPhase(
        name=phase_dict["name"],
        description=phase_dict.get("description", ""),
        events=events,
        correlation=correlation,
        duration_minutes=phase_dict.get("duration_minutes", 5),
    )


def _dict_to_event_template(event_dict: dict) -> EventTemplate:
    """
    Convert dictionary to EventTemplate object.

    Supports both inline params and template references.

    Args:
        event_dict: Dictionary containing event template data

    Returns:
        EventTemplate object
    """
    event_type = event_dict["type"]
    template_name = event_dict.get("template", "")

    # If using a predefined template, merge with inline params
    if template_name and template_name in EVENT_TEMPLATES:
        base_params = EVENT_TEMPLATES[template_name].get("params", {}).copy()
        inline_params = event_dict.get("params", {})
        base_params.update(inline_params)
        params = base_params
    else:
        params = event_dict.get("params", {})

    return EventTemplate(
        type=event_type,
        template=template_name,
        params=params,
        delay_seconds=event_dict.get("delay_seconds", 0),
    )


def create_sample_multi_event_scenario() -> str:
    """
    Generate a sample multi-event scenario YAML.

    Returns:
        YAML string with sample scenario
    """
    sample = """# Multi-event attack scenario example
scenarios:
  - name: "APT29 Initial Access Campaign"
    description: "Spear-phishing leading to payload execution and C2 establishment"
    severity: "critical"
    threat_actor: "APT29"
    ttps:
      - "T1566.001"  # Spear-phishing Attachment
      - "T1059.001"  # PowerShell
      - "T1071.001"  # Web Protocols
      - "T1547.001"  # Registry Run Keys

    environment:
      os_family: "windows"
      host_template: "workstation"
      user_template: "standard"

    phases:
      - name: "initial_access"
        description: "User opens malicious document"
        duration_minutes: 2
        correlation:
          same_host: true
          same_user: true
          process_tree: true
        events:
          - type: "authentication"
            template: "successful_login"
            delay_seconds: 0
          - type: "process"
            params:
              name: "OUTLOOK.EXE"
              executable: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
              args: ["/recycle"]
              working_dir: "C:\\Users\\victim\\Documents"
              user: "victim"
            delay_seconds: 30
          - type: "file"
            template: "malware_drop"
            params:
              action: "creation"
              file_path: "C:\\Users\\victim\\AppData\\Local\\Temp\\report.doc"
            delay_seconds: 5

      - name: "execution"
        description: "Malicious macro executes PowerShell"
        duration_minutes: 3
        events:
          - type: "process"
            template: "powershell_encoded"
            delay_seconds: 0
          - type: "file"
            template: "malware_drop"
            params:
              file_path: "C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe"
            delay_seconds: 10

      - name: "persistence"
        description: "Establish registry persistence"
        duration_minutes: 1
        events:
          - type: "registry"
            template: "run_key_persistence"
            delay_seconds: 0

      - name: "c2_communication"
        description: "Establish C2 channel"
        duration_minutes: 5
        events:
          - type: "dns"
            params:
              query_name: "cozy-c2.evil.com"
              is_malicious: true
            delay_seconds: 0
          - type: "network"
            template: "c2_beacon"
            params:
              destination_domain: "cozy-c2.evil.com"
              destination_ip: "198.51.100.10"
            delay_seconds: 5
          - type: "tls"
            params:
              server_name: "cozy-c2.evil.com"
              is_malicious: true
            delay_seconds: 1

    generate_indicators: true
"""
    return sample
