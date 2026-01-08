"""Preset schema and loading utilities."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PresetStep:
    """A step in a preset workflow."""

    type: str  # "event", "attack", "feature"
    name: str  # Event type, attack pattern, or feature name
    count: int = 10
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Preset:
    """Preset configuration for data generation."""

    name: str
    description: str
    steps: list[PresetStep]
    world_config: dict[str, Any] = field(default_factory=dict)
    index: bool = True
    time_spread_hours: int = 24

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Preset":
        """Create Preset from dictionary."""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(
                PresetStep(
                    type=step_data.get("type", "event"),
                    name=step_data.get("name", ""),
                    count=step_data.get("count", 10),
                    params=step_data.get("params", {}),
                )
            )

        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            steps=steps,
            world_config=data.get("world", {}),
            index=data.get("index", True),
            time_spread_hours=data.get("time_spread_hours", 24),
        )

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "Preset":
        """Load Preset from YAML file."""
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)


# Built-in preset definitions
# Note: 'process' events require Scenario context and are generated via attack patterns
# or legacy alert mode. Use file, registry, endpoint-network for endpoint telemetry.
BUILTIN_PRESETS: dict[str, dict[str, Any]] = {
    "demo-cluster": {
        "name": "demo-cluster",
        "description": "Comprehensive demo data for all Elastic Security features",
        "world": {"hosts": 25, "users": 50},
        "time_spread_hours": 48,
        "steps": [
            # Endpoint events (process events come from attack patterns)
            {"type": "event", "name": "file", "count": 200},
            {"type": "event", "name": "registry", "count": 150},
            {"type": "event", "name": "endpoint-network", "count": 200},
            # Network events
            {
                "type": "event",
                "name": "network-flow",
                "count": 300,
                "params": {"geo_diverse": True},
            },
            {"type": "event", "name": "dns", "count": 200},
            {"type": "event", "name": "http", "count": 100},
            # Identity events
            {"type": "event", "name": "authentication", "count": 200},
            # Cloud events
            {"type": "event", "name": "aws-cloudtrail", "count": 100},
            {"type": "event", "name": "azure-audit", "count": 100},
            # Security events
            {"type": "event", "name": "vulnerability", "count": 150},
            {"type": "event", "name": "cspm", "count": 100},
            {"type": "event", "name": "risk-score", "count": 75},
            # Attack patterns for detection testing (these include process events)
            {"type": "attack", "name": "brute-force", "count": 2},
            {"type": "attack", "name": "c2-beacon", "count": 1},
            {"type": "attack", "name": "malware-drop", "count": 1},
        ],
    },
    "entity-analytics-showcase": {
        "name": "entity-analytics-showcase",
        "description": "Entity Analytics demonstration with diverse risk scores",
        "world": {"hosts": 30, "users": 60},
        "time_spread_hours": 72,
        "steps": [
            # Risk scores for hosts and users
            {"type": "event", "name": "risk-score", "count": 60, "params": {"entity_type": "host"}},
            {"type": "event", "name": "risk-score", "count": 60, "params": {"entity_type": "user"}},
            # Supporting authentication events
            {"type": "event", "name": "authentication", "count": 300},
            # Attack patterns to generate alerts
            {"type": "attack", "name": "brute-force", "count": 3},
            {"type": "attack", "name": "impossible-travel", "count": 2},
            {"type": "attack", "name": "credential-stuffing", "count": 1},
        ],
    },
    "load-test": {
        "name": "load-test",
        "description": "High-volume event generation for performance testing",
        "world": {"hosts": 100, "users": 200},
        "time_spread_hours": 24,
        "steps": [
            {"type": "event", "name": "file", "count": 5000},
            {"type": "event", "name": "endpoint-network", "count": 3000},
            {"type": "event", "name": "network-flow", "count": 5000},
            {"type": "event", "name": "dns", "count": 3000},
            {"type": "event", "name": "authentication", "count": 2000},
        ],
    },
    "attack-simulation": {
        "name": "attack-simulation",
        "description": "Multi-stage attack simulation for detection rule testing",
        "world": {"hosts": 15, "users": 30},
        "time_spread_hours": 4,
        "steps": [
            # Initial access - phishing indicators
            {"type": "attack", "name": "malware-drop", "count": 2},
            # Persistence
            {"type": "attack", "name": "registry-persistence", "count": 2},
            # Defense evasion
            {"type": "attack", "name": "security-disable", "count": 1},
            # Credential access
            {"type": "attack", "name": "brute-force", "count": 1},
            # Lateral movement
            {"type": "attack", "name": "lateral-movement", "count": 3},
            # C2
            {"type": "attack", "name": "c2-beacon", "count": 2},
            {"type": "attack", "name": "dga-activity", "count": 1},
            # Exfiltration
            {"type": "attack", "name": "data-exfiltration", "count": 1},
        ],
    },
    "network-visibility": {
        "name": "network-visibility",
        "description": "Network-focused events for Network Map and flow analysis",
        "world": {"hosts": 20, "users": 40},
        "time_spread_hours": 24,
        "steps": [
            {
                "type": "event",
                "name": "network-flow",
                "count": 500,
                "params": {"geo_diverse": True},
            },
            {"type": "event", "name": "dns", "count": 300},
            {"type": "event", "name": "http", "count": 200},
            {"type": "event", "name": "tls", "count": 200},
            {"type": "event", "name": "endpoint-network", "count": 300},
        ],
    },
    "cloud-security": {
        "name": "cloud-security",
        "description": "Cloud security events for CSPM and cloud audit",
        "world": {"hosts": 10, "users": 20},
        "time_spread_hours": 48,
        "steps": [
            {"type": "event", "name": "aws-cloudtrail", "count": 200},
            {"type": "event", "name": "azure-audit", "count": 200},
            {"type": "event", "name": "gcp-audit", "count": 100},
            {"type": "event", "name": "cspm", "count": 150, "params": {"cloud_provider": "aws"}},
            {"type": "event", "name": "cspm", "count": 100, "params": {"cloud_provider": "azure"}},
        ],
    },
    # =========================================================================
    # Quick Start & Testing Presets
    # =========================================================================
    "quick-start": {
        "name": "quick-start",
        "description": "Minimal data to quickly verify Elastic Security setup",
        "world": {"hosts": 5, "users": 10},
        "time_spread_hours": 1,
        "steps": [
            {"type": "event", "name": "file", "count": 20},
            {"type": "event", "name": "authentication", "count": 20},
            {"type": "event", "name": "dns", "count": 20},
            {"type": "attack", "name": "brute-force", "count": 1},
        ],
    },
    "siem-demo": {
        "name": "siem-demo",
        "description": "Balanced SIEM data for sales demos and presentations",
        "world": {"hosts": 15, "users": 30},
        "time_spread_hours": 24,
        "steps": [
            # Endpoint telemetry
            {"type": "event", "name": "file", "count": 100},
            {"type": "event", "name": "registry", "count": 50},
            {"type": "event", "name": "endpoint-network", "count": 100},
            # Network visibility
            {
                "type": "event",
                "name": "network-flow",
                "count": 150,
                "params": {"geo_diverse": True},
            },
            {"type": "event", "name": "dns", "count": 100},
            # Identity
            {"type": "event", "name": "authentication", "count": 100},
            # A few alerts to show detection
            {"type": "attack", "name": "brute-force", "count": 1},
            {"type": "attack", "name": "c2-beacon", "count": 1},
        ],
    },
    # =========================================================================
    # Attack Simulation Presets
    # =========================================================================
    "ransomware-attack": {
        "name": "ransomware-attack",
        "description": "Ransomware attack chain from initial access to encryption",
        "world": {"hosts": 10, "users": 20},
        "time_spread_hours": 6,
        "steps": [
            # Initial Access - Malicious attachment
            {"type": "attack", "name": "malware-drop", "count": 1},
            # Execution & Persistence
            {"type": "attack", "name": "registry-persistence", "count": 2},
            # Defense Evasion - Disable security tools
            {"type": "attack", "name": "security-disable", "count": 1},
            # Discovery - Network reconnaissance
            {"type": "event", "name": "dns", "count": 50},
            {"type": "event", "name": "endpoint-network", "count": 100},
            # Lateral Movement
            {"type": "attack", "name": "lateral-movement", "count": 3},
            # Data staging before encryption
            {"type": "attack", "name": "data-staging", "count": 2},
            # C2 for exfiltration
            {"type": "attack", "name": "c2-beacon", "count": 2},
            {"type": "attack", "name": "data-exfiltration", "count": 1},
            # File encryption indicators
            {"type": "event", "name": "file", "count": 200, "params": {"is_malicious": True}},
        ],
    },
    "apt-campaign": {
        "name": "apt-campaign",
        "description": "Advanced Persistent Threat campaign over extended period",
        "world": {"hosts": 20, "users": 40},
        "time_spread_hours": 168,  # 1 week
        "steps": [
            # Initial Compromise (Day 1)
            {"type": "attack", "name": "malware-drop", "count": 1},
            {"type": "attack", "name": "registry-persistence", "count": 1},
            # Establish C2 (Day 1-2)
            {"type": "attack", "name": "c2-beacon", "count": 3},
            {"type": "attack", "name": "dga-activity", "count": 1},
            # Internal Reconnaissance (Day 2-3)
            {"type": "event", "name": "dns", "count": 100},
            {"type": "event", "name": "endpoint-network", "count": 150},
            # Credential Harvesting (Day 3-4)
            {"type": "attack", "name": "brute-force", "count": 2},
            {"type": "attack", "name": "credential-stuffing", "count": 1},
            # Lateral Movement (Day 4-5)
            {"type": "attack", "name": "lateral-movement", "count": 5},
            # Data Collection (Day 5-6)
            {"type": "attack", "name": "data-staging", "count": 3},
            {"type": "event", "name": "file", "count": 100},
            # Exfiltration (Day 6-7)
            {"type": "attack", "name": "data-exfiltration", "count": 2},
        ],
    },
    "insider-threat": {
        "name": "insider-threat",
        "description": "Insider threat scenario with data theft indicators",
        "world": {"hosts": 10, "users": 25},
        "time_spread_hours": 72,
        "steps": [
            # Normal baseline activity
            {"type": "event", "name": "authentication", "count": 150},
            {"type": "event", "name": "file", "count": 100},
            # Suspicious after-hours access
            {
                "type": "event",
                "name": "authentication",
                "count": 30,
                "params": {"is_suspicious": True},
            },
            # Unusual data access patterns
            {"type": "event", "name": "file", "count": 150, "params": {"is_sensitive": True}},
            # Data staging and compression
            {"type": "attack", "name": "data-staging", "count": 2},
            # Exfiltration via cloud storage
            {"type": "event", "name": "http", "count": 50, "params": {"is_upload": True}},
            {"type": "attack", "name": "data-exfiltration", "count": 1},
            # Elevated risk scores
            {"type": "event", "name": "risk-score", "count": 25, "params": {"entity_type": "user"}},
        ],
    },
    "credential-attack": {
        "name": "credential-attack",
        "description": "Credential-focused attacks: brute force, stuffing, and phishing",
        "world": {"hosts": 15, "users": 50},
        "time_spread_hours": 12,
        "steps": [
            # Background legitimate auth
            {"type": "event", "name": "authentication", "count": 200},
            # Password spray attack
            {"type": "attack", "name": "brute-force", "count": 3},
            # Credential stuffing
            {"type": "attack", "name": "credential-stuffing", "count": 2},
            # Impossible travel detection
            {"type": "attack", "name": "impossible-travel", "count": 2},
            # MFA bypass attempts
            {"type": "attack", "name": "mfa-bypass", "count": 1},
            # Resulting risk scores
            {"type": "event", "name": "risk-score", "count": 50, "params": {"entity_type": "user"}},
        ],
    },
    # =========================================================================
    # Feature-Specific Presets
    # =========================================================================
    "timeline-investigation": {
        "name": "timeline-investigation",
        "description": "Correlated events optimized for Timeline investigation",
        "world": {"hosts": 5, "users": 10},
        "time_spread_hours": 2,
        "steps": [
            # Dense correlated activity on few hosts
            {"type": "event", "name": "file", "count": 100},
            {"type": "event", "name": "registry", "count": 50},
            {"type": "event", "name": "endpoint-network", "count": 100},
            {"type": "event", "name": "dns", "count": 75},
            {"type": "event", "name": "authentication", "count": 50},
            # Attack sequence for investigation
            {"type": "attack", "name": "malware-drop", "count": 1},
            {"type": "attack", "name": "c2-beacon", "count": 1},
        ],
    },
    "analyzer-showcase": {
        "name": "analyzer-showcase",
        "description": "Process-heavy data for Analyzer visualization",
        "world": {"hosts": 5, "users": 10},
        "time_spread_hours": 1,
        "steps": [
            # File and registry for process context
            {"type": "event", "name": "file", "count": 50},
            {"type": "event", "name": "registry", "count": 30},
            {"type": "event", "name": "endpoint-network", "count": 50},
            # Multiple attack chains for Analyzer
            {"type": "attack", "name": "malware-drop", "count": 2},
            {"type": "attack", "name": "registry-persistence", "count": 2},
            {"type": "attack", "name": "c2-beacon", "count": 2},
        ],
    },
    "network-map-demo": {
        "name": "network-map-demo",
        "description": "Geo-diverse network flows for Network Map visualization",
        "world": {"hosts": 30, "users": 50},
        "time_spread_hours": 24,
        "steps": [
            # Heavy network flow data with geo diversity
            {
                "type": "event",
                "name": "network-flow",
                "count": 1000,
                "params": {"geo_diverse": True},
            },
            {"type": "event", "name": "dns", "count": 500},
            {"type": "event", "name": "http", "count": 300},
            {"type": "event", "name": "tls", "count": 300},
            # Some malicious C2 traffic
            {"type": "attack", "name": "c2-beacon", "count": 2},
            {"type": "attack", "name": "dga-activity", "count": 1},
            {"type": "attack", "name": "dns-tunneling", "count": 1},
        ],
    },
    "vulnerability-dashboard": {
        "name": "vulnerability-dashboard",
        "description": "Vulnerability data for VM dashboard testing",
        "world": {"hosts": 50, "users": 25},
        "time_spread_hours": 24,
        "steps": [
            # Diverse vulnerability findings
            {"type": "event", "name": "vulnerability", "count": 500},
            # Host context
            {"type": "event", "name": "file", "count": 100},
            {"type": "event", "name": "endpoint-network", "count": 100},
            # Risk correlation
            {"type": "event", "name": "risk-score", "count": 50, "params": {"entity_type": "host"}},
        ],
    },
    "cspm-compliance": {
        "name": "cspm-compliance",
        "description": "Cloud posture data for CSPM compliance dashboards",
        "world": {"hosts": 10, "users": 20},
        "time_spread_hours": 24,
        "steps": [
            # Multi-cloud CSPM findings
            {"type": "event", "name": "cspm", "count": 200, "params": {"cloud_provider": "aws"}},
            {"type": "event", "name": "cspm", "count": 150, "params": {"cloud_provider": "azure"}},
            {"type": "event", "name": "cspm", "count": 100, "params": {"cloud_provider": "gcp"}},
            # Cloud audit trails
            {"type": "event", "name": "aws-cloudtrail", "count": 100},
            {"type": "event", "name": "azure-audit", "count": 100},
            {"type": "event", "name": "gcp-audit", "count": 50},
        ],
    },
    # =========================================================================
    # Specialized Use Cases
    # =========================================================================
    "detection-engineering": {
        "name": "detection-engineering",
        "description": "Malicious events for testing and tuning detection rules",
        "world": {"hosts": 20, "users": 40},
        "time_spread_hours": 8,
        "steps": [
            # High ratio of malicious to normal activity
            {"type": "event", "name": "file", "count": 100, "params": {"is_malicious": True}},
            {"type": "event", "name": "registry", "count": 50, "params": {"is_malicious": True}},
            {"type": "event", "name": "dns", "count": 100, "params": {"is_malicious": True}},
            # All attack patterns for rule coverage
            {"type": "attack", "name": "brute-force", "count": 2},
            {"type": "attack", "name": "credential-stuffing", "count": 1},
            {"type": "attack", "name": "malware-drop", "count": 2},
            {"type": "attack", "name": "registry-persistence", "count": 2},
            {"type": "attack", "name": "security-disable", "count": 1},
            {"type": "attack", "name": "c2-beacon", "count": 2},
            {"type": "attack", "name": "dga-activity", "count": 2},
            {"type": "attack", "name": "dns-tunneling", "count": 1},
            {"type": "attack", "name": "lateral-movement", "count": 2},
            {"type": "attack", "name": "data-exfiltration", "count": 1},
        ],
    },
    "threat-hunting": {
        "name": "threat-hunting",
        "description": "Mixed benign and malicious data for threat hunting exercises",
        "world": {"hosts": 30, "users": 60},
        "time_spread_hours": 72,
        "steps": [
            # Heavy baseline of normal activity (needle in haystack)
            {"type": "event", "name": "file", "count": 500},
            {"type": "event", "name": "registry", "count": 200},
            {"type": "event", "name": "endpoint-network", "count": 500},
            {"type": "event", "name": "dns", "count": 500},
            {"type": "event", "name": "http", "count": 300},
            {"type": "event", "name": "authentication", "count": 400},
            # Hidden malicious activity
            {"type": "attack", "name": "c2-beacon", "count": 1},
            {"type": "attack", "name": "dga-activity", "count": 1},
            {"type": "attack", "name": "data-staging", "count": 1},
            # Subtle indicators
            {"type": "event", "name": "file", "count": 20, "params": {"is_malicious": True}},
            {"type": "event", "name": "dns", "count": 20, "params": {"is_malicious": True}},
        ],
    },
    "incident-response": {
        "name": "incident-response",
        "description": "Complete attack chain for IR training and tabletop exercises",
        "world": {"hosts": 15, "users": 30},
        "time_spread_hours": 48,
        "steps": [
            # Pre-incident baseline
            {"type": "event", "name": "authentication", "count": 100},
            {"type": "event", "name": "file", "count": 100},
            # Initial compromise indicators
            {"type": "attack", "name": "malware-drop", "count": 1},
            # Persistence establishment
            {"type": "attack", "name": "registry-persistence", "count": 2},
            # Discovery phase
            {"type": "event", "name": "dns", "count": 100},
            {"type": "event", "name": "endpoint-network", "count": 150},
            # Credential access
            {"type": "attack", "name": "brute-force", "count": 1},
            # Lateral movement
            {"type": "attack", "name": "lateral-movement", "count": 3},
            # C2 and exfiltration
            {"type": "attack", "name": "c2-beacon", "count": 2},
            {"type": "attack", "name": "data-staging", "count": 1},
            {"type": "attack", "name": "data-exfiltration", "count": 1},
            # Post-incident risk assessment
            {"type": "event", "name": "risk-score", "count": 30},
            {"type": "event", "name": "vulnerability", "count": 50},
        ],
    },
    "soc-training": {
        "name": "soc-training",
        "description": "Varied alerts and events for SOC analyst training",
        "world": {"hosts": 25, "users": 50},
        "time_spread_hours": 24,
        "steps": [
            # Mixed event types
            {"type": "event", "name": "file", "count": 150},
            {"type": "event", "name": "registry", "count": 75},
            {"type": "event", "name": "endpoint-network", "count": 150},
            {"type": "event", "name": "dns", "count": 150},
            {"type": "event", "name": "authentication", "count": 150},
            {"type": "event", "name": "http", "count": 100},
            # Variety of attack patterns (different severity levels)
            {"type": "attack", "name": "brute-force", "count": 2},
            {"type": "attack", "name": "malware-drop", "count": 1},
            {"type": "attack", "name": "c2-beacon", "count": 1},
            {"type": "attack", "name": "registry-persistence", "count": 1},
            {"type": "attack", "name": "dga-activity", "count": 1},
            # Risk scores for prioritization
            {"type": "event", "name": "risk-score", "count": 50},
        ],
    },
    "aws-security": {
        "name": "aws-security",
        "description": "AWS-focused cloud security events and misconfigurations",
        "world": {"hosts": 10, "users": 30},
        "time_spread_hours": 48,
        "steps": [
            # AWS CloudTrail audit events
            {"type": "event", "name": "aws-cloudtrail", "count": 500},
            # AWS CSPM findings
            {"type": "event", "name": "cspm", "count": 300, "params": {"cloud_provider": "aws"}},
            # Network visibility for AWS
            {
                "type": "event",
                "name": "network-flow",
                "count": 200,
                "params": {"geo_diverse": True},
            },
            {"type": "event", "name": "dns", "count": 100},
        ],
    },
    "azure-security": {
        "name": "azure-security",
        "description": "Azure-focused identity and cloud security events",
        "world": {"hosts": 10, "users": 40},
        "time_spread_hours": 48,
        "steps": [
            # Azure AD sign-ins and audit
            {"type": "event", "name": "azure-audit", "count": 400},
            {"type": "event", "name": "authentication", "count": 200},
            # Azure CSPM
            {"type": "event", "name": "cspm", "count": 250, "params": {"cloud_provider": "azure"}},
            # Identity attacks
            {"type": "attack", "name": "brute-force", "count": 2},
            {"type": "attack", "name": "impossible-travel", "count": 2},
            {"type": "attack", "name": "mfa-bypass", "count": 1},
        ],
    },
    "endpoint-telemetry": {
        "name": "endpoint-telemetry",
        "description": "Rich endpoint telemetry for EDR testing",
        "world": {"hosts": 20, "users": 40},
        "time_spread_hours": 24,
        "steps": [
            # Heavy endpoint events
            {"type": "event", "name": "file", "count": 500},
            {"type": "event", "name": "registry", "count": 300},
            {"type": "event", "name": "endpoint-network", "count": 400},
            # Endpoint-based attacks
            {"type": "attack", "name": "malware-drop", "count": 3},
            {"type": "attack", "name": "registry-persistence", "count": 3},
            {"type": "attack", "name": "security-disable", "count": 2},
            {"type": "attack", "name": "data-staging", "count": 2},
        ],
    },
    "dns-security": {
        "name": "dns-security",
        "description": "DNS-focused events for DNS security testing",
        "world": {"hosts": 15, "users": 30},
        "time_spread_hours": 24,
        "steps": [
            # Normal DNS traffic
            {"type": "event", "name": "dns", "count": 1000},
            # Malicious DNS patterns
            {"type": "attack", "name": "dga-activity", "count": 3},
            {"type": "attack", "name": "dns-tunneling", "count": 2},
            {"type": "attack", "name": "c2-dns", "count": 2},
            # Network context
            {"type": "event", "name": "endpoint-network", "count": 200},
        ],
    },
}


def get_presets_dir() -> Path:
    """Get the directory containing preset YAML files."""
    return Path(__file__).parent


def list_builtin_presets() -> dict[str, str]:
    """
    List all built-in presets.

    Returns:
        Dictionary of preset name to description
    """
    return {name: preset["description"] for name, preset in BUILTIN_PRESETS.items()}


def load_preset(name_or_path: str) -> Preset:
    """
    Load a preset by name or file path.

    Args:
        name_or_path: Built-in preset name or path to YAML file

    Returns:
        Loaded Preset

    Raises:
        ValueError: If preset not found
    """
    # Check if it's a built-in preset
    if name_or_path in BUILTIN_PRESETS:
        return Preset.from_dict(BUILTIN_PRESETS[name_or_path])

    # Check if it's a file path
    if os.path.exists(name_or_path):
        return Preset.from_yaml(name_or_path)

    # Check for .yaml extension
    if os.path.exists(f"{name_or_path}.yaml"):
        return Preset.from_yaml(f"{name_or_path}.yaml")

    raise ValueError(
        f"Preset '{name_or_path}' not found. "
        f"Available presets: {', '.join(BUILTIN_PRESETS.keys())}"
    )
