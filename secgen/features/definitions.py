"""Feature test definitions for Elastic Security capabilities."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FeatureTest:
    """Definition of a feature test."""

    name: str
    description: str
    kibana_path: str
    event_types: list[str]
    default_count: int = 100
    required_world: bool = True
    configuration: dict[str, Any] = field(default_factory=dict)
    verification_steps: list[str] = field(default_factory=list)


# Feature test definitions
FEATURE_TESTS: dict[str, FeatureTest] = {
    "network-map": FeatureTest(
        name="network-map",
        description="Network Map visualization with geo-diverse flows",
        kibana_path="/app/security/network",
        event_types=["network-flow", "endpoint-network"],
        default_count=200,
        configuration={
            "geo_diversity": True,
            "internal_external_mix": 0.5,
            "time_spread_hours": 24,
        },
        verification_steps=[
            "Navigate to Security > Network",
            "Verify Network Map shows geo-diverse connections",
            "Check that internal and external flows are visible",
            "Verify flow lines connect to different countries",
        ],
    ),
    "timeline": FeatureTest(
        name="timeline",
        description="Correlated events for Timeline investigation",
        kibana_path="/app/security/timelines",
        # Note: 'process' excluded - requires Scenario object
        event_types=["file", "registry", "endpoint-network", "dns", "authentication"],
        default_count=150,
        configuration={
            "correlation_required": True,
            "same_host": True,
            "time_spread_minutes": 60,
        },
        verification_steps=[
            "Navigate to Security > Timelines",
            "Create a new Timeline",
            "Query by host.id to see correlated events",
            "Verify events from multiple types appear",
            "Check that events are properly ordered by timestamp",
        ],
    ),
    "analyzer": FeatureTest(
        name="analyzer",
        description="Process tree for Analyzer visualization",
        kibana_path="/app/security/hosts",
        # Note: 'process' excluded - requires Scenario object; alerts include process context
        event_types=["alert", "file", "endpoint-network"],
        default_count=50,
        configuration={
            "process_tree_depth": 4,
            "malicious_chain": True,
        },
        verification_steps=[
            "Navigate to Security > Alerts",
            "Click on an alert to view details",
            "Click 'Analyze Event' button",
            "Verify process tree is displayed",
            "Check parent-child relationships are correct",
        ],
    ),
    "entity-analytics": FeatureTest(
        name="entity-analytics",
        description="Entity Analytics with risk scores for hosts and users",
        kibana_path="/app/security/entity_analytics",
        event_types=["risk-score", "authentication", "alert"],
        default_count=100,
        configuration={
            "host_risk_scores": True,
            "user_risk_scores": True,
            "risk_distribution": {"critical": 5, "high": 15, "medium": 30, "low": 50},
        },
        verification_steps=[
            "Navigate to Security > Entity Analytics",
            "Verify Host Risk dashboard shows scored hosts",
            "Verify User Risk dashboard shows scored users",
            "Check risk level distribution matches expected",
            "Click on a high-risk entity to view details",
        ],
    ),
    "detection-rule": FeatureTest(
        name="detection-rule",
        description="Malicious events for detection rule testing",
        kibana_path="/app/security/rules",
        # Note: 'process' excluded - requires Scenario object
        event_types=["file", "registry", "endpoint-network", "dns", "authentication"],
        default_count=75,
        configuration={
            "malicious_ratio": 0.8,
            "attack_patterns": ["malware-drop", "registry-persistence", "c2-beacon"],
        },
        verification_steps=[
            "Navigate to Security > Rules",
            "Enable relevant detection rules",
            "Wait for rule execution interval",
            "Verify alerts are generated",
            "Check alert severity matches rule configuration",
        ],
    ),
    "vulnerability-management": FeatureTest(
        name="vulnerability-management",
        description="Vulnerability scan events for VM dashboard",
        kibana_path="/app/security/vulnerability_management",
        event_types=["vulnerability"],
        default_count=200,
        configuration={
            "severity_distribution": {"critical": 10, "high": 30, "medium": 40, "low": 20},
            "multiple_hosts": True,
        },
        verification_steps=[
            "Navigate to Security > Vulnerability Management",
            "Verify vulnerability findings are displayed",
            "Check severity distribution in dashboard",
            "Filter by CVE ID to find specific vulnerabilities",
            "Verify host association is correct",
        ],
    ),
    "cloud-posture": FeatureTest(
        name="cloud-posture",
        description="CSPM compliance findings for Cloud Posture dashboard",
        kibana_path="/app/security/cloud_posture",
        event_types=["cspm"],
        default_count=150,
        configuration={
            "cloud_providers": ["aws", "azure"],
            "compliance_rate": 0.7,
        },
        verification_steps=[
            "Navigate to Security > Cloud Security Posture",
            "Verify CSPM findings are displayed",
            "Check pass/fail distribution",
            "Filter by cloud provider",
            "Verify CIS benchmark rules are shown",
        ],
    ),
}


def get_feature_tests() -> dict[str, str]:
    """
    Get feature tests as name: description mapping.

    Returns:
        Dictionary of feature name to description
    """
    return {name: ft.description for name, ft in FEATURE_TESTS.items()}


def get_feature_test(name: str) -> FeatureTest | None:
    """
    Get a specific feature test by name.

    Args:
        name: Feature test name

    Returns:
        FeatureTest or None if not found
    """
    return FEATURE_TESTS.get(name)

