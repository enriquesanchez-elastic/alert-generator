"""Case generator for creating security investigation cases."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.models.attack_discovery import AttackDiscovery
from secgen.models.case import (
    CASE_TEMPLATES,
    CaseAlertAttachment,
    CaseComment,
    CaseConnector,
    CaseSeverity,
    SecurityCase,
)
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User


@register_event_type(
    name="case",
    category=GeneratorCategory.ANALYTICS,
    description="Security investigation cases with alert and attack discovery linkage",
    ecs_fields=[
        "case.id",
        "case.title",
        "case.status",
        "case.severity",
    ],
    index_pattern="",  # Cases use Kibana API, not direct indexing
    example_params={"template": "brute-force-investigation", "alert_ids": ["uuid1"]},
)
class CaseGenerator:
    """
    Generator for creating Security Cases.

    Cases allow analysts to track and manage security investigations,
    linking alerts, attack discoveries, comments, and external systems.
    """

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize Case generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        template: str | None = None,
        title: str | None = None,
        description: str | None = None,
        severity: CaseSeverity = "medium",
        tags: list[str] | None = None,
        assignees: list[str] | None = None,
        alert_ids: list[str] | None = None,
        attack_discovery_ids: list[str] | None = None,
        created_by: str = "elastic",
    ) -> SecurityCase:
        """
        Generate a security case.

        Args:
            template: Case template name (e.g., "brute-force-investigation")
            title: Case title (overrides template)
            description: Case description (overrides template)
            severity: Case severity (low, medium, high, critical)
            tags: List of tags
            assignees: List of assigned usernames
            alert_ids: List of alert UUIDs to attach
            attack_discovery_ids: List of attack discovery IDs to link
            created_by: Username of case creator

        Returns:
            SecurityCase instance
        """
        # Get template if provided
        template_data: dict[str, Any] = {}
        if template:
            template_data = CASE_TEMPLATES.get(template, {})

        # Build case fields
        case_title = title or template_data.get("title", "Security Investigation")
        case_description = description or template_data.get("description", "Security investigation case.")
        case_severity = severity or template_data.get("severity", "medium")
        case_tags = tags or template_data.get("tags", [])

        # Create case
        case = SecurityCase(
            title=case_title,
            description=case_description,
            severity=case_severity,
            tags=case_tags,
            assignees=assignees or [],
            created_by=created_by,
            updated_by=created_by,
        )

        # Add initial comments from template
        initial_comments = template_data.get("initial_comments", [])
        for comment_text in initial_comments:
            case.add_comment(comment_text, created_by=created_by)

        # Attach alerts
        if alert_ids:
            for alert_id in alert_ids:
                case.attach_alert(
                    alert_id=alert_id,
                    index=".alerts-security.alerts-default",
                )

        # Link attack discoveries
        if attack_discovery_ids:
            for discovery_id in attack_discovery_ids:
                case.link_attack_discovery(discovery_id)

        return case

    def generate_from_alerts(
        self,
        alerts: list[dict[str, Any]],
        attack_pattern: str | None = None,
        assignee: Optional["User"] = None,
    ) -> SecurityCase:
        """
        Generate a case from alert documents.

        Analyzes alerts to determine appropriate case template and
        automatically attaches all alerts to the case.

        Args:
            alerts: List of alert dictionaries
            attack_pattern: Optional attack pattern override
            assignee: Optional User entity to assign

        Returns:
            SecurityCase instance
        """
        if not alerts:
            raise ValueError("At least one alert is required")

        # Determine attack pattern if not provided
        if not attack_pattern:
            attack_pattern = self._infer_attack_pattern(alerts)

        # Map attack pattern to case template
        template_mapping = {
            "brute-force": "brute-force-investigation",
            "ssh-brute-force": "brute-force-investigation",
            "malware-drop": "malware-incident",
            "ransomware": "ransomware-incident",
            "c2-beacon": "c2-investigation",
            "dga": "c2-investigation",
            "data-exfiltration": "data-exfiltration-investigation",
            "lateral-movement": "lateral-movement-investigation",
        }
        template = template_mapping.get(attack_pattern)

        # Extract alert IDs
        alert_ids = []
        for alert in alerts:
            alert_id = alert.get("kibana.alert.uuid") or alert.get("_id", "")
            if alert_id:
                alert_ids.append(alert_id)

        # Determine severity from alerts
        severities = []
        for alert in alerts:
            sev = alert.get("kibana.alert.severity", "medium")
            severities.append(sev)

        # Use highest severity
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_severity = max(severities, key=lambda s: severity_order.get(s, 0))

        # Build tags from alerts
        tags = set()
        for alert in alerts:
            rule_tags = alert.get("kibana.alert.rule.tags", [])
            tags.update(rule_tags)
        tags.add(attack_pattern)

        # Generate case
        case = self.generate(
            template=template,
            severity=max_severity,
            tags=list(tags)[:10],  # Limit tags
            assignees=[assignee.name] if assignee else [],
            alert_ids=alert_ids,
        )

        # Add analysis comment
        host_count = len(set(a.get("host", {}).get("name", "") for a in alerts if a.get("host")))
        user_count = len(set(a.get("user", {}).get("name", "") for a in alerts if a.get("user")))

        case.add_comment(
            f"Initial analysis: {len(alerts)} alerts analyzed. "
            f"Affected hosts: {host_count}, Affected users: {user_count}. "
            f"Attack pattern: {attack_pattern}.",
            created_by="system",
        )

        return case

    def generate_from_attack_discovery(
        self,
        discovery: AttackDiscovery,
        assignee: Optional["User"] = None,
    ) -> SecurityCase:
        """
        Generate a case from an Attack Discovery document.

        Creates a case linked to the attack discovery with appropriate
        template and attached alerts.

        Args:
            discovery: AttackDiscovery instance
            assignee: Optional User entity to assign

        Returns:
            SecurityCase instance
        """
        # Infer attack pattern from discovery
        attack_pattern = self._infer_pattern_from_discovery(discovery)

        # Map to template
        template_mapping = {
            "brute-force": "brute-force-investigation",
            "c2-beacon": "c2-investigation",
            "dga": "c2-investigation",
            "lateral-movement": "lateral-movement-investigation",
            "ransomware": "ransomware-incident",
            "data-exfiltration": "data-exfiltration-investigation",
            "credential-dump": "brute-force-investigation",
            "malware-drop": "malware-incident",
        }
        template = template_mapping.get(attack_pattern)

        # Determine severity from risk score
        if discovery.risk_score >= 90:
            severity: CaseSeverity = "critical"
        elif discovery.risk_score >= 70:
            severity = "high"
        elif discovery.risk_score >= 40:
            severity = "medium"
        else:
            severity = "low"

        # Build tags
        tags = [attack_pattern] + discovery.mitre_attack_tactics[:3]

        # Generate case
        case = self.generate(
            template=template,
            severity=severity,
            tags=tags,
            assignees=[assignee.name] if assignee else [],
            alert_ids=discovery.alert_ids,
            attack_discovery_ids=[discovery.id],
        )

        # Add discovery summary as comment
        case.add_comment(
            f"**Attack Discovery Summary:**\n\n{discovery.summary_markdown}",
            created_by="system",
        )

        # Add entity summary
        if discovery.entity_summary_markdown:
            case.add_comment(
                discovery.entity_summary_markdown,
                created_by="system",
            )

        return case

    def generate_investigation_workflow(
        self,
        case: SecurityCase,
        workflow_steps: list[str] | None = None,
        analyst: str = "analyst",
    ) -> SecurityCase:
        """
        Simulate an investigation workflow by adding comments.

        Args:
            case: Existing SecurityCase instance
            workflow_steps: Optional list of workflow steps
            analyst: Analyst username

        Returns:
            Updated SecurityCase instance
        """
        default_workflow = [
            "Beginning initial triage and alert review.",
            "Confirmed malicious activity based on alert analysis.",
            "Gathering additional evidence from affected systems.",
            "Identified scope of compromise.",
            "Initiating containment procedures.",
            "Containment complete. Beginning remediation.",
            "Remediation in progress.",
        ]

        steps = workflow_steps or default_workflow

        # Add comments with timestamps spread over time
        for i, step in enumerate(steps):
            # Update case status based on progress
            if i == 1:
                case.status = "in-progress"

            case.add_comment(step, created_by=analyst)

        return case

    def _infer_attack_pattern(self, alerts: list[dict[str, Any]]) -> str:
        """Infer attack pattern from alert content."""
        all_text = ""
        for alert in alerts:
            rule_name = alert.get("kibana.alert.rule.name", "").lower()
            rule_desc = alert.get("kibana.alert.rule.description", "").lower()
            tags = " ".join(alert.get("kibana.alert.rule.tags", [])).lower()
            all_text += f" {rule_name} {rule_desc} {tags}"

        # Pattern matching
        if "brute" in all_text or "failed" in all_text and "auth" in all_text:
            return "brute-force"
        elif "beacon" in all_text or "c2" in all_text or "command" in all_text:
            return "c2-beacon"
        elif "dga" in all_text or "domain generation" in all_text:
            return "dga"
        elif "lateral" in all_text or "rdp" in all_text or "smb" in all_text:
            return "lateral-movement"
        elif "ransom" in all_text:
            return "ransomware"
        elif "exfil" in all_text:
            return "data-exfiltration"
        elif "malware" in all_text or "malicious" in all_text:
            return "malware-drop"
        else:
            return "unknown"

    def _infer_pattern_from_discovery(self, discovery: AttackDiscovery) -> str:
        """Infer attack pattern from attack discovery."""
        title_lower = discovery.title.lower()

        patterns = {
            "brute force": "brute-force",
            "c2": "c2-beacon",
            "command and control": "c2-beacon",
            "beacon": "c2-beacon",
            "dga": "dga",
            "lateral": "lateral-movement",
            "ransomware": "ransomware",
            "exfiltration": "data-exfiltration",
            "credential": "credential-dump",
            "malware": "malware-drop",
        }

        for keyword, pattern in patterns.items():
            if keyword in title_lower:
                return pattern

        return "unknown"

    def generate_batch(
        self,
        count: int,
        templates: list[str] | None = None,
        alerts_per_case: int = 5,
    ) -> list[SecurityCase]:
        """
        Generate multiple cases.

        Args:
            count: Number of cases to generate
            templates: Optional list of templates to cycle through
            alerts_per_case: Number of fake alert IDs per case

        Returns:
            List of SecurityCase instances
        """
        if templates is None:
            templates = list(CASE_TEMPLATES.keys())

        cases = []
        for i in range(count):
            template = templates[i % len(templates)]

            # Generate fake alert IDs
            alert_ids = [self.randomizer.generate_uuid() for _ in range(alerts_per_case)]

            case = self.generate(
                template=template,
                alert_ids=alert_ids,
            )
            cases.append(case)

        return cases

