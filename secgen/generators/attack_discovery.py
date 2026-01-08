"""Attack Discovery generator for creating AI-style attack summaries."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.data.mitre_attack import MITRE_TACTICS, get_technique
from secgen.generators.randomizers import RandomDataGenerator
from secgen.models.attack_discovery import ATTACK_DISCOVERY_TEMPLATES, AttackDiscovery
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User


@register_event_type(
    name="attack-discovery",
    category=GeneratorCategory.ANALYTICS,
    description="AI-generated attack discovery documents linking alerts to attack narratives",
    ecs_fields=[
        "kibana.alert.attack_discovery.id",
        "kibana.alert.attack_discovery.title",
        "kibana.alert.attack_discovery.alert_ids",
        "kibana.alert.attack_discovery.mitre_attack_tactics",
    ],
    index_pattern=".ai-attack-discovery-default",
    example_params={"attack_pattern": "brute-force", "alert_ids": ["uuid1", "uuid2"]},
)
class AttackDiscoveryGenerator:
    """
    Generator for creating Attack Discovery documents.

    Attack Discovery uses AI to analyze alerts and identify attack patterns.
    This generator creates realistic discovery documents with:
    - MITRE ATT&CK mapping
    - Attack narrative summaries
    - Entity correlation
    - Alert linkage
    """

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize Attack Discovery generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        attack_pattern: str,
        alert_ids: list[str],
        hosts: list["Host"] | None = None,
        users: list["User"] | None = None,
        timestamp_offset: int = 0,
        use_llm: bool = False,
    ) -> AttackDiscovery:
        """
        Generate an Attack Discovery document.

        Args:
            attack_pattern: Attack pattern name (e.g., "brute-force", "c2-beacon")
            alert_ids: List of alert UUIDs to link to this discovery
            hosts: Optional list of affected Host entities
            users: Optional list of affected User entities
            timestamp_offset: Minutes to offset timestamp
            use_llm: Whether to use LLM for enhanced content (not implemented here)

        Returns:
            AttackDiscovery instance
        """
        timestamp = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)

        # Get template for this attack pattern
        template = ATTACK_DISCOVERY_TEMPLATES.get(attack_pattern)
        if not template:
            # Fall back to a generic template
            template = self._generate_generic_template(attack_pattern)

        # Build entity lists
        host_list = []
        if hosts:
            for host in hosts:
                host_list.append({
                    "name": host.name,
                    "id": host.id,
                })

        user_list = []
        if users:
            for user in users:
                user_list.append({
                    "name": user.name,
                    "id": user.id if hasattr(user, "id") else "",
                })

        # Build entity summary markdown
        entity_summary = self._build_entity_summary(hosts, users)

        # Extract tactics and techniques
        ttps = template.get("ttps", [])
        tactics = template.get("tactics", [])

        # If tactics not provided, derive from techniques
        if not tactics and ttps:
            tactics = self._derive_tactics_from_techniques(ttps)

        discovery = AttackDiscovery(
            title=template.get("title", f"Attack Discovery: {attack_pattern}"),
            alert_ids=alert_ids,
            timestamp=timestamp.isoformat(),
            details_markdown=template.get("details_markdown", ""),
            summary_markdown=template.get("summary_markdown", ""),
            entity_summary_markdown=entity_summary,
            mitre_attack_tactics=tactics,
            mitre_attack_techniques=ttps,
            risk_score=template.get("risk_score", 50),
            status="open",
            hosts=host_list,
            users=user_list,
            attack_first_seen=(timestamp - timedelta(minutes=random.randint(5, 60))).isoformat(),
            attack_last_seen=timestamp.isoformat(),
        )

        return discovery

    def generate_from_alerts(
        self,
        alerts: list[dict[str, Any]],
        attack_pattern: str | None = None,
    ) -> AttackDiscovery:
        """
        Generate an Attack Discovery from alert documents.

        Analyzes the alerts to extract hosts, users, and determine attack pattern.

        Args:
            alerts: List of alert dictionaries
            attack_pattern: Optional attack pattern override

        Returns:
            AttackDiscovery instance
        """
        if not alerts:
            raise ValueError("At least one alert is required")

        # Extract alert IDs
        alert_ids = []
        for alert in alerts:
            alert_id = alert.get("kibana.alert.uuid") or alert.get("_id", "")
            if alert_id:
                alert_ids.append(alert_id)

        # Extract unique hosts
        hosts_dict: dict[str, dict[str, str]] = {}
        for alert in alerts:
            host = alert.get("host", {})
            host_id = host.get("id", "")
            if host_id and host_id not in hosts_dict:
                hosts_dict[host_id] = {
                    "name": host.get("name", "unknown"),
                    "id": host_id,
                }

        # Extract unique users
        users_dict: dict[str, dict[str, str]] = {}
        for alert in alerts:
            user = alert.get("user", {})
            user_name = user.get("name", "")
            if user_name and user_name not in users_dict:
                users_dict[user_name] = {
                    "name": user_name,
                    "id": user.get("id", ""),
                }

        # Determine attack pattern from alerts if not provided
        if not attack_pattern:
            attack_pattern = self._infer_attack_pattern(alerts)

        # Get template
        template = ATTACK_DISCOVERY_TEMPLATES.get(attack_pattern)
        if not template:
            template = self._generate_generic_template(attack_pattern)

        # Build entity summary
        entity_summary = self._build_entity_summary_from_dicts(
            list(hosts_dict.values()),
            list(users_dict.values()),
        )

        # Get timestamps from alerts
        timestamps = []
        for alert in alerts:
            ts = alert.get("@timestamp", "")
            if ts:
                timestamps.append(ts)

        first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()
        last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc).isoformat()

        # Extract tactics and techniques
        ttps = template.get("ttps", [])
        tactics = template.get("tactics", [])
        if not tactics and ttps:
            tactics = self._derive_tactics_from_techniques(ttps)

        discovery = AttackDiscovery(
            title=template.get("title", f"Attack Discovery: {attack_pattern}"),
            alert_ids=alert_ids,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details_markdown=template.get("details_markdown", ""),
            summary_markdown=template.get("summary_markdown", ""),
            entity_summary_markdown=entity_summary,
            mitre_attack_tactics=tactics,
            mitre_attack_techniques=ttps,
            risk_score=template.get("risk_score", 50),
            status="open",
            hosts=list(hosts_dict.values()),
            users=list(users_dict.values()),
            attack_first_seen=first_seen,
            attack_last_seen=last_seen,
        )

        return discovery

    def _generate_generic_template(self, attack_pattern: str) -> dict[str, Any]:
        """Generate a generic template for unknown attack patterns."""
        return {
            "title": f"Suspicious Activity Detected: {attack_pattern.replace('-', ' ').title()}",
            "summary_markdown": f"Suspicious activity matching the pattern '{attack_pattern}' has been detected and requires investigation.",
            "details_markdown": f"""## Attack Overview

Suspicious activity has been detected in the environment.

### Key Findings
- **Attack Pattern**: {attack_pattern}
- **Risk Level**: Medium

### Recommendations
1. Review the associated alerts
2. Investigate affected hosts and users
3. Determine scope of potential compromise
4. Take appropriate containment actions
5. Document findings and update security controls""",
            "ttps": [],
            "tactics": [],
            "risk_score": 50,
        }

    def _build_entity_summary(
        self,
        hosts: Optional[list["Host"]],
        users: Optional[list["User"]],
    ) -> str:
        """Build entity summary markdown from entity objects."""
        lines = ["## Affected Entities\n"]

        if hosts:
            lines.append("### Hosts")
            for host in hosts:
                lines.append(f"- **{host.name}** (ID: `{host.id}`)")
            lines.append("")

        if users:
            lines.append("### Users")
            for user in users:
                user_id = getattr(user, "id", "unknown")
                lines.append(f"- **{user.name}** (ID: `{user_id}`)")
            lines.append("")

        if not hosts and not users:
            lines.append("No specific entities identified.")

        return "\n".join(lines)

    def _build_entity_summary_from_dicts(
        self,
        hosts: list[dict[str, str]],
        users: list[dict[str, str]],
    ) -> str:
        """Build entity summary markdown from dictionaries."""
        lines = ["## Affected Entities\n"]

        if hosts:
            lines.append("### Hosts")
            for host in hosts:
                lines.append(f"- **{host.get('name', 'unknown')}** (ID: `{host.get('id', 'unknown')}`)")
            lines.append("")

        if users:
            lines.append("### Users")
            for user in users:
                lines.append(f"- **{user.get('name', 'unknown')}** (ID: `{user.get('id', 'unknown')}`)")
            lines.append("")

        if not hosts and not users:
            lines.append("No specific entities identified.")

        return "\n".join(lines)

    def _derive_tactics_from_techniques(self, techniques: list[str]) -> list[str]:
        """Derive tactic IDs from technique IDs."""
        tactics = set()
        for tech_id in techniques:
            # Handle subtechniques (e.g., T1110.001)
            base_id = tech_id.split(".")[0]
            technique = get_technique(base_id)
            if technique and "tactic_ids" in technique:
                tactics.update(technique["tactic_ids"])
        return list(tactics)

    def _infer_attack_pattern(self, alerts: list[dict[str, Any]]) -> str:
        """Infer attack pattern from alert content."""
        # Check for common patterns in alert fields
        all_text = ""
        for alert in alerts:
            rule_name = alert.get("kibana.alert.rule.name", "").lower()
            rule_desc = alert.get("kibana.alert.rule.description", "").lower()
            event_category = str(alert.get("event", {}).get("category", [])).lower()
            all_text += f" {rule_name} {rule_desc} {event_category}"

        # Pattern matching
        if "brute" in all_text or "authentication" in all_text:
            return "brute-force"
        elif "beacon" in all_text or "c2" in all_text or "command and control" in all_text:
            return "c2-beacon"
        elif "dga" in all_text or "domain generation" in all_text:
            return "dga"
        elif "lateral" in all_text or "rdp" in all_text or "smb" in all_text:
            return "lateral-movement"
        elif "ransom" in all_text or "encrypt" in all_text:
            return "ransomware"
        elif "exfil" in all_text:
            return "data-exfiltration"
        elif "credential" in all_text or "mimikatz" in all_text or "lsass" in all_text:
            return "credential-dump"
        elif "malware" in all_text or "malicious" in all_text:
            return "malware-drop"
        elif "phish" in all_text:
            return "phishing"
        elif "shell" in all_text or "webshell" in all_text:
            return "webshell"
        else:
            return "unknown"

    def generate_batch(
        self,
        attack_patterns: list[str],
        alerts_per_discovery: int = 5,
        hosts: Optional[list["Host"]] = None,
        users: Optional[list["User"]] = None,
    ) -> list[AttackDiscovery]:
        """
        Generate multiple Attack Discovery documents.

        Args:
            attack_patterns: List of attack pattern names
            alerts_per_discovery: Number of fake alert IDs per discovery
            hosts: Optional list of hosts to distribute across discoveries
            users: Optional list of users to distribute across discoveries

        Returns:
            List of AttackDiscovery instances
        """
        discoveries = []

        for i, pattern in enumerate(attack_patterns):
            # Generate fake alert IDs
            alert_ids = [self.randomizer.generate_uuid() for _ in range(alerts_per_discovery)]

            # Select subset of hosts and users if provided
            pattern_hosts = None
            pattern_users = None
            if hosts:
                pattern_hosts = [hosts[i % len(hosts)]] if hosts else None
            if users:
                pattern_users = [users[i % len(users)]] if users else None

            discovery = self.generate(
                attack_pattern=pattern,
                alert_ids=alert_ids,
                hosts=pattern_hosts,
                users=pattern_users,
                timestamp_offset=len(attack_patterns) - i,
            )
            discoveries.append(discovery)

        return discoveries

