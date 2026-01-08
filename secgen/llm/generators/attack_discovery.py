"""LLM-powered Attack Discovery generator for realistic attack narratives."""

import json
import logging
from typing import Any

from secgen.llm.cache import ArtifactCache
from secgen.llm.client import GeminiClient
from secgen.llm.generators.base import BaseLLMGenerator

logger = logging.getLogger(__name__)


class AttackDiscoveryLLMGenerator(BaseLLMGenerator):
    """
    LLM-powered generator for Attack Discovery narratives.

    Uses Gemini to generate realistic attack summaries, timelines,
    and investigation recommendations based on alert context.
    """

    CACHE_PREFIX = "attack_discovery"

    def __init__(
        self,
        client: GeminiClient,
        cache: ArtifactCache | None = None,
    ) -> None:
        """
        Initialize Attack Discovery LLM generator.

        Args:
            client: GeminiClient instance
            cache: Optional ArtifactCache instance
        """
        super().__init__(client, cache)

    def generate_discovery_narrative(
        self,
        attack_pattern: str,
        alert_summaries: list[dict[str, Any]],
        affected_hosts: list[str],
        affected_users: list[str],
        mitre_ttps: list[str],
    ) -> dict[str, str]:
        """
        Generate a detailed attack discovery narrative using LLM.

        Args:
            attack_pattern: Name of the attack pattern
            alert_summaries: List of summarized alert information
            affected_hosts: List of affected host names
            affected_users: List of affected usernames
            mitre_ttps: List of MITRE ATT&CK technique IDs

        Returns:
            Dictionary with title, summary_markdown, details_markdown, entity_summary_markdown
        """
        # Build cache key
        cache_key = f"{attack_pattern}_{len(alert_summaries)}_{len(affected_hosts)}_{len(affected_users)}"

        # Check cache
        if self.cache:
            cached = self.cache.get(self.CACHE_PREFIX, cache_key)
            if cached:
                logger.debug(f"Using cached attack discovery narrative for {cache_key}")
                return cached

        # Build prompt
        prompt = self._build_discovery_prompt(
            attack_pattern,
            alert_summaries,
            affected_hosts,
            affected_users,
            mitre_ttps,
        )

        try:
            response = self.client.generate(prompt)
            result = self._parse_discovery_response(response)

            # Cache result
            if self.cache:
                self.cache.set(self.CACHE_PREFIX, cache_key, result)

            return result

        except Exception as e:
            logger.warning(f"LLM generation failed, using fallback: {e}")
            return self._generate_fallback(attack_pattern, affected_hosts, affected_users)

    def _build_discovery_prompt(
        self,
        attack_pattern: str,
        alert_summaries: list[dict[str, Any]],
        affected_hosts: list[str],
        affected_users: list[str],
        mitre_ttps: list[str],
    ) -> str:
        """Build the prompt for attack discovery generation."""
        alerts_text = json.dumps(alert_summaries, indent=2) if alert_summaries else "No alerts provided"
        hosts_text = ", ".join(affected_hosts) if affected_hosts else "Unknown hosts"
        users_text = ", ".join(affected_users) if affected_users else "Unknown users"
        ttps_text = ", ".join(mitre_ttps) if mitre_ttps else "Unknown techniques"

        return f"""You are a security analyst AI generating an Attack Discovery report for a SIEM system.
Based on the following information, generate a comprehensive attack discovery narrative.

ATTACK PATTERN: {attack_pattern}

ASSOCIATED ALERTS:
{alerts_text}

AFFECTED HOSTS: {hosts_text}
AFFECTED USERS: {users_text}
MITRE ATT&CK TTPs: {ttps_text}

Generate a JSON response with exactly these fields:
{{
    "title": "A concise, professional title for this attack discovery (max 100 chars)",
    "summary_markdown": "A 1-2 sentence executive summary of the attack (max 300 chars)",
    "details_markdown": "A detailed markdown report including: ## Attack Overview, ### Key Findings, ### Attack Timeline, ### Recommendations (500-1000 words)",
    "entity_summary_markdown": "A markdown summary of affected entities with bullet points"
}}

Requirements:
- Be specific and actionable
- Use professional security analyst language
- Reference the specific hosts, users, and TTPs provided
- Include concrete remediation steps
- Format in valid markdown

Return ONLY the JSON object, no additional text."""

    def _parse_discovery_response(self, response: str) -> dict[str, str]:
        """Parse the LLM response into structured fields."""
        try:
            # Try to extract JSON from response
            response = response.strip()

            # Handle potential markdown code blocks
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]

            result = json.loads(response.strip())

            # Validate required fields
            required_fields = ["title", "summary_markdown", "details_markdown", "entity_summary_markdown"]
            for field in required_fields:
                if field not in result:
                    result[field] = ""

            return result

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            # Extract content manually if JSON parsing fails
            return {
                "title": "Attack Discovery",
                "summary_markdown": response[:300] if response else "",
                "details_markdown": response,
                "entity_summary_markdown": "",
            }

    def _generate_fallback(
        self,
        attack_pattern: str,
        affected_hosts: list[str],
        affected_users: list[str],
    ) -> dict[str, str]:
        """Generate fallback content when LLM is unavailable."""
        hosts_text = ", ".join(affected_hosts[:5]) if affected_hosts else "multiple hosts"
        users_text = ", ".join(affected_users[:5]) if affected_users else "multiple users"

        return {
            "title": f"Attack Discovery: {attack_pattern.replace('-', ' ').title()}",
            "summary_markdown": f"Suspicious activity matching '{attack_pattern}' detected affecting {hosts_text}.",
            "details_markdown": f"""## Attack Overview

An attack matching the pattern **{attack_pattern}** has been detected in the environment.

### Key Findings
- **Attack Pattern**: {attack_pattern}
- **Affected Hosts**: {hosts_text}
- **Affected Users**: {users_text}

### Recommendations
1. Investigate the affected systems immediately
2. Review associated alerts for additional context
3. Isolate compromised systems if necessary
4. Document findings and update detection rules""",
            "entity_summary_markdown": f"""## Affected Entities

### Hosts
{chr(10).join(f'- {h}' for h in affected_hosts[:10]) if affected_hosts else '- Unknown hosts'}

### Users
{chr(10).join(f'- {u}' for u in affected_users[:10]) if affected_users else '- Unknown users'}""",
        }

    def enhance_discovery(
        self,
        discovery_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Enhance an existing attack discovery with LLM-generated content.

        Args:
            discovery_dict: Existing attack discovery dictionary

        Returns:
            Enhanced discovery dictionary
        """
        # Extract info from existing discovery
        alert_ids = discovery_dict.get("kibana.alert.attack_discovery.alert_ids", [])
        hosts = discovery_dict.get("kibana.alert.attack_discovery.hosts", [])
        users = discovery_dict.get("kibana.alert.attack_discovery.users", [])
        ttps = discovery_dict.get("kibana.alert.attack_discovery.mitre_attack_techniques", [])

        # Infer attack pattern from title if available
        title = discovery_dict.get("kibana.alert.attack_discovery.title", "")
        attack_pattern = self._infer_pattern_from_title(title)

        # Build alert summaries (simplified)
        alert_summaries = [{"id": aid} for aid in alert_ids[:10]]

        # Generate enhanced narrative
        host_names = [h.get("name", "") for h in hosts]
        user_names = [u.get("name", "") for u in users]

        narrative = self.generate_discovery_narrative(
            attack_pattern=attack_pattern,
            alert_summaries=alert_summaries,
            affected_hosts=host_names,
            affected_users=user_names,
            mitre_ttps=ttps,
        )

        # Update discovery with enhanced content
        enhanced = discovery_dict.copy()
        enhanced["kibana.alert.attack_discovery.title"] = narrative.get("title", title)
        enhanced["kibana.alert.attack_discovery.summary_markdown"] = narrative.get("summary_markdown", "")
        enhanced["kibana.alert.attack_discovery.details_markdown"] = narrative.get("details_markdown", "")
        enhanced["kibana.alert.attack_discovery.entity_summary_markdown"] = narrative.get("entity_summary_markdown", "")

        return enhanced

    def _infer_pattern_from_title(self, title: str) -> str:
        """Infer attack pattern from discovery title."""
        title_lower = title.lower()

        patterns = {
            "brute force": "brute-force",
            "c2": "c2-beacon",
            "command and control": "c2-beacon",
            "beacon": "c2-beacon",
            "dga": "dga",
            "domain generation": "dga",
            "lateral": "lateral-movement",
            "ransomware": "ransomware",
            "exfiltration": "data-exfiltration",
            "credential": "credential-dump",
            "malware": "malware-drop",
            "phishing": "phishing",
            "webshell": "webshell",
        }

        for keyword, pattern in patterns.items():
            if keyword in title_lower:
                return pattern

        return "unknown"

