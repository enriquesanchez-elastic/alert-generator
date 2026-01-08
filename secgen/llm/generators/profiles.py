"""Entity behavior profile generator using LLM."""

import logging
import random
from typing import Any

from secgen.llm.generators.base import BaseArtifactGenerator
from secgen.llm.prompts import INDUSTRY_CONTEXTS, get_entity_profile_prompt

logger = logging.getLogger(__name__)


class EntityProfileGenerator(BaseArtifactGenerator):
    """
    Generator for entity (user) behavior profiles.

    Creates realistic user personas for specific industry verticals,
    including typical behavior patterns and anomaly indicators.
    """

    ARTIFACT_TYPE = "profiles"

    # Available industries
    INDUSTRIES = list(INDUSTRY_CONTEXTS.keys())

    def generate(
        self,
        industry: str = "technology",
        role_count: int = 10,
        org_size: str = "medium",
        context: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate entity behavior profiles for an industry.

        Args:
            industry: Industry vertical (healthcare, finance, technology, etc.)
            role_count: Number of user personas to generate
            org_size: Organization size (small, medium, large)
            context: Additional context for the generation

        Returns:
            Dictionary with 'personas' list containing user profiles
        """
        prompt = get_entity_profile_prompt(
            industry=industry,
            role_count=role_count,
            org_size=org_size,
            context=context,
        )

        try:
            data = self.client.generate_yaml(
                prompt,
                temperature=0.7,
                max_output_tokens=8192,
            )

            # Validate structure
            if "personas" not in data:
                logger.warning("LLM response missing 'personas' key")
                if isinstance(data, list):
                    data = {"personas": data}
                else:
                    data = {"personas": [data]}

            # Add metadata
            data["industry"] = industry
            data["org_size"] = org_size
            data["role_count_requested"] = role_count
            data["role_count_generated"] = len(data.get("personas", []))

            logger.info(
                f"Generated {data['role_count_generated']} personas " f"for {industry} industry"
            )
            return data

        except Exception as e:
            logger.error(f"Failed to generate entity profiles: {e}")
            raise

    def get_artifact_name(
        self,
        industry: str = "technology",
        org_size: str = "medium",
        **kwargs: Any,
    ) -> str:
        """Generate artifact name from parameters."""
        return f"{industry.lower()}_{org_size}"

    def get_personas(
        self,
        industry: str = "technology",
        org_size: str = "medium",
    ) -> list[dict[str, Any]]:
        """
        Get list of personas from cache or generate.

        Args:
            industry: Industry vertical
            org_size: Organization size

        Returns:
            List of persona dictionaries
        """
        data = self.generate_or_load(
            industry=industry,
            org_size=org_size,
        )
        return data.get("personas", [])

    def get_random_persona(
        self,
        industry: str = "technology",
        org_size: str = "medium",
        privilege_level: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Get a random persona, optionally filtered by privilege level.

        Args:
            industry: Industry vertical
            org_size: Organization size
            privilege_level: Filter by privilege (standard, elevated, admin)

        Returns:
            Random persona dict, or None if not found
        """
        personas = self.get_personas(industry, org_size)

        if not personas:
            return None

        if privilege_level:
            filtered = [
                p for p in personas if p.get("privilege_level", "standard") == privilege_level
            ]
            if filtered:
                personas = filtered

        return random.choice(personas)

    def get_anomaly_indicators(
        self,
        industry: str = "technology",
        org_size: str = "medium",
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get anomaly indicators for a role or all roles.

        Args:
            industry: Industry vertical
            org_size: Organization size
            role: Specific role to get indicators for, or None for all

        Returns:
            List of anomaly indicator dictionaries
        """
        personas = self.get_personas(industry, org_size)
        indicators = []

        for persona in personas:
            if role and persona.get("role", "").lower() != role.lower():
                continue

            persona_indicators = persona.get("anomaly_indicators", [])
            for indicator in persona_indicators:
                indicator["role"] = persona.get("role", "Unknown")
                indicators.append(indicator)

        return indicators

    def get_typical_applications(
        self,
        industry: str = "technology",
        org_size: str = "medium",
        role: str | None = None,
    ) -> list[str]:
        """
        Get typical applications for roles.

        Args:
            industry: Industry vertical
            org_size: Organization size
            role: Specific role, or None for union of all

        Returns:
            List of application names
        """
        personas = self.get_personas(industry, org_size)
        apps = set()

        for persona in personas:
            if role and persona.get("role", "").lower() != role.lower():
                continue

            typical = persona.get("typical_behavior", {})
            persona_apps = typical.get("applications", [])
            apps.update(persona_apps)

        return list(apps)

    def generate_user_from_persona(
        self,
        persona: dict[str, Any],
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a concrete user instance from a persona template.

        Args:
            persona: Persona dictionary
            first_name: Override first name
            last_name: Override last name

        Returns:
            User dictionary with populated fields
        """
        # Generate names if not provided
        if not first_name:
            first_name = random.choice(
                [
                    "Alice",
                    "Bob",
                    "Charlie",
                    "Diana",
                    "Eve",
                    "Frank",
                    "Grace",
                    "Henry",
                    "Ivy",
                    "Jack",
                    "Kate",
                    "Liam",
                    "Maya",
                    "Noah",
                    "Olivia",
                    "Paul",
                    "Quinn",
                    "Rose",
                ]
            )

        if not last_name:
            last_name = random.choice(
                [
                    "Smith",
                    "Johnson",
                    "Williams",
                    "Brown",
                    "Jones",
                    "Garcia",
                    "Miller",
                    "Davis",
                    "Rodriguez",
                    "Martinez",
                    "Anderson",
                    "Taylor",
                    "Thomas",
                    "Moore",
                    "Jackson",
                ]
            )

        # Generate username from pattern
        pattern = persona.get("username_pattern", "{firstname}.{lastname}")
        username = pattern.format(
            firstname=first_name.lower(),
            lastname=last_name.lower(),
            dept=persona.get("department", "general").lower()[:3],
        )

        return {
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "role": persona.get("role", "Employee"),
            "department": persona.get("department", "General"),
            "privilege_level": persona.get("privilege_level", "standard"),
            "typical_behavior": persona.get("typical_behavior", {}),
            "anomaly_indicators": persona.get("anomaly_indicators", []),
        }

    @staticmethod
    def list_industries() -> list[str]:
        """Get list of available industries."""
        return list(INDUSTRY_CONTEXTS.keys())

    def generate_for_multiple_industries(
        self,
        industries: list[str] | None = None,
        role_count: int = 10,
        org_size: str = "medium",
        force_regenerate: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """
        Generate profiles for multiple industries.

        Args:
            industries: List of industries, or None for all
            role_count: Roles per industry
            org_size: Organization size
            force_regenerate: Regenerate even if cached

        Returns:
            Dictionary mapping industry names to profile data
        """
        if industries is None:
            industries = self.INDUSTRIES

        results = {}
        for industry in industries:
            try:
                results[industry] = self.generate_or_load(
                    force_regenerate=force_regenerate,
                    industry=industry,
                    role_count=role_count,
                    org_size=org_size,
                )
            except Exception as e:
                logger.error(f"Failed to generate profiles for {industry}: {e}")
                results[industry] = {"error": str(e)}

        return results
