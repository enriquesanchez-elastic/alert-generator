"""Command library generator using LLM."""

import logging
import random
from typing import Any

from secgen.llm.generators.base import BaseArtifactGenerator
from secgen.llm.prompts import (
    TACTIC_CATEGORIES,
    TACTIC_DESCRIPTIONS,
    get_command_library_prompt,
)

logger = logging.getLogger(__name__)


class CommandLibraryGenerator(BaseArtifactGenerator):
    """
    Generator for command libraries organized by MITRE ATT&CK tactics.

    Generates batches of realistic commands that can be used to populate
    process arguments and command-line events.
    """

    ARTIFACT_TYPE = "commands"

    # Available tactics
    TACTICS = list(TACTIC_DESCRIPTIONS.keys())

    def generate(
        self,
        tactic: str = "execution",
        count: int = 30,
        threat_actor_style: str = "generic_apt",
        os_family: str = "windows",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a command library for a specific tactic.

        Args:
            tactic: MITRE ATT&CK tactic (e.g., "execution", "lateral_movement")
            count: Number of commands to generate
            threat_actor_style: Threat actor to emulate
            os_family: Target OS (windows, linux, macos)

        Returns:
            Command library with categorized commands
        """
        prompt = get_command_library_prompt(
            tactic=tactic,
            count=count,
            threat_actor_style=threat_actor_style,
            os_family=os_family,
        )

        try:
            data = self.client.generate_json(
                prompt,
                temperature=0.8,  # Higher for more variety
                max_output_tokens=4096,
            )

            # Validate structure
            if "commands" not in data:
                logger.warning("LLM response missing 'commands' key, wrapping response")
                data = {"commands": data}

            # Add metadata
            data["tactic"] = tactic
            data["threat_actor_style"] = threat_actor_style
            data["os_family"] = os_family
            data["count_requested"] = count

            # Count actual commands
            total = sum(len(cmds) for cmds in data.get("commands", {}).values())
            data["count_generated"] = total

            logger.info(f"Generated {total} commands for tactic '{tactic}'")
            return data

        except Exception as e:
            logger.error(f"Failed to generate command library: {e}")
            raise

    def get_artifact_name(
        self,
        tactic: str = "execution",
        threat_actor_style: str = "generic_apt",
        os_family: str = "windows",
        **kwargs: Any,
    ) -> str:
        """Generate artifact name from parameters."""
        return f"{tactic}_{threat_actor_style}_{os_family}"

    def generate_all_tactics(
        self,
        count_per_tactic: int = 20,
        threat_actor_style: str = "generic_apt",
        os_family: str = "windows",
        force_regenerate: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """
        Generate command libraries for all tactics.

        Args:
            count_per_tactic: Commands per tactic
            threat_actor_style: Threat actor to emulate
            os_family: Target OS
            force_regenerate: Regenerate even if cached

        Returns:
            Dictionary mapping tactic names to command libraries
        """
        results = {}
        for tactic in self.TACTICS:
            try:
                results[tactic] = self.generate_or_load(
                    force_regenerate=force_regenerate,
                    tactic=tactic,
                    count=count_per_tactic,
                    threat_actor_style=threat_actor_style,
                    os_family=os_family,
                )
            except Exception as e:
                logger.error(f"Failed to generate commands for {tactic}: {e}")
                results[tactic] = {"error": str(e)}

        return results

    def get_random_command(
        self,
        tactic: str,
        category: str | None = None,
        threat_actor_style: str = "generic_apt",
        os_family: str = "windows",
    ) -> str | None:
        """
        Get a random command from the library.

        Args:
            tactic: Tactic to get command from
            category: Specific category, or None for any
            threat_actor_style: Threat actor style
            os_family: Target OS

        Returns:
            Random command string, or None if not available
        """
        library = self.generate_or_load(
            tactic=tactic,
            threat_actor_style=threat_actor_style,
            os_family=os_family,
        )

        commands = library.get("commands", {})
        if not commands:
            return None

        if category and category in commands:
            category_cmds = commands[category]
        else:
            # Get from any category
            all_cmds = []
            for cat_cmds in commands.values():
                if isinstance(cat_cmds, list):
                    all_cmds.extend(cat_cmds)
            category_cmds = all_cmds

        if not category_cmds:
            return None

        return random.choice(category_cmds)

    def get_commands_for_tactic(
        self,
        tactic: str,
        threat_actor_style: str = "generic_apt",
        os_family: str = "windows",
    ) -> dict[str, list[str]]:
        """
        Get all commands for a tactic, organized by category.

        Args:
            tactic: Tactic name
            threat_actor_style: Threat actor style
            os_family: Target OS

        Returns:
            Dictionary mapping categories to command lists
        """
        library = self.generate_or_load(
            tactic=tactic,
            threat_actor_style=threat_actor_style,
            os_family=os_family,
        )

        return library.get("commands", {})

    @staticmethod
    def list_tactics() -> list[str]:
        """Get list of available tactics."""
        return list(TACTIC_DESCRIPTIONS.keys())

    @staticmethod
    def list_categories(tactic: str) -> list[str]:
        """Get list of categories for a tactic."""
        return TACTIC_CATEGORIES.get(tactic.lower(), ["general"])

