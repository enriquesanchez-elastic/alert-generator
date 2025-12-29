"""Tests for LLM prompts."""

import pytest

from secgen.llm.prompts import (
    CAMPAIGN_OBJECTIVES,
    INDUSTRY_CONTEXTS,
    TACTIC_CATEGORIES,
    TACTIC_DESCRIPTIONS,
    THREAT_ACTOR_PROFILES,
    get_campaign_narrative_prompt,
    get_command_library_prompt,
    get_entity_profile_prompt,
    get_scenario_variation_prompt,
)


class TestCommandLibraryPrompt:
    """Tests for command library prompt generation."""

    def test_generates_prompt_with_tactic(self):
        """Test that prompt includes tactic."""
        prompt = get_command_library_prompt(tactic="lateral_movement")
        assert "lateral_movement" in prompt

    def test_generates_prompt_with_count(self):
        """Test that prompt includes count."""
        prompt = get_command_library_prompt(tactic="execution", count=50)
        assert "50" in prompt

    def test_generates_prompt_with_threat_actor(self):
        """Test that prompt includes threat actor style."""
        prompt = get_command_library_prompt(
            tactic="execution", threat_actor_style="APT29"
        )
        assert "APT29" in prompt

    def test_generates_prompt_with_os_family(self):
        """Test that prompt includes OS family."""
        prompt = get_command_library_prompt(tactic="execution", os_family="linux")
        assert "linux" in prompt

    def test_includes_tactic_description(self):
        """Test that prompt includes tactic description."""
        prompt = get_command_library_prompt(tactic="discovery")
        # discovery description includes "network" and "configuration"
        assert "network" in prompt.lower() or "configuration" in prompt.lower()

    def test_includes_categories(self):
        """Test that prompt includes categories."""
        prompt = get_command_library_prompt(tactic="lateral_movement")
        # Categories for lateral movement
        assert "wmi" in prompt.lower() or "psremoting" in prompt.lower()


class TestScenarioVariationPrompt:
    """Tests for scenario variation prompt generation."""

    def test_generates_prompt_with_base_info(self):
        """Test that prompt includes base scenario info."""
        prompt = get_scenario_variation_prompt(
            base_name="Ransomware",
            base_description="Test description",
            base_severity="critical",
            base_process_chain=[{"name": "proc1"}, {"name": "proc2"}],
        )

        assert "Ransomware" in prompt
        assert "Test description" in prompt
        assert "critical" in prompt
        assert "proc1" in prompt

    def test_generates_prompt_with_variation_count(self):
        """Test that prompt includes variation count."""
        prompt = get_scenario_variation_prompt(
            base_name="Test",
            base_description="",
            base_severity="high",
            base_process_chain=[],
            variation_count=10,
        )

        assert "10" in prompt

    def test_generates_prompt_with_target_os(self):
        """Test that prompt includes target OS."""
        prompt = get_scenario_variation_prompt(
            base_name="Test",
            base_description="",
            base_severity="high",
            base_process_chain=[],
            target_os="linux",
        )

        assert "linux" in prompt


class TestEntityProfilePrompt:
    """Tests for entity profile prompt generation."""

    def test_generates_prompt_with_industry(self):
        """Test that prompt includes industry."""
        prompt = get_entity_profile_prompt(industry="healthcare")
        assert "healthcare" in prompt.lower()

    def test_generates_prompt_with_role_count(self):
        """Test that prompt includes role count."""
        prompt = get_entity_profile_prompt(industry="finance", role_count=15)
        assert "15" in prompt

    def test_generates_prompt_with_org_size(self):
        """Test that prompt includes org size."""
        prompt = get_entity_profile_prompt(industry="retail", org_size="large")
        assert "large" in prompt

    def test_includes_industry_context(self):
        """Test that prompt includes industry-specific context."""
        prompt = get_entity_profile_prompt(industry="healthcare")
        # Healthcare context includes HIPAA
        assert "HIPAA" in prompt or "PHI" in prompt

    def test_handles_unknown_industry(self):
        """Test that unknown industry gets default context."""
        prompt = get_entity_profile_prompt(industry="unknown_industry")
        assert "Standard corporate" in prompt


class TestCampaignNarrativePrompt:
    """Tests for campaign narrative prompt generation."""

    def test_generates_prompt_with_threat_actor(self):
        """Test that prompt includes threat actor."""
        prompt = get_campaign_narrative_prompt(
            threat_actor="APT29", target_sector="technology"
        )
        # The prompt includes the actor name
        assert "APT29" in prompt

    def test_generates_prompt_with_target_sector(self):
        """Test that prompt includes target sector."""
        prompt = get_campaign_narrative_prompt(
            threat_actor="FIN7", target_sector="healthcare"
        )
        assert "healthcare" in prompt

    def test_generates_prompt_with_dwell_time(self):
        """Test that prompt includes dwell time."""
        prompt = get_campaign_narrative_prompt(
            threat_actor="APT29", target_sector="technology", dwell_time_days=21
        )
        # The dwell time appears in the format
        assert "21" in prompt or "dwell_time_days: 21" in prompt

    def test_generates_prompt_with_objective(self):
        """Test that prompt includes objective description."""
        prompt = get_campaign_narrative_prompt(
            threat_actor="APT29", target_sector="technology", objective="ransomware"
        )
        # The objective gets expanded to its description
        assert "ransomware" in prompt.lower() or "extortion" in prompt.lower() or "Deploy" in prompt

    def test_includes_threat_actor_context(self):
        """Test that prompt includes threat actor description."""
        prompt = get_campaign_narrative_prompt(
            threat_actor="APT29", target_sector="technology"
        )
        # APT29 profile mentions Russian or state-sponsored or stealthy
        assert any(term in prompt.lower() for term in ["russian", "state", "stealthy", "government"])


class TestPromptData:
    """Tests for prompt data constants."""

    def test_all_tactics_have_descriptions(self):
        """Test that all tactics have descriptions."""
        for tactic in TACTIC_CATEGORIES.keys():
            assert tactic in TACTIC_DESCRIPTIONS

    def test_all_tactics_have_categories(self):
        """Test that all tactics have categories."""
        for tactic in TACTIC_DESCRIPTIONS.keys():
            assert tactic in TACTIC_CATEGORIES
            assert len(TACTIC_CATEGORIES[tactic]) > 0

    def test_industry_contexts_not_empty(self):
        """Test that industry contexts are populated."""
        assert len(INDUSTRY_CONTEXTS) > 0
        for industry, context in INDUSTRY_CONTEXTS.items():
            assert len(context) > 0

    def test_threat_actor_profiles_not_empty(self):
        """Test that threat actor profiles are populated."""
        assert len(THREAT_ACTOR_PROFILES) > 0
        for actor, profile in THREAT_ACTOR_PROFILES.items():
            assert len(profile) > 0

    def test_campaign_objectives_not_empty(self):
        """Test that campaign objectives are populated."""
        assert len(CAMPAIGN_OBJECTIVES) > 0
        for objective, description in CAMPAIGN_OBJECTIVES.items():
            assert len(description) > 0

