"""Tests for the preset system."""

import pytest

from secgen.presets.schema import (
    Preset,
    PresetStep,
    list_builtin_presets,
    load_preset,
    BUILTIN_PRESETS,
)


class TestPresetStep:
    """Tests for PresetStep dataclass."""

    def test_create_basic_step(self):
        """Should create a basic preset step."""
        step = PresetStep(
            type="event",
            name="dns",
            count=50,
        )

        assert step.type == "event"
        assert step.name == "dns"
        assert step.count == 50
        assert step.params == {}

    def test_create_step_with_params(self):
        """Should create step with parameters."""
        step = PresetStep(
            type="attack",
            name="brute-force",
            count=3,
            params={"success_at_end": True},
        )

        assert step.params["success_at_end"] is True


class TestPreset:
    """Tests for Preset dataclass."""

    def test_create_preset(self):
        """Should create a preset."""
        preset = Preset(
            name="test-preset",
            description="Test preset",
            steps=[
                PresetStep(type="event", name="dns", count=10),
                PresetStep(type="attack", name="brute-force", count=1),
            ],
        )

        assert preset.name == "test-preset"
        assert len(preset.steps) == 2
        assert preset.index is True
        assert preset.time_spread_hours == 24

    def test_from_dict(self):
        """Should create preset from dictionary."""
        data = {
            "name": "dict-preset",
            "description": "From dict",
            "world": {"hosts": 10, "users": 20},
            "time_spread_hours": 12,
            "steps": [
                {"type": "event", "name": "process", "count": 100},
                {"type": "attack", "name": "c2-beacon", "count": 2},
            ],
        }

        preset = Preset.from_dict(data)

        assert preset.name == "dict-preset"
        assert preset.world_config["hosts"] == 10
        assert preset.time_spread_hours == 12
        assert len(preset.steps) == 2
        assert preset.steps[0].name == "process"
        assert preset.steps[1].type == "attack"


class TestBuiltinPresets:
    """Tests for built-in presets."""

    def test_list_builtin_presets(self):
        """Should list all built-in presets."""
        presets = list_builtin_presets()

        assert "demo-cluster" in presets
        assert "entity-analytics-showcase" in presets
        assert "load-test" in presets
        assert "attack-simulation" in presets

    def test_demo_cluster_preset(self):
        """Should load demo-cluster preset."""
        preset = load_preset("demo-cluster")

        assert preset.name == "demo-cluster"
        assert len(preset.steps) > 0
        # Should have diverse event types
        event_types = [s.name for s in preset.steps if s.type == "event"]
        # Note: 'process' events require Scenario context, so not included directly
        assert "file" in event_types
        assert "dns" in event_types
        assert "authentication" in event_types

    def test_attack_simulation_preset(self):
        """Should load attack-simulation preset."""
        preset = load_preset("attack-simulation")

        assert preset.name == "attack-simulation"
        # Should have attack steps
        attack_steps = [s for s in preset.steps if s.type == "attack"]
        assert len(attack_steps) > 0

    def test_all_builtin_presets_valid(self):
        """All built-in presets should be loadable."""
        for name in BUILTIN_PRESETS:
            preset = load_preset(name)
            assert preset.name == name
            assert preset.description
            assert len(preset.steps) > 0


class TestLoadPreset:
    """Tests for load_preset function."""

    def test_load_builtin_preset(self):
        """Should load built-in preset by name."""
        preset = load_preset("demo-cluster")
        assert preset.name == "demo-cluster"

    def test_load_nonexistent_preset(self):
        """Should raise error for non-existent preset."""
        with pytest.raises(ValueError) as exc_info:
            load_preset("nonexistent-preset")

        assert "not found" in str(exc_info.value)
        assert "Available presets" in str(exc_info.value)

