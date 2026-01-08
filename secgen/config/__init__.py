"""Configuration management for alerts generator.

This module provides configuration loaders and settings management.

Functions:
- load_scenarios_from_file: Load legacy scenario YAML files
- load_multi_event_scenarios: Load multi-event scenario YAML files
- create_sample_multi_event_scenario: Generate sample multi-event scenario

Classes:
- Settings: Pydantic settings class (requires pydantic)
"""

from secgen.config.loader import (
    create_sample_multi_event_scenario,
    load_multi_event_scenarios,
    load_scenarios_from_file,
)

__all__ = [
    "load_scenarios_from_file",
    "load_multi_event_scenarios",
    "create_sample_multi_event_scenario",
]


def __getattr__(name: str):
    """Lazy import of Settings class that depends on pydantic."""
    if name == "Settings":
        from secgen.config.settings import Settings

        return Settings
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
