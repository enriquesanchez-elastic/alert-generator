"""Configuration management for alerts generator."""

from alerts_generator.config.loader import load_scenarios_from_file
from alerts_generator.config.settings import Settings

__all__ = ["Settings", "load_scenarios_from_file"]
