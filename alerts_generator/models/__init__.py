"""Data models for alerts generator."""

from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario

__all__ = ["Campaign", "Scenario", "ProcessInfo", "MalwareFile"]
