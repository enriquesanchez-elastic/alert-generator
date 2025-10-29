"""
Alerts Generator - A Pythonic tool for generating security alerts for Elasticsearch/Kibana.

This package provides a modular, extensible framework for generating realistic
security alerts with support for campaigns, time distribution, and custom scenarios.
"""

__version__ = "2.0.0"

from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario

__all__ = [
    "Campaign",
    "Scenario",
    "ProcessInfo",
    "MalwareFile",
]
