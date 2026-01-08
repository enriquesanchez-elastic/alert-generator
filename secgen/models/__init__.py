"""Data models for alerts generator."""

from secgen.models.attack_discovery import AttackDiscovery
from secgen.models.campaign import Campaign
from secgen.models.case import (
    CaseAlertAttachment,
    CaseComment,
    CaseConnector,
    SecurityCase,
)

# Import entities from submodule
from secgen.models.entities import Host, OSInfo, ProcessNode, ProcessTree, User
from secgen.models.scenario import (
    AttackPhase,
    EnvironmentConfig,
    EventTemplate,
    MalwareFile,
    MultiEventScenario,
    PhaseCorrelation,
    ProcessInfo,
    Scenario,
)

__all__ = [
    # Legacy
    "Campaign",
    "Scenario",
    "ProcessInfo",
    "MalwareFile",
    # Multi-event scenarios
    "AttackPhase",
    "EnvironmentConfig",
    "EventTemplate",
    "MultiEventScenario",
    "PhaseCorrelation",
    # Entities
    "Host",
    "OSInfo",
    "User",
    "ProcessNode",
    "ProcessTree",
    # Attack Discovery
    "AttackDiscovery",
    # Case Management
    "SecurityCase",
    "CaseComment",
    "CaseConnector",
    "CaseAlertAttachment",
]
