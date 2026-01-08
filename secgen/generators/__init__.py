"""Alert and event generators.

This module provides generators for various security event types.

Core generators (require settings/pydantic):
- AlertGenerator: Detection rule alerts
- ProcessEventGenerator: Process execution events
- CampaignGenerator: Attack campaign generation

Standalone generators (no external dependencies):
- RandomDataGenerator: Random data utilities
- FileEventGenerator: File system events
- RegistryEventGenerator: Windows registry events
- EndpointNetworkEventGenerator: Process-linked network events
- DNSEventGenerator: DNS transaction events
- NetworkFlowGenerator: Network flow events
- HTTPEventGenerator: HTTP transaction events
- TLSEventGenerator: TLS/SSL events
- AuthenticationEventGenerator: Authentication events
- IAMEventGenerator: Identity management events
- AWSCloudTrailGenerator: AWS audit logs
- AzureAuditGenerator: Azure audit logs
- GCPAuditGenerator: GCP audit logs
- ThreatIndicatorGenerator: Threat intelligence indicators
"""

# Only import RandomDataGenerator by default (no external dependencies)
from secgen.generators.randomizers import RandomDataGenerator

__all__ = [
    "RandomDataGenerator",
]


def __getattr__(name: str):
    """Lazy import of generators that depend on pydantic/settings."""
    if name == "AlertGenerator":
        from secgen.generators.alert import AlertGenerator

        return AlertGenerator
    elif name == "CampaignGenerator":
        from secgen.generators.campaign import CampaignGenerator

        return CampaignGenerator
    elif name == "ProcessEventGenerator":
        from secgen.generators.process import ProcessEventGenerator

        return ProcessEventGenerator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
