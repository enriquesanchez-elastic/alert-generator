"""Bootstrap module to initialize the generator registry.

This module imports all generators to trigger their decorators,
populating the registry with event types and attack patterns.
It uses lazy initialization to avoid import overhead when not needed.
"""

import logging

logger = logging.getLogger(__name__)

_bootstrapped = False


def bootstrap_registry() -> None:
    """
    Import all generators to trigger decorator registration.

    This function should be called once before using registry discovery features.
    It's safe to call multiple times (will only bootstrap once).
    """
    global _bootstrapped
    if _bootstrapped:
        return

    logger.debug("Bootstrapping generator registry...")

    # Import all generator modules to trigger decorators
    # Each import will register event types and attack patterns

    # Endpoint generators
    from secgen.generators.endpoint import (  # noqa: F401
        EndpointNetworkEventGenerator,
        FileEventGenerator,
        RegistryEventGenerator,
    )

    # Network generators
    from secgen.generators.network import (  # noqa: F401
        DNSEventGenerator,
        HTTPEventGenerator,
        NetworkFlowGenerator,
        TLSEventGenerator,
    )

    # Identity generators
    from secgen.generators.identity import (  # noqa: F401
        AuthenticationEventGenerator,
        IAMEventGenerator,
    )

    # Cloud generators
    from secgen.generators.cloud import (  # noqa: F401
        AWSCloudTrailGenerator,
        AzureAuditGenerator,
        GCPAuditGenerator,
    )

    # Threat intel generators
    from secgen.generators.threat_intel import ThreatIndicatorGenerator  # noqa: F401

    # Core generators
    from secgen.generators.process import ProcessEventGenerator  # noqa: F401
    from secgen.generators.alert import AlertGenerator  # noqa: F401

    # Security generators
    from secgen.generators.security import VulnerabilityGenerator  # noqa: F401

    # Cloud CSPM generator
    from secgen.generators.cloud.cspm import CSPMGenerator  # noqa: F401

    # Analytics generators
    from secgen.generators.analytics import RiskScoreGenerator  # noqa: F401

    # Finalize attack pattern registration for all generator classes
    from secgen.registry import finalize_attack_patterns

    # Finalize attack patterns for each generator class
    finalize_attack_patterns(FileEventGenerator)
    finalize_attack_patterns(RegistryEventGenerator)
    finalize_attack_patterns(EndpointNetworkEventGenerator)
    finalize_attack_patterns(DNSEventGenerator)
    finalize_attack_patterns(HTTPEventGenerator)
    finalize_attack_patterns(NetworkFlowGenerator)
    finalize_attack_patterns(TLSEventGenerator)
    finalize_attack_patterns(AuthenticationEventGenerator)
    finalize_attack_patterns(IAMEventGenerator)
    finalize_attack_patterns(AWSCloudTrailGenerator)
    finalize_attack_patterns(AzureAuditGenerator)
    finalize_attack_patterns(GCPAuditGenerator)
    finalize_attack_patterns(ThreatIndicatorGenerator)
    finalize_attack_patterns(ProcessEventGenerator)
    finalize_attack_patterns(AlertGenerator)
    finalize_attack_patterns(VulnerabilityGenerator)
    finalize_attack_patterns(CSPMGenerator)
    finalize_attack_patterns(RiskScoreGenerator)

    _bootstrapped = True
    logger.debug("Generator registry bootstrap complete")


def ensure_bootstrapped() -> None:
    """Ensure registry is bootstrapped before use."""
    if not _bootstrapped:
        bootstrap_registry()

