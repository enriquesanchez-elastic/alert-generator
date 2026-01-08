"""Data modules for MITRE ATT&CK, detection rules, and case templates."""

from secgen.data.detection_rules import (
    ATTACK_PATTERN_RULES,
    DETECTION_RULES,
    build_kibana_rule_fields,
    get_rule,
    get_rule_for_attack_pattern,
    get_rule_with_threat_mapping,
    get_rules_by_severity,
    get_rules_by_ttp,
)
from secgen.data.mitre_attack import (
    ATTACK_PATTERN_TTPS,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    build_threat_mapping,
    get_tactic,
    get_technique,
    get_techniques_for_tactic,
    get_ttps_for_attack_pattern,
)

__all__ = [
    # MITRE ATT&CK
    "MITRE_TACTICS",
    "MITRE_TECHNIQUES",
    "ATTACK_PATTERN_TTPS",
    "build_threat_mapping",
    "get_tactic",
    "get_technique",
    "get_techniques_for_tactic",
    "get_ttps_for_attack_pattern",
    # Detection Rules
    "DETECTION_RULES",
    "ATTACK_PATTERN_RULES",
    "get_rule",
    "get_rule_with_threat_mapping",
    "get_rules_by_severity",
    "get_rules_by_ttp",
    "build_kibana_rule_fields",
    "get_rule_for_attack_pattern",
]

