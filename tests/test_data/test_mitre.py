"""Tests for MITRE ATT&CK data module."""

import pytest

from secgen.data.mitre_attack import (
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    build_threat_mapping,
    get_tactic,
    get_technique,
    get_techniques_for_tactic,
    get_ttps_for_attack_pattern,
)


class TestMitreAttackData:
    """Tests for MITRE ATT&CK data."""

    def test_tactics_exist(self) -> None:
        """Test that tactics are defined."""
        assert len(MITRE_TACTICS) > 10
        assert "TA0001" in MITRE_TACTICS  # Initial Access
        assert "TA0006" in MITRE_TACTICS  # Credential Access
        assert "TA0011" in MITRE_TACTICS  # Command and Control

    def test_techniques_exist(self) -> None:
        """Test that techniques are defined."""
        assert len(MITRE_TECHNIQUES) > 20
        assert "T1110" in MITRE_TECHNIQUES  # Brute Force
        assert "T1071" in MITRE_TECHNIQUES  # Application Layer Protocol
        assert "T1059" in MITRE_TECHNIQUES  # Command and Scripting Interpreter

    def test_get_tactic(self) -> None:
        """Test getting tactic by ID."""
        tactic = get_tactic("TA0006")

        assert tactic is not None
        assert tactic["name"] == "Credential Access"
        assert "reference" in tactic

    def test_get_tactic_not_found(self) -> None:
        """Test getting non-existent tactic."""
        tactic = get_tactic("TA9999")
        assert tactic is None

    def test_get_technique(self) -> None:
        """Test getting technique by ID."""
        technique = get_technique("T1110")

        assert technique is not None
        assert technique["name"] == "Brute Force"
        assert "TA0006" in technique["tactic_ids"]
        assert "subtechniques" in technique

    def test_get_subtechnique(self) -> None:
        """Test getting subtechnique by ID."""
        technique = get_technique("T1110.001")

        assert technique is not None
        assert technique["name"] == "Password Guessing"
        assert technique["parent_id"] == "T1110"

    def test_get_technique_not_found(self) -> None:
        """Test getting non-existent technique."""
        technique = get_technique("T9999")
        assert technique is None

    def test_get_techniques_for_tactic(self) -> None:
        """Test getting techniques for a tactic."""
        techniques = get_techniques_for_tactic("TA0006")

        assert len(techniques) > 0
        assert any(t["id"] == "T1110" for t in techniques)

    def test_build_threat_mapping_single_technique(self) -> None:
        """Test building threat mapping for single technique."""
        mapping = build_threat_mapping(["T1110"])

        assert len(mapping) > 0
        assert mapping[0]["framework"] == "MITRE ATT&CK"
        assert mapping[0]["tactic"]["id"] == "TA0006"
        assert mapping[0]["tactic"]["name"] == "Credential Access"
        assert any(t["id"] == "T1110" for t in mapping[0]["technique"])

    def test_build_threat_mapping_with_subtechnique(self) -> None:
        """Test building threat mapping with subtechnique."""
        mapping = build_threat_mapping(["T1110", "T1110.001"])

        assert len(mapping) > 0
        # Should have subtechnique info
        for entry in mapping:
            for technique in entry["technique"]:
                if technique["id"] == "T1110":
                    assert "subtechnique" in technique

    def test_build_threat_mapping_multiple_tactics(self) -> None:
        """Test building threat mapping with techniques from multiple tactics."""
        mapping = build_threat_mapping(["T1110", "T1071"])

        # Should have entries for different tactics
        tactic_ids = [entry["tactic"]["id"] for entry in mapping]
        assert "TA0006" in tactic_ids  # Credential Access
        assert "TA0011" in tactic_ids  # Command and Control

    def test_get_ttps_for_attack_pattern(self) -> None:
        """Test getting TTPs for attack pattern."""
        ttps = get_ttps_for_attack_pattern("brute-force")

        assert "T1110" in ttps
        assert "T1110.001" in ttps

    def test_get_ttps_for_unknown_pattern(self) -> None:
        """Test getting TTPs for unknown pattern."""
        ttps = get_ttps_for_attack_pattern("unknown-pattern")
        assert ttps == []


class TestDetectionRules:
    """Tests for detection rule data."""

    def test_rules_exist(self) -> None:
        """Test that rules are defined."""
        from secgen.data.detection_rules import DETECTION_RULES

        assert len(DETECTION_RULES) > 0
        assert "brute_force_attempt" in DETECTION_RULES
        assert "ssh_brute_force" in DETECTION_RULES

    def test_get_rule(self) -> None:
        """Test getting a rule."""
        from secgen.data.detection_rules import get_rule

        rule = get_rule("brute_force_attempt")

        assert rule is not None
        assert rule["name"] == "Attempts to Brute Force a Microsoft 365 User Account"
        assert "T1110" in rule["ttps"]

    def test_get_rule_with_threat_mapping(self) -> None:
        """Test getting rule with threat mapping."""
        from secgen.data.detection_rules import get_rule_with_threat_mapping

        rule = get_rule_with_threat_mapping("brute_force_attempt")

        assert rule is not None
        assert "threat" in rule
        assert len(rule["threat"]) > 0
        assert rule["threat"][0]["framework"] == "MITRE ATT&CK"

    def test_get_rule_for_attack_pattern(self) -> None:
        """Test getting rule for attack pattern."""
        from secgen.data.detection_rules import get_rule_for_attack_pattern

        rule = get_rule_for_attack_pattern("brute-force")

        assert rule is not None
        assert "brute" in rule["name"].lower()

    def test_build_kibana_rule_fields(self) -> None:
        """Test building Kibana rule fields."""
        from secgen.data.detection_rules import build_kibana_rule_fields

        fields = build_kibana_rule_fields("brute_force_attempt")

        assert "kibana.alert.rule.name" in fields
        assert "kibana.alert.rule.severity" in fields
        assert "kibana.alert.rule.threat" in fields
        assert len(fields["kibana.alert.rule.threat"]) > 0

