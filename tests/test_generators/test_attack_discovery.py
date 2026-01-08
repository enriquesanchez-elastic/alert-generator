"""Tests for Attack Discovery generator."""

import pytest

from secgen.generators.attack_discovery import AttackDiscoveryGenerator
from secgen.models.attack_discovery import ATTACK_DISCOVERY_TEMPLATES, AttackDiscovery


class TestAttackDiscovery:
    """Tests for AttackDiscovery model."""

    def test_create_discovery(self) -> None:
        """Test creating an AttackDiscovery instance."""
        discovery = AttackDiscovery(
            title="Test Discovery",
            alert_ids=["alert-1", "alert-2"],
            summary_markdown="Test summary",
        )

        assert discovery.title == "Test Discovery"
        assert len(discovery.alert_ids) == 2
        assert discovery.summary_markdown == "Test summary"
        assert discovery.status == "open"
        assert discovery.id  # UUID should be auto-generated

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        discovery = AttackDiscovery(
            title="Test Discovery",
            alert_ids=["alert-1"],
            risk_score=73,
        )

        data = discovery.to_dict()

        assert data["kibana.alert.attack_discovery.title"] == "Test Discovery"
        assert data["kibana.alert.attack_discovery.alert_ids"] == ["alert-1"]
        assert data["kibana.alert.attack_discovery.risk_score"] == 73
        assert "@timestamp" in data

    def test_templates_exist(self) -> None:
        """Test that templates are defined."""
        assert "brute-force" in ATTACK_DISCOVERY_TEMPLATES
        assert "c2-beacon" in ATTACK_DISCOVERY_TEMPLATES
        assert "ransomware" in ATTACK_DISCOVERY_TEMPLATES

        for name, template in ATTACK_DISCOVERY_TEMPLATES.items():
            assert "title" in template
            assert "summary_markdown" in template
            assert "details_markdown" in template
            assert "ttps" in template


class TestAttackDiscoveryGenerator:
    """Tests for AttackDiscoveryGenerator."""

    def test_init(self) -> None:
        """Test generator initialization."""
        gen = AttackDiscoveryGenerator()
        assert gen.randomizer is not None

    def test_generate_brute_force(self) -> None:
        """Test generating brute-force discovery."""
        gen = AttackDiscoveryGenerator()
        discovery = gen.generate(
            attack_pattern="brute-force",
            alert_ids=["alert-1", "alert-2", "alert-3"],
        )

        assert discovery.title == "Brute Force Attack Detected"
        assert "T1110" in discovery.mitre_attack_techniques
        assert len(discovery.alert_ids) == 3
        assert discovery.risk_score == 73

    def test_generate_c2_beacon(self) -> None:
        """Test generating c2-beacon discovery."""
        gen = AttackDiscoveryGenerator()
        discovery = gen.generate(
            attack_pattern="c2-beacon",
            alert_ids=["alert-1"],
        )

        assert "Command and Control" in discovery.title
        assert "T1071" in discovery.mitre_attack_techniques
        assert discovery.risk_score == 99

    def test_generate_unknown_pattern(self) -> None:
        """Test generating discovery for unknown pattern."""
        gen = AttackDiscoveryGenerator()
        discovery = gen.generate(
            attack_pattern="unknown-pattern",
            alert_ids=["alert-1"],
        )

        # Should still generate a valid discovery
        assert discovery.title is not None
        # Unknown pattern generates a generic title
        assert "unknown" in discovery.title.lower() or "suspicious" in discovery.title.lower()

    def test_generate_with_entities(self) -> None:
        """Test generating discovery with entity information."""
        gen = AttackDiscoveryGenerator()

        class MockHost:
            id = "host-1"
            name = "test-host"

        class MockUser:
            id = "user-1"
            name = "test-user"

        discovery = gen.generate(
            attack_pattern="lateral-movement",
            alert_ids=["alert-1"],
            hosts=[MockHost()],
            users=[MockUser()],
        )

        assert len(discovery.hosts) == 1
        assert discovery.hosts[0]["name"] == "test-host"
        assert len(discovery.users) == 1
        assert discovery.users[0]["name"] == "test-user"
        assert "test-host" in discovery.entity_summary_markdown

    def test_generate_batch(self) -> None:
        """Test batch generation."""
        gen = AttackDiscoveryGenerator()
        discoveries = gen.generate_batch(
            attack_patterns=["brute-force", "c2-beacon", "ransomware"],
            alerts_per_discovery=3,
        )

        assert len(discoveries) == 3
        assert discoveries[0].title == "Brute Force Attack Detected"
        assert discoveries[1].title == "Command and Control Beaconing Activity"
        assert discoveries[2].title == "Ransomware Activity Detected"

    def test_generate_from_alerts(self) -> None:
        """Test generating discovery from alert documents."""
        gen = AttackDiscoveryGenerator()

        alerts = [
            {
                "kibana.alert.uuid": "alert-1",
                "kibana.alert.rule.name": "Brute Force Attempt",
                "@timestamp": "2024-01-01T00:00:00Z",
                "host": {"id": "host-1", "name": "test-host"},
                "user": {"id": "user-1", "name": "test-user"},
            },
            {
                "kibana.alert.uuid": "alert-2",
                "kibana.alert.rule.name": "Failed Authentication",
                "@timestamp": "2024-01-01T00:05:00Z",
                "host": {"id": "host-1", "name": "test-host"},
            },
        ]

        discovery = gen.generate_from_alerts(alerts, attack_pattern="brute-force")

        assert len(discovery.alert_ids) == 2
        assert "alert-1" in discovery.alert_ids
        assert len(discovery.hosts) == 1
        assert len(discovery.users) == 1

