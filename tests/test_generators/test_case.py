"""Tests for Case generator."""

import pytest

from secgen.generators.case import CaseGenerator
from secgen.models.attack_discovery import AttackDiscovery
from secgen.models.case import CASE_TEMPLATES, SecurityCase


class TestSecurityCase:
    """Tests for SecurityCase model."""

    def test_create_case(self) -> None:
        """Test creating a SecurityCase instance."""
        case = SecurityCase(
            title="Test Case",
            description="Test description",
            severity="high",
            tags=["test", "investigation"],
        )

        assert case.title == "Test Case"
        assert case.description == "Test description"
        assert case.severity == "high"
        assert case.status == "open"
        assert case.id  # UUID should be auto-generated

    def test_add_comment(self) -> None:
        """Test adding a comment to a case."""
        case = SecurityCase(title="Test Case")
        comment = case.add_comment("Test comment", created_by="analyst")

        assert len(case.comments) == 1
        assert case.comments[0].comment == "Test comment"
        assert case.comments[0].created_by == "analyst"
        assert case.total_comments == 1

    def test_attach_alert(self) -> None:
        """Test attaching an alert to a case."""
        case = SecurityCase(title="Test Case")
        attachment = case.attach_alert(
            alert_id="alert-123",
            rule_name="Test Rule",
        )

        assert len(case.alerts) == 1
        assert case.alerts[0].alert_id == "alert-123"
        assert case.total_alerts == 1

    def test_link_attack_discovery(self) -> None:
        """Test linking attack discovery to a case."""
        case = SecurityCase(title="Test Case")
        case.link_attack_discovery("discovery-123")

        assert "discovery-123" in case.attack_discovery_ids

    def test_close_case(self) -> None:
        """Test closing a case."""
        case = SecurityCase(title="Test Case")
        case.close(closed_by="analyst")

        assert case.status == "closed"
        assert case.closed_by == "analyst"
        assert case.closed_at is not None

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        case = SecurityCase(
            title="Test Case",
            severity="critical",
            tags=["incident"],
        )

        data = case.to_dict()

        assert data["title"] == "Test Case"
        assert data["severity"] == "critical"
        assert data["tags"] == ["incident"]
        assert data["status"] == "open"

    def test_templates_exist(self) -> None:
        """Test that templates are defined."""
        assert "brute-force-investigation" in CASE_TEMPLATES
        assert "malware-incident" in CASE_TEMPLATES
        assert "ransomware-incident" in CASE_TEMPLATES

        for name, template in CASE_TEMPLATES.items():
            assert "title" in template
            assert "description" in template
            assert "tags" in template
            assert "severity" in template


class TestCaseGenerator:
    """Tests for CaseGenerator."""

    def test_init(self) -> None:
        """Test generator initialization."""
        gen = CaseGenerator()
        assert gen.randomizer is not None

    def test_generate_with_template(self) -> None:
        """Test generating case with template."""
        gen = CaseGenerator()
        # Pass severity=None to use template's severity
        case = gen.generate(template="brute-force-investigation", severity=None)

        assert case.title == "Brute Force Attack Investigation"
        assert "brute-force" in case.tags
        assert case.severity == "high"
        assert len(case.comments) >= 1  # Should have initial comments

    def test_generate_with_custom_title(self) -> None:
        """Test generating case with custom title."""
        gen = CaseGenerator()
        case = gen.generate(
            template="brute-force-investigation",
            title="Custom Title",
        )

        assert case.title == "Custom Title"

    def test_generate_with_alerts(self) -> None:
        """Test generating case with alert attachments."""
        gen = CaseGenerator()
        case = gen.generate(
            template="malware-incident",
            alert_ids=["alert-1", "alert-2", "alert-3"],
        )

        assert case.total_alerts == 3

    def test_generate_with_discovery_link(self) -> None:
        """Test generating case with attack discovery link."""
        gen = CaseGenerator()
        case = gen.generate(
            template="c2-investigation",
            attack_discovery_ids=["discovery-1"],
        )

        assert "discovery-1" in case.attack_discovery_ids

    def test_generate_from_alerts(self) -> None:
        """Test generating case from alert documents."""
        gen = CaseGenerator()

        alerts = [
            {
                "kibana.alert.uuid": "alert-1",
                "kibana.alert.rule.name": "Malware Detection",
                "kibana.alert.severity": "critical",
                "kibana.alert.rule.tags": ["malware", "endpoint"],
                "host": {"name": "test-host"},
                "user": {"name": "test-user"},
            },
            {
                "kibana.alert.uuid": "alert-2",
                "kibana.alert.rule.name": "Malware Execution",
                "kibana.alert.severity": "high",
                "kibana.alert.rule.tags": ["malware"],
                "host": {"name": "test-host"},
            },
        ]

        case = gen.generate_from_alerts(alerts, attack_pattern="malware-drop")

        assert case.total_alerts == 2
        assert case.severity == "critical"  # Highest severity from alerts
        assert "malware-drop" in case.tags

    def test_generate_from_attack_discovery(self) -> None:
        """Test generating case from attack discovery."""
        gen = CaseGenerator()

        discovery = AttackDiscovery(
            id="discovery-1",
            title="Brute Force Attack Detected",
            alert_ids=["alert-1", "alert-2"],
            summary_markdown="Multiple failed login attempts detected",
            risk_score=73,
            mitre_attack_tactics=["TA0006"],
        )

        case = gen.generate_from_attack_discovery(discovery)

        assert "discovery-1" in case.attack_discovery_ids
        assert case.total_alerts == 2
        assert case.severity == "high"  # Based on risk score 73
        assert len(case.comments) >= 2  # Summary + entity summary

    def test_generate_batch(self) -> None:
        """Test batch generation."""
        gen = CaseGenerator()
        cases = gen.generate_batch(count=3, alerts_per_case=5)

        assert len(cases) == 3
        for case in cases:
            assert case.total_alerts == 5

    def test_investigation_workflow(self) -> None:
        """Test simulating investigation workflow."""
        gen = CaseGenerator()
        case = gen.generate(template="brute-force-investigation")

        initial_comments = len(case.comments)

        case = gen.generate_investigation_workflow(case, analyst="analyst1")

        # Should have more comments after workflow
        assert len(case.comments) > initial_comments
        # Status should be in-progress (workflow simulation)
        assert case.status == "in-progress"

