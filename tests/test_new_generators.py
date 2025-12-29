"""Tests for new generators (vulnerability, CSPM, risk score)."""

import pytest

from secgen.generators.security.vulnerability import VulnerabilityGenerator
from secgen.generators.cloud.cspm import CSPMGenerator
from secgen.generators.analytics.risk_score import RiskScoreGenerator
from secgen.models.entities.host import Host


class TestVulnerabilityGenerator:
    """Tests for VulnerabilityGenerator."""

    @pytest.fixture
    def generator(self):
        return VulnerabilityGenerator()

    @pytest.fixture
    def host(self):
        return Host.generate(template="server")

    def test_generate_basic(self, generator):
        """Should generate a basic vulnerability event."""
        event = generator.generate()

        assert event is not None
        assert "@timestamp" in event
        assert event["event"]["kind"] == "state"
        assert "vulnerability" in event["event"]["category"]
        assert "vulnerability" in event
        assert "id" in event["vulnerability"]
        assert "severity" in event["vulnerability"]

    def test_generate_with_severity(self, generator):
        """Should generate vulnerability with specified severity."""
        event = generator.generate(severity="critical")

        assert event["vulnerability"]["severity"] == "critical"
        # Critical CVEs have CVSS scores typically >= 7.0
        assert event["vulnerability"]["score"]["base"] >= 7.0

    def test_generate_with_host(self, generator, host):
        """Should include host information."""
        event = generator.generate(host=host)

        assert event["host"]["id"] == host.id
        assert event["host"]["name"] == host.name

    def test_generate_batch(self, generator, host):
        """Should generate multiple events."""
        events = generator.generate_batch(count=10, host=host)

        assert len(events) == 10
        for event in events:
            assert event["host"]["id"] == host.id

    def test_cve_database_coverage(self, generator):
        """Should have vulnerabilities across severities."""
        severities = set()
        for cve in generator.CVE_DATABASE:
            severities.add(cve["severity"])

        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities


class TestCSPMGenerator:
    """Tests for CSPMGenerator."""

    @pytest.fixture
    def generator(self):
        return CSPMGenerator()

    def test_generate_basic(self, generator):
        """Should generate a basic CSPM finding."""
        event = generator.generate()

        assert event is not None
        assert "@timestamp" in event
        assert "configuration" in event["event"]["category"]
        assert "rule" in event
        assert "cloud" in event
        assert "provider" in event["cloud"]

    def test_generate_with_provider(self, generator):
        """Should generate for specific cloud provider."""
        event = generator.generate(cloud_provider="azure")

        assert event["cloud"]["provider"] == "azure"

    def test_generate_passed_finding(self, generator):
        """Should generate passed compliance check."""
        event = generator.generate(passed=True)

        assert event["event"]["outcome"] == "success"
        assert event["result"]["evaluation"] == "passed"

    def test_generate_failed_finding(self, generator):
        """Should generate failed compliance check."""
        event = generator.generate(passed=False)

        assert event["event"]["outcome"] == "failure"
        assert event["result"]["evaluation"] == "failed"

    def test_generate_batch(self, generator):
        """Should generate multiple findings."""
        events = generator.generate_batch(count=20, cloud_provider="aws")

        assert len(events) == 20
        for event in events:
            assert event["cloud"]["provider"] == "aws"

    def test_compliance_report(self, generator):
        """Should generate complete compliance report."""
        events = generator.generate_compliance_report(cloud_provider="aws")

        assert len(events) > 0
        # Should cover all AWS rules
        rule_ids = [e["rule"]["id"] for e in events]
        assert any("cis-aws" in rid for rid in rule_ids)


class TestRiskScoreGenerator:
    """Tests for RiskScoreGenerator."""

    @pytest.fixture
    def generator(self):
        return RiskScoreGenerator()

    @pytest.fixture
    def host(self):
        return Host.generate(template="workstation")

    def test_generate_basic(self, generator):
        """Should generate a basic risk score event."""
        event = generator.generate()

        assert event is not None
        assert "@timestamp" in event
        assert event["event"]["kind"] == "enrichment"
        assert "threat" in event["event"]["category"]

    def test_generate_host_risk(self, generator, host):
        """Should generate host risk score."""
        event = generator.generate(host=host, entity_type="host")

        assert "host" in event
        assert event["host"]["id"] == host.id
        assert "risk" in event["host"]
        assert "calculated_score_norm" in event["host"]["risk"]
        assert "calculated_level" in event["host"]["risk"]

    def test_generate_user_risk(self, generator):
        """Should generate user risk score."""
        event = generator.generate(entity_type="user")

        assert "user" in event
        assert "risk" in event["user"]
        assert "calculated_score_norm" in event["user"]["risk"]

    def test_generate_with_risk_level(self, generator):
        """Should generate with specific risk level."""
        event = generator.generate(risk_level="Critical")

        # Score should be in Critical range (76-100)
        score = event.get("host", event.get("user", {}))["risk"]["calculated_score_norm"]
        assert 76 <= score <= 100

    def test_risk_inputs_generated(self, generator):
        """Should generate risk inputs."""
        event = generator.generate(risk_level="High")

        risk_data = event.get("host", event.get("user", {}))["risk"]
        assert "inputs" in risk_data
        # High risk should have some inputs
        if risk_data["inputs"]:
            assert "category" in risk_data["inputs"][0]
            assert "risk_score" in risk_data["inputs"][0]

    def test_generate_batch(self, generator, host):
        """Should generate multiple risk scores."""
        events = generator.generate_batch(
            count=10,
            host=host,
            entity_type="host"
        )

        assert len(events) == 10

