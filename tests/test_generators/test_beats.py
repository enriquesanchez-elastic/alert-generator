"""Tests for Beat generators."""

import pytest

from secgen.generators.beats import (
    AuditbeatEventGenerator,
    FilebeatEventGenerator,
    PacketbeatEventGenerator,
)


class TestAuditbeatEventGenerator:
    """Tests for Auditbeat event generator."""

    def test_init(self) -> None:
        """Test generator initialization."""
        gen = AuditbeatEventGenerator()
        assert gen.randomizer is not None

    def test_generate_auditd_event(self) -> None:
        """Test generating auditd event."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="auditd")

        assert "@timestamp" in event
        assert event["agent"]["type"] == "auditbeat"
        assert event["event"]["module"] == "auditd"
        assert "auditd" in event

    def test_generate_auditd_event_with_syscall(self) -> None:
        """Test generating auditd syscall event."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="auditd")

        # The syscall is stored in auditd.data.syscall
        assert "auditd" in event
        assert "data" in event["auditd"]
        assert "syscall" in event["auditd"]["data"]

    def test_generate_process_event(self) -> None:
        """Test generating auditbeat process event."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="system.process")

        assert "@timestamp" in event
        assert event["event"]["module"] == "system"
        assert event["event"]["dataset"] == "system.process"
        assert "process" in event

    def test_generate_login_event(self) -> None:
        """Test generating auditbeat login event."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="system.login")

        assert event["event"]["module"] == "system"
        assert event["event"]["dataset"] == "system.login"
        assert "user" in event

    def test_generate_fim_event(self) -> None:
        """Test generating file integrity event."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="file_integrity")

        assert event["event"]["module"] == "file_integrity"
        assert "file" in event

    def test_generate_batch(self) -> None:
        """Test batch generation."""
        gen = AuditbeatEventGenerator()
        events = gen.generate_batch(count=5, dataset="auditd")

        assert len(events) == 5
        for event in events:
            assert event["event"]["module"] == "auditd"

    def test_generate_malicious_events(self) -> None:
        """Test generating malicious events."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="auditd", is_malicious=True)

        assert "auditd" in event


class TestPacketbeatEventGenerator:
    """Tests for Packetbeat event generator."""

    def test_init(self) -> None:
        """Test generator initialization."""
        gen = PacketbeatEventGenerator()
        assert gen.randomizer is not None

    def test_generate_dns_event(self) -> None:
        """Test generating DNS event."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(dataset="dns")

        assert "@timestamp" in event
        assert event["agent"]["type"] == "packetbeat"
        assert event["network"]["protocol"] == "dns"
        assert "dns" in event

    def test_generate_dns_event_with_domain(self) -> None:
        """Test generating DNS event with specific domain."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(
            dataset="dns",
            domain="malware.example.com",
            query_type="A",
        )

        assert event["dns"]["question"]["name"] == "malware.example.com"
        assert event["dns"]["question"]["type"] == "A"

    def test_generate_http_event(self) -> None:
        """Test generating HTTP event."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(dataset="http")

        assert event["network"]["protocol"] == "http"
        assert "http" in event
        assert "request" in event["http"]
        assert "response" in event["http"]

    def test_generate_http_event_with_params(self) -> None:
        """Test generating HTTP event with specific params."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(
            dataset="http",
            method="POST",
            path="/api/login",
        )

        assert event["http"]["request"]["method"] == "POST"
        assert event["url"]["path"] == "/api/login"
        assert "status_code" in event["http"]["response"]

    def test_generate_tls_event(self) -> None:
        """Test generating TLS event."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(dataset="tls")

        assert event["network"]["protocol"] == "tls"
        assert "tls" in event

    def test_generate_flow_event(self) -> None:
        """Test generating flow event."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(dataset="flow")

        assert "source" in event
        assert "destination" in event
        assert "network" in event

    def test_generate_batch(self) -> None:
        """Test batch generation."""
        gen = PacketbeatEventGenerator()
        events = gen.generate_batch(count=5, dataset="dns")

        assert len(events) == 5
        for event in events:
            assert event["network"]["protocol"] == "dns"


class TestFilebeatEventGenerator:
    """Tests for Filebeat event generator."""

    def test_init(self) -> None:
        """Test generator initialization."""
        gen = FilebeatEventGenerator()
        assert gen.randomizer is not None

    def test_generate_syslog_event(self) -> None:
        """Test generating syslog event."""
        gen = FilebeatEventGenerator()
        event = gen.generate(dataset="system.syslog")

        assert "@timestamp" in event
        assert event["agent"]["type"] == "filebeat"
        assert event["event"]["module"] == "system"
        assert "message" in event

    def test_generate_syslog_event_with_malicious(self) -> None:
        """Test generating malicious syslog event."""
        gen = FilebeatEventGenerator()
        event = gen.generate(
            dataset="system.syslog",
            is_malicious=True,
        )

        # Malicious events have more severe syslog severity
        assert event["log"]["syslog"]["severity"]["name"] in ["err", "crit", "alert", "warning"]
        assert "message" in event
        assert "process" in event

    def test_generate_auth_event(self) -> None:
        """Test generating auth event."""
        gen = FilebeatEventGenerator()
        event = gen.generate(dataset="system.auth")

        assert event["event"]["module"] == "system"
        assert event["event"]["dataset"] == "system.auth"
        assert "user" in event

    def test_generate_auth_event_malicious(self) -> None:
        """Test generating malicious auth event."""
        gen = FilebeatEventGenerator()
        event = gen.generate(
            dataset="system.auth",
            is_malicious=True,
        )

        # Malicious auth events mostly fail (90% chance)
        assert event["event"]["outcome"] in ["failure", "success"]
        assert "user" in event
        assert event["event"]["dataset"] == "system.auth"

    def test_generate_nginx_access_event(self) -> None:
        """Test generating nginx access log event."""
        gen = FilebeatEventGenerator()
        event = gen.generate(dataset="nginx.access")

        assert event["event"]["module"] == "nginx"
        assert event["event"]["dataset"] == "nginx.access"
        assert "http" in event
        assert "url" in event

    def test_generate_batch(self) -> None:
        """Test batch generation."""
        gen = FilebeatEventGenerator()
        events = gen.generate_batch(count=5, dataset="system.syslog")

        assert len(events) == 5
        for event in events:
            assert event["event"]["module"] == "system"


class TestBeatEventECSCompliance:
    """Tests for ECS compliance in Beat events."""

    def test_auditbeat_ecs_fields(self) -> None:
        """Test ECS compliance of auditbeat events."""
        gen = AuditbeatEventGenerator()
        event = gen.generate(dataset="auditd")

        # Required ECS fields
        assert "ecs" in event
        assert "version" in event["ecs"]
        assert "agent" in event
        assert "host" in event
        assert "event" in event
        assert "@timestamp" in event

    def test_packetbeat_ecs_fields(self) -> None:
        """Test ECS compliance of packetbeat events."""
        gen = PacketbeatEventGenerator()
        event = gen.generate(dataset="dns")

        # Required ECS fields
        assert "ecs" in event
        assert "agent" in event
        assert "host" in event
        assert "event" in event
        assert "network" in event
        assert "@timestamp" in event

    def test_filebeat_ecs_fields(self) -> None:
        """Test ECS compliance of filebeat events."""
        gen = FilebeatEventGenerator()
        event = gen.generate(dataset="system.syslog")

        # Required ECS fields
        assert "ecs" in event
        assert "agent" in event
        assert "host" in event
        assert "event" in event
        assert "@timestamp" in event
