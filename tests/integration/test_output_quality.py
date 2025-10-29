"""Integration tests for output quality and ECS compliance."""

import re
from datetime import datetime

from alerts_generator.core import AlertOrchestrator


def validate_ecs_fields(alert_dict):
    """Helper function to validate ECS fields."""
    required_fields = [
        "@timestamp",
        "agent",
        "host",
        "ecs",
    ]
    for field in required_fields:
        assert field in alert_dict, f"Missing required ECS field: {field}"

    # Event fields are stored with dot notation, not as nested dict
    event_fields = ["event.action", "event.category", "event.id", "event.kind"]
    for field in event_fields:
        assert field in alert_dict, f"Missing required ECS event field: {field}"


def validate_timestamp(timestamp_str):
    """Helper function to validate timestamp format."""
    try:
        datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


def validate_uuid(uuid_str):
    """Helper function to validate UUID format."""
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    )
    return uuid_pattern.match(uuid_str) is not None


def validate_ip(ip_str):
    """Helper function to validate IP format."""
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not ip_pattern.match(ip_str):
        return False
    parts = ip_str.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def validate_mac(mac_str):
    """Helper function to validate MAC format."""
    mac_pattern = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
    return mac_pattern.match(mac_str) is not None


def validate_hash(hash_str, hash_type):
    """Helper function to validate hash format."""
    length_map = {"md5": 32, "sha1": 40, "sha256": 64}
    expected_length = length_map.get(hash_type, 32)
    hex_pattern = re.compile(r"^[0-9a-f]{" + str(expected_length) + "}$", re.IGNORECASE)
    return hex_pattern.match(hash_str) is not None


def test_all_required_ecs_fields_present(settings, mock_indexer, multiple_scenarios):
    """Test that all required ECS fields are present."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        validate_ecs_fields(alert_data.detection_alert)

        # Endpoint alert should have event dict
        assert "event" in alert_data.endpoint_alert
        assert alert_data.endpoint_alert["event"]["kind"] == "alert"

        # Process events should also have ECS fields
        for event in alert_data.process_events:
            assert "@timestamp" in event
            assert "agent" in event
            assert "host" in event
            assert "ecs" in event
            assert "event" in event


def test_kibana_alert_fields_properly_formatted(settings, mock_indexer, multiple_scenarios):
    """Test that Kibana alert fields are properly formatted."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        alert = alert_data.detection_alert

        # Required Kibana fields (using dot notation)
        assert "kibana.alert.risk_score" in alert
        assert "kibana.alert.severity" in alert
        assert "kibana.alert.status" in alert
        assert "kibana.alert.rule.rule_id" in alert

        # Risk score should be integer
        assert isinstance(alert["kibana.alert.risk_score"], int)
        assert 0 <= alert["kibana.alert.risk_score"] <= 100


def test_process_events_have_valid_hierarchy(settings, mock_indexer, multiple_scenarios):
    """Test that process events have valid hierarchy."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        events = alert_data.process_events

        # Should have at least 2 processes
        assert len(events) >= 2

        # First event should be root (no parent ancestry)
        assert events[0]["process"]["Ext"]["ancestry"] == []

        # Later events should have ancestry
        for i in range(1, len(events)):
            assert len(events[i]["process"]["Ext"]["ancestry"]) > 0


def test_entity_ids_are_properly_linked(settings, mock_indexer, multiple_scenarios):
    """Test that entity IDs are properly linked."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        events = alert_data.process_events

        if len(events) > 1:
            # Parent entity ID should match previous process entity ID
            for i in range(1, len(events)):
                parent_entity_id = events[i]["process"]["parent"]["entity_id"]
                previous_entity_id = events[i - 1]["process"]["entity_id"]
                assert parent_entity_id == previous_entity_id


def test_timestamps_are_valid_iso_format(settings, mock_indexer, multiple_scenarios):
    """Test that timestamps are valid ISO format."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        # Detection alert timestamp
        assert validate_timestamp(alert_data.detection_alert["@timestamp"])

        # Endpoint alert timestamp
        assert validate_timestamp(alert_data.endpoint_alert["@timestamp"])

        # Process event timestamps
        for event in alert_data.process_events:
            assert validate_timestamp(event["@timestamp"])


def test_hash_values_are_valid_hex_strings(settings, mock_indexer, multiple_scenarios):
    """Test that hash values are valid hex strings."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        file_hash = alert_data.detection_alert["file"]["hash"]

        assert validate_hash(file_hash["md5"], "md5")
        assert validate_hash(file_hash["sha1"], "sha1")
        assert validate_hash(file_hash["sha256"], "sha256")


def test_ip_addresses_are_valid_format(settings, mock_indexer, multiple_scenarios):
    """Test that IP addresses are valid format."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        host = alert_data.detection_alert["host"]

        # Should have IP list
        assert "ip" in host
        assert isinstance(host["ip"], list)
        assert len(host["ip"]) > 0

        # Each IP should be valid
        for ip in host["ip"]:
            assert validate_ip(ip)


def test_mac_addresses_are_valid_format(settings, mock_indexer, multiple_scenarios):
    """Test that MAC addresses are valid format."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        host = alert_data.detection_alert["host"]

        # Should have MAC list
        assert "mac" in host
        assert isinstance(host["mac"], list)
        assert len(host["mac"]) > 0

        # Each MAC should be valid
        for mac in host["mac"]:
            assert validate_mac(mac)


def test_uuids_are_valid_format(settings, mock_indexer, multiple_scenarios):
    """Test that UUIDs are valid format."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        alert = alert_data.detection_alert

        # Agent ID
        assert validate_uuid(alert["agent"]["id"])

        # Host ID
        assert validate_uuid(alert["host"]["id"])

        # Event ID (stored with dot notation)
        assert validate_uuid(alert["event.id"])


def test_no_missing_required_fields(settings, mock_indexer, multiple_scenarios):
    """Test that there are no missing required fields."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        alert = alert_data.detection_alert

        # Check critical required fields
        assert "@timestamp" in alert
        assert "agent" in alert and "id" in alert["agent"]
        assert "host" in alert and "hostname" in alert["host"]
        assert "event.action" in alert  # Event fields use dot notation
        assert "process" in alert and "entity_id" in alert["process"]
        assert "file" in alert and "name" in alert["file"]


def test_data_types_are_correct(settings, mock_indexer, multiple_scenarios):
    """Test that data types are correct."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        alert = alert_data.detection_alert

        # Timestamp should be string
        assert isinstance(alert["@timestamp"], str)

        # Agent should be dict
        assert isinstance(alert["agent"], dict)

        # Host should be dict
        assert isinstance(alert["host"], dict)

        # Event fields use dot notation (not a nested dict in detection alert)
        assert "event.action" in alert
        assert isinstance(alert["event.action"], str)

        # Process should be dict
        assert isinstance(alert["process"], dict)

        # File should be dict
        assert isinstance(alert["file"], dict)

        # Process count should be integer
        assert isinstance(alert_data.process_count, int)

        # Process events should be list
        assert isinstance(alert_data.process_events, list)
