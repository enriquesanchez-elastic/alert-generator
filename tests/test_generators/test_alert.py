"""Tests for AlertGenerator."""

from datetime import datetime, timedelta, timezone

from alerts_generator.generators.alert import AlertGenerator


def test_generate_returns_tuple_with_alert_dict_and_entity_ids(sample_scenario, settings):
    """Test that generate() returns tuple with alert dict and entity_ids list."""
    generator = AlertGenerator(settings)
    alert, entity_ids = generator.generate(sample_scenario)

    assert isinstance(alert, dict)
    assert isinstance(entity_ids, list)
    assert len(entity_ids) == len(sample_scenario.processes)


def test_alert_contains_required_ecs_fields(sample_scenario, settings):
    """Test that alert contains required ECS fields."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario)

    # Required ECS fields
    assert "@timestamp" in alert
    assert "agent" in alert
    assert "host" in alert
    assert "ecs" in alert
    assert "process" in alert
    assert "file" in alert
    # Event fields use dot notation, not nested dict
    assert "event.action" in alert


def test_alert_contains_kibana_alert_fields(sample_scenario, settings):
    """Test that alert contains Kibana alert fields."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario)

    # Kibana alert fields (using dot notation)
    assert "kibana.alert.risk_score" in alert
    assert "kibana.alert.severity" in alert
    assert "kibana.alert.status" in alert
    assert "kibana.alert.reason" in alert
    assert "kibana.alert.rule.rule_id" in alert


def test_entity_ids_match_number_of_processes(sample_scenario, settings):
    """Test that entity IDs match number of processes."""
    generator = AlertGenerator(settings)
    alert, entity_ids = generator.generate(sample_scenario)

    assert len(entity_ids) == len(sample_scenario.processes)
    # Entity IDs should be unique
    assert len(set(entity_ids)) == len(entity_ids)


def test_campaign_mode_uses_shared_hash_base(sample_scenario, sample_campaign, settings):
    """Test that campaign mode uses shared hash base."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario, campaign=sample_campaign)

    file_hash = alert["file"]["hash"]["md5"]
    # Hash should start with campaign base
    assert file_hash.startswith(sample_campaign.file_hash_base)


def test_non_campaign_mode_uses_unique_hashes(sample_scenario, settings):
    """Test that non-campaign mode uses unique hashes."""
    generator = AlertGenerator(settings)

    # Generate two alerts and check hashes are different
    alert1, _ = generator.generate(sample_scenario)
    alert2, _ = generator.generate(sample_scenario)

    hash1 = alert1["file"]["hash"]["md5"]
    hash2 = alert2["file"]["hash"]["md5"]

    assert hash1 != hash2


def test_timestamp_offset_is_correctly_applied(sample_scenario, settings):
    """Test that timestamp offset is correctly applied."""
    generator = AlertGenerator(settings)

    offset_minutes = 30
    alert, _ = generator.generate(sample_scenario, timestamp_offset=offset_minutes)

    # Parse timestamp
    timestamp_str = alert["@timestamp"]
    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

    # Should be approximately offset_minutes ago
    now = datetime.now(timezone.utc)
    expected_time = now - timedelta(minutes=offset_minutes)

    # Allow 1 minute tolerance for test execution time
    time_diff = abs((timestamp - expected_time).total_seconds())
    assert time_diff < 60


def test_generate_endpoint_alert_transforms_correctly(sample_scenario, settings):
    """Test that generate_endpoint_alert() transforms detection alert correctly."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario)

    endpoint_alert = generator.generate_endpoint_alert(alert)

    # Should have event.kind="alert"
    assert endpoint_alert["event"]["kind"] == "alert"
    # Should have common fields
    assert "@timestamp" in endpoint_alert
    assert "agent" in endpoint_alert
    assert "host" in endpoint_alert
    assert "file" in endpoint_alert
    assert "process" in endpoint_alert


def test_endpoint_alert_has_event_kind_alert(sample_scenario, settings):
    """Test that endpoint alert has event.kind='alert'."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario)

    endpoint_alert = generator.generate_endpoint_alert(alert)

    assert endpoint_alert["event"]["kind"] == "alert"


def test_alert_process_hierarchy_is_correct(sample_scenario, settings):
    """Test that alert process hierarchy is correctly built."""
    generator = AlertGenerator(settings)
    alert, entity_ids = generator.generate(sample_scenario)

    process = alert["process"]

    # Should have entity_id
    assert "entity_id" in process
    assert process["entity_id"] == entity_ids[-1]  # Last entity ID is the malware process

    # Should have parent
    assert "parent" in process

    # Should have session_leader
    assert "session_leader" in process
    assert "entry_leader" in process
    assert "group_leader" in process

    # Session leader should be first process
    assert process["session_leader"]["entity_id"] == entity_ids[0]


def test_alert_contains_file_hashes(sample_scenario, settings):
    """Test that alert contains file hashes."""
    generator = AlertGenerator(settings)
    alert, _ = generator.generate(sample_scenario)

    file_hash = alert["file"]["hash"]
    assert "md5" in file_hash
    assert "sha1" in file_hash
    assert "sha256" in file_hash

    # Hashes should be hex strings
    assert len(file_hash["md5"]) == 32
    assert len(file_hash["sha1"]) == 40
    assert len(file_hash["sha256"]) == 64
