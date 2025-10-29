"""Tests for AlertData model."""

from alerts_generator.models.alert import AlertData


def test_alert_data_initialization_with_all_fields(sample_scenario):
    """Test AlertData initialization with all fields."""
    alert_dict = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test-agent"},
    }
    events = [{"event": {"id": "event1"}}]
    endpoint_alert = {"event": {"kind": "alert"}}

    alert_data = AlertData(
        alert_number=1,
        scenario_name=sample_scenario.name,
        hostname="test-host",
        severity="high",
        process_count=2,
        malware_file_name="malware",
        detection_alert=alert_dict,
        process_events=events,
        endpoint_alert=endpoint_alert,
        phase="initial",
        campaign_id="campaign-123",
        indexed=True,
        alert_id="alert-456",
    )

    assert alert_data.alert_number == 1
    assert alert_data.scenario_name == sample_scenario.name
    assert alert_data.hostname == "test-host"
    assert alert_data.severity == "high"
    assert alert_data.process_count == 2
    assert alert_data.malware_file_name == "malware"
    assert alert_data.detection_alert == alert_dict
    assert alert_data.process_events == events
    assert alert_data.endpoint_alert == endpoint_alert
    assert alert_data.phase == "initial"
    assert alert_data.campaign_id == "campaign-123"
    assert alert_data.indexed is True
    assert alert_data.alert_id == "alert-456"


def test_alert_data_initialization_without_optional_fields(sample_scenario):
    """Test AlertData initialization without optional fields."""
    alert_dict = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test-agent"},
    }
    events = [{"event": {"id": "event1"}}]
    endpoint_alert = {"event": {"kind": "alert"}}

    alert_data = AlertData(
        alert_number=1,
        scenario_name=sample_scenario.name,
        hostname="test-host",
        severity="high",
        process_count=2,
        malware_file_name="malware",
        detection_alert=alert_dict,
        process_events=events,
        endpoint_alert=endpoint_alert,
    )

    assert alert_data.phase is None
    assert alert_data.campaign_id is None
    assert alert_data.indexed is False
    assert alert_data.alert_id is None


def test_alert_data_to_dict(sample_scenario):
    """Test AlertData.to_dict() serialization."""
    alert_dict = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test-agent"},
    }
    events = [{"event": {"id": "event1"}}]
    endpoint_alert = {"event": {"kind": "alert"}}

    alert_data = AlertData(
        alert_number=1,
        scenario_name=sample_scenario.name,
        hostname="test-host",
        severity="high",
        process_count=2,
        malware_file_name="malware",
        detection_alert=alert_dict,
        process_events=events,
        endpoint_alert=endpoint_alert,
        phase="initial",
        campaign_id="campaign-123",
    )

    result = alert_data.to_dict()

    assert result["alert_number"] == 1
    assert result["scenario"] == sample_scenario.name
    assert result["hostname"] == "test-host"
    assert result["severity"] == "high"
    assert result["process_count"] == 2
    assert result["malware_file"] == "malware"
    assert result["detection_alert"] == alert_dict
    assert result["process_events"] == events
    assert result["endpoint_alert"] == endpoint_alert
    assert result["phase"] == "initial"
    assert result["campaign_id"] == "campaign-123"


def test_alert_data_to_dict_without_optional_fields(sample_scenario):
    """Test AlertData.to_dict() without optional fields."""
    alert_dict = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test-agent"},
    }
    events = [{"event": {"id": "event1"}}]
    endpoint_alert = {"event": {"kind": "alert"}}

    alert_data = AlertData(
        alert_number=1,
        scenario_name=sample_scenario.name,
        hostname="test-host",
        severity="high",
        process_count=2,
        malware_file_name="malware",
        detection_alert=alert_dict,
        process_events=events,
        endpoint_alert=endpoint_alert,
    )

    result = alert_data.to_dict()

    assert "phase" not in result
    assert "campaign_id" not in result
