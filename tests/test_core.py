"""Tests for AlertOrchestrator."""

import json
import tempfile
from pathlib import Path

from alerts_generator.core import AlertOrchestrator


def test_initialization_with_settings_indexer_scenarios(settings, mock_indexer, multiple_scenarios):
    """Test AlertOrchestrator initialization with settings, indexer, scenarios."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    assert orchestrator.settings == settings
    assert orchestrator.indexer == mock_indexer
    assert len(orchestrator.scenarios) == len(multiple_scenarios)


def test_generate_multiple_in_dry_run_mode_generates_correct_number(
    settings, mock_indexer, multiple_scenarios
):
    """Test that generate_multiple() in dry_run mode generates correct number of alerts."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    count = 5
    results = orchestrator.generate_multiple(count=count, dry_run=True)

    assert len(results["alerts"]) == count
    # Indexer should not have been called
    mock_indexer.index_alert.assert_not_called()
    mock_indexer.index_events.assert_not_called()


def test_generate_multiple_all_alerts_have_alert_data_structure(
    settings, mock_indexer, multiple_scenarios
):
    """Test that all generated alerts have AlertData structure."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=3, dry_run=True)

    for alert_data in results["alerts"]:
        assert hasattr(alert_data, "alert_number")
        assert hasattr(alert_data, "scenario_name")
        assert hasattr(alert_data, "hostname")
        assert hasattr(alert_data, "severity")
        assert hasattr(alert_data, "detection_alert")
        assert hasattr(alert_data, "process_events")
        assert hasattr(alert_data, "endpoint_alert")


def test_generate_multiple_campaign_mode_creates_campaign(
    settings, mock_indexer, multiple_scenarios
):
    """Test that campaign mode creates campaign."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(
        count=10, dry_run=True, campaign_mode=True, campaign_hosts=5
    )

    assert results["campaign"] is not None
    assert results["campaign"].id is not None
    assert len(results["campaign"].target_hosts) == 5


def test_generate_multiple_campaign_mode_phase_distribution(
    settings, mock_indexer, multiple_scenarios
):
    """Test that campaign mode phase distribution follows expected percentages."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    count = 100
    results = orchestrator.generate_multiple(
        count=count, dry_run=True, campaign_mode=True, campaign_hosts=5
    )

    phase_counts = results["phase_counts"]
    assert phase_counts is not None

    # Check approximate distribution (10%, 30%, 40%, 20%)
    total = sum(phase_counts.values())
    assert total == count

    # Initial should be ~10%
    assert 5 <= phase_counts["initial"] <= 15  # Allow variance
    # Execution should be ~30%
    assert 20 <= phase_counts["execution"] <= 40  # Allow variance
    # Lateral should be ~40%
    assert 30 <= phase_counts["lateral"] <= 50  # Allow variance
    # Exfiltration should be ~20%
    assert 15 <= phase_counts["exfiltration"] <= 25  # Allow variance


def test_generate_multiple_campaign_mode_campaign_metadata_in_alerts(
    settings, mock_indexer, multiple_scenarios
):
    """Test that campaign metadata is in alerts."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(
        count=5, dry_run=True, campaign_mode=True, campaign_hosts=3
    )

    campaign = results["campaign"]
    for alert_data in results["alerts"]:
        assert alert_data.campaign_id == campaign.id
        assert alert_data.phase is not None


def test_generate_multiple_non_campaign_mode_random_scenario_selection(
    settings, mock_indexer, multiple_scenarios
):
    """Test that non-campaign mode uses random scenario selection."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=10, dry_run=True, campaign_mode=False)

    # Should have alerts from different scenarios
    scenario_names = [alert.scenario_name for alert in results["alerts"]]
    # With 10 alerts and 5 scenarios, should have at least 2 different scenarios
    assert len(set(scenario_names)) >= 2


def test_generate_multiple_output_file_creation(settings, mock_indexer, multiple_scenarios):
    """Test that output file creation works."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        results = orchestrator.generate_multiple(count=3, dry_run=True, output_file=temp_path)

        # File should exist
        assert Path(temp_path).exists()

        # File should contain valid JSON
        with open(temp_path) as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert len(data) == 3
    finally:
        Path(temp_path).unlink()


def test_generate_multiple_returns_correct_result_structure(
    settings, mock_indexer, multiple_scenarios
):
    """Test that generate_multiple() returns correct result structure."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=3, dry_run=True)

    assert "alerts" in results
    assert "campaign" in results
    assert "phase_counts" in results

    assert results["campaign"] is None  # Not in campaign mode
    assert results["phase_counts"] is None  # Not in campaign mode


def test_generate_multiple_with_no_scenarios_returns_empty(settings, mock_indexer):
    """Test that generate_multiple() with no scenarios returns empty."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, scenarios=[])

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    assert results["alerts"] == []
    assert results["campaign"] is None


def test_generate_multiple_time_spread_affects_timestamps(
    settings, mock_indexer, multiple_scenarios
):
    """Test that time_spread affects timestamps."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    # Generate with hours spread
    results = orchestrator.generate_multiple(
        count=3, dry_run=True, time_spread="hours", campaign_mode=False
    )

    # Timestamps should be in the past
    from datetime import datetime, timezone

    for alert_data in results["alerts"]:
        timestamp_str = alert_data.detection_alert["@timestamp"]
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        # Should be in the past
        assert timestamp < now
