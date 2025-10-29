"""Integration tests for full alert generation pipeline."""

from alerts_generator.core import AlertOrchestrator


def test_complete_alert_generation_pipeline(settings, mock_indexer, multiple_scenarios):
    """Test complete alert generation pipeline."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    count = 10
    results = orchestrator.generate_multiple(count=count, dry_run=True)

    # Verify structure
    assert "alerts" in results
    assert len(results["alerts"]) == count


def test_output_structure_matches_expectations(settings, mock_indexer, multiple_scenarios):
    """Test that output structure matches expectations."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        # Each alert should have detection_alert, process_events, endpoint_alert
        assert alert_data.detection_alert is not None
        assert alert_data.process_events is not None
        assert isinstance(alert_data.process_events, list)
        assert alert_data.endpoint_alert is not None


def test_all_generated_alerts_have_required_fields(settings, mock_indexer, multiple_scenarios):
    """Test that all generated alerts have required fields."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    for alert_data in results["alerts"]:
        # Alert data fields
        assert alert_data.alert_number > 0
        assert alert_data.scenario_name is not None
        assert alert_data.hostname is not None
        assert alert_data.severity is not None
        assert alert_data.process_count > 0
        assert alert_data.malware_file_name is not None

        # Detection alert required fields (event fields use dot notation)
        alert = alert_data.detection_alert
        assert "@timestamp" in alert
        assert "agent" in alert
        assert "host" in alert
        assert "event.action" in alert  # Event fields are flat with dots
        assert "process" in alert
        assert "file" in alert


def test_dry_run_generates_output_without_indexing(settings, mock_indexer, multiple_scenarios):
    """Test that dry_run generates output without indexing."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    assert len(results["alerts"]) == 5

    # Indexer should not have been called
    mock_indexer.index_alert.assert_not_called()
    mock_indexer.index_events.assert_not_called()


def test_output_file_generation(settings, mock_indexer, multiple_scenarios):
    """Test output file generation."""
    import json
    import tempfile
    from pathlib import Path

    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        results = orchestrator.generate_multiple(count=3, dry_run=True, output_file=temp_path)

        # File should exist and be valid JSON
        assert Path(temp_path).exists()

        with open(temp_path) as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert len(data) == 3

            # Each item should be a valid alert dict
            for item in data:
                assert "scenario" in item
                assert "hostname" in item
                assert "detection_alert" in item
                assert "process_events" in item
    finally:
        Path(temp_path).unlink()
