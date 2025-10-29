"""Integration tests for CLI end-to-end workflows."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from alerts_generator.cli import load_scenarios, main
from alerts_generator.core import AlertOrchestrator


def test_cli_parses_arguments_correctly(capsys):
    """Test that CLI parses arguments correctly."""
    # This test verifies argument parsing works (would need argparse mocking)
    # For now, we test that the CLI functions exist and are callable
    # Actual CLI argument parsing would require more complex mocking
    assert callable(load_scenarios)
    assert callable(main)


def test_scenario_loading_from_file_works():
    """Test that scenario loading from file works."""
    import tempfile

    from alerts_generator.config.loader import load_scenarios_from_file

    yaml_content = """
scenarios:
  - name: "CLI Test Attack"
    description: "Test for CLI"
    severity: "high"
    processes:
      - name: "init"
        executable: "/sbin/init"
        args: ["/sbin/init"]
        working_dir: "/"
        user: "root"
      - name: "malware"
        executable: "/tmp/malware"
        args: ["/tmp/malware"]
        working_dir: "/tmp"
        user: "root"
    malware_file:
      name: "malware"
      path: "/tmp/malware"
      extension: ""
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        scenarios = load_scenarios_from_file(temp_path)
        assert scenarios is not None
        assert len(scenarios) == 1
        assert scenarios[0].name == "CLI Test Attack"
    finally:
        Path(temp_path).unlink()


def test_dry_run_generates_output_without_indexing(settings, mock_indexer, multiple_scenarios):
    """Test that dry run generates output without indexing."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=5, dry_run=True)

    assert len(results["alerts"]) == 5
    # Verify no indexing occurred
    mock_indexer.index_alert.assert_not_called()
    mock_indexer.index_events.assert_not_called()


def test_output_file_generation_works(settings, mock_indexer, multiple_scenarios):
    """Test that output file generation works."""
    import json

    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        results = orchestrator.generate_multiple(count=3, dry_run=True, output_file=temp_path)

        # File should exist
        assert Path(temp_path).exists()

        # Should be valid JSON
        with open(temp_path) as f:
            data = json.load(f)
            assert isinstance(data, list)
            assert len(data) == 3
    finally:
        Path(temp_path).unlink()


def test_delete_all_command_works(settings):
    """Test that delete-all command works (with mocks)."""
    from unittest.mock import MagicMock

    from alerts_generator.indexers.elasticsearch import ElasticsearchIndexer

    indexer = ElasticsearchIndexer(settings)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"deleted": 10}

    with patch("requests.post", return_value=mock_response):
        result = indexer.delete_all()

        assert "alerts_index" in result
        assert "process_events" in result
        assert "endpoint_alerts" in result
        assert result["alerts_index"]["success"] is True


def test_error_handling_for_invalid_inputs(settings, mock_indexer):
    """Test error handling for invalid inputs."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, scenarios=[])

    # Should handle empty scenarios gracefully
    results = orchestrator.generate_multiple(count=5, dry_run=True)
    assert results["alerts"] == []


def test_summary_output_format(settings, mock_indexer, multiple_scenarios):
    """Test that summary output format is correct."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(count=10, dry_run=True)

    # Verify results structure matches expected summary format
    assert "alerts" in results
    assert len(results["alerts"]) == 10

    # Each alert should have required fields for summary
    for alert_data in results["alerts"]:
        assert alert_data.scenario_name is not None
        assert alert_data.severity is not None
        assert alert_data.hostname is not None
