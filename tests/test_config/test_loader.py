"""Tests for scenario loader."""

import tempfile
from pathlib import Path

from alerts_generator.config.loader import load_scenarios_from_file


def test_load_scenarios_from_file_with_valid_yaml():
    """Test load_scenarios_from_file() with valid YAML."""
    yaml_content = """
scenarios:
  - name: "Test Attack"
    description: "A test attack"
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
        assert scenarios[0].name == "Test Attack"
        assert scenarios[0].severity == "high"
        assert len(scenarios[0].processes) == 2
    finally:
        Path(temp_path).unlink()


def test_load_scenarios_handles_missing_file():
    """Test that load_scenarios_from_file() handles missing file gracefully."""
    scenarios = load_scenarios_from_file("/nonexistent/path/scenarios.yaml")
    assert scenarios is None


def test_load_scenarios_handles_invalid_yaml():
    """Test that load_scenarios_from_file() handles invalid YAML format."""
    yaml_content = "invalid: yaml: content: ["

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        scenarios = load_scenarios_from_file(temp_path)
        # Should return None or raise exception
        assert scenarios is None or scenarios == []
    finally:
        Path(temp_path).unlink()


def test_load_scenarios_handles_missing_required_fields():
    """Test that load_scenarios_from_file() handles missing required fields."""
    yaml_content = """
scenarios:
  - name: "Test Attack"
    # Missing severity, processes, malware_file
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        scenarios = load_scenarios_from_file(temp_path)
        # Should return None due to validation error
        assert scenarios is None
    finally:
        Path(temp_path).unlink()


def test_load_scenarios_handles_invalid_scenario_data():
    """Test that load_scenarios_from_file() handles invalid scenario data."""
    yaml_content = """
scenarios:
  - name: "Test Attack"
    description: "Test"
    severity: "invalid_severity"
    processes:
      - name: "init"
        executable: "/sbin/init"
        args: ["/sbin/init"]
        working_dir: "/"
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
        # Should return None due to validation error
        assert scenarios is None
    finally:
        Path(temp_path).unlink()


def test_load_scenarios_multiple_scenarios():
    """Test that load_scenarios_from_file() loads multiple scenarios."""
    yaml_content = """
scenarios:
  - name: "Attack 1"
    description: "First attack"
    severity: "high"
    processes:
      - name: "init"
        executable: "/sbin/init"
        args: ["/sbin/init"]
        working_dir: "/"
        user: "root"
      - name: "malware1"
        executable: "/tmp/malware1"
        args: ["/tmp/malware1"]
        working_dir: "/tmp"
        user: "root"
    malware_file:
      name: "malware1"
      path: "/tmp/malware1"
      extension: ""
  - name: "Attack 2"
    description: "Second attack"
    severity: "medium"
    processes:
      - name: "init"
        executable: "/sbin/init"
        args: ["/sbin/init"]
        working_dir: "/"
        user: "root"
      - name: "malware2"
        executable: "/tmp/malware2"
        args: ["/tmp/malware2"]
        working_dir: "/tmp"
        user: "root"
    malware_file:
      name: "malware2"
      path: "/tmp/malware2"
      extension: ""
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        scenarios = load_scenarios_from_file(temp_path)
        assert scenarios is not None
        assert len(scenarios) == 2
        assert scenarios[0].name == "Attack 1"
        assert scenarios[1].name == "Attack 2"
    finally:
        Path(temp_path).unlink()


def test_load_scenarios_with_single_process_raises_error():
    """Test that load_scenarios_from_file() handles scenario with single process."""
    yaml_content = """
scenarios:
  - name: "Test Attack"
    description: "Test"
    severity: "high"
    processes:
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
        # Should return None due to validation error (must have at least 2 processes)
        assert scenarios is None
    finally:
        Path(temp_path).unlink()
