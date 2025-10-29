"""Tests for Scenario model."""

import pytest

from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario


def test_scenario_creation_succeeds(sample_scenario):
    """Test that valid scenario creation works."""
    assert sample_scenario.name == "Test Attack"
    assert sample_scenario.description == "A test attack scenario"
    assert sample_scenario.severity == "high"
    assert len(sample_scenario.processes) == 2
    assert sample_scenario.malware_file.name == "malware"


def test_scenario_empty_name_raises_value_error():
    """Test that empty name raises ValueError."""
    with pytest.raises(ValueError, match="Scenario name cannot be empty"):
        Scenario(
            name="",
            description="Test",
            severity="high",
            processes=[
                ProcessInfo(
                    name="init",
                    executable="/sbin/init",
                    args=["/sbin/init"],
                    working_dir="/",
                    user="root",
                ),
                ProcessInfo(
                    name="malware",
                    executable="/tmp/malware",
                    args=["/tmp/malware"],
                    working_dir="/tmp",
                    user="root",
                ),
            ],
            malware_file=MalwareFile(name="malware", path="/tmp/malware", extension=""),
        )


def test_scenario_empty_processes_raises_value_error():
    """Test that empty processes list raises ValueError."""
    with pytest.raises(ValueError, match="Scenario must have at least one process"):
        Scenario(
            name="Test",
            description="Test",
            severity="high",
            processes=[],
            malware_file=MalwareFile(name="malware", path="/tmp/malware", extension=""),
        )


def test_scenario_single_process_raises_value_error():
    """Test that less than 2 processes raises ValueError."""
    with pytest.raises(ValueError, match="Scenario must have at least 2 processes"):
        Scenario(
            name="Test",
            description="Test",
            severity="high",
            processes=[
                ProcessInfo(
                    name="malware",
                    executable="/tmp/malware",
                    args=["/tmp/malware"],
                    working_dir="/tmp",
                    user="root",
                ),
            ],
            malware_file=MalwareFile(name="malware", path="/tmp/malware", extension=""),
        )


def test_scenario_invalid_severity_raises_value_error():
    """Test that invalid severity raises ValueError."""
    with pytest.raises(
        ValueError,
        match="Invalid severity.*Must be one of: low, medium, high, critical",
    ):
        Scenario(
            name="Test",
            description="Test",
            severity="invalid",
            processes=[
                ProcessInfo(
                    name="init",
                    executable="/sbin/init",
                    args=["/sbin/init"],
                    working_dir="/",
                    user="root",
                ),
                ProcessInfo(
                    name="malware",
                    executable="/tmp/malware",
                    args=["/tmp/malware"],
                    working_dir="/tmp",
                    user="root",
                ),
            ],
            malware_file=MalwareFile(name="malware", path="/tmp/malware", extension=""),
        )


def test_scenario_all_valid_severities():
    """Test that all valid severities work."""
    valid_severities = ["low", "medium", "high", "critical"]
    for severity in valid_severities:
        scenario = Scenario(
            name="Test",
            description="Test",
            severity=severity,
            processes=[
                ProcessInfo(
                    name="init",
                    executable="/sbin/init",
                    args=["/sbin/init"],
                    working_dir="/",
                    user="root",
                ),
                ProcessInfo(
                    name="malware",
                    executable="/tmp/malware",
                    args=["/tmp/malware"],
                    working_dir="/tmp",
                    user="root",
                ),
            ],
            malware_file=MalwareFile(name="malware", path="/tmp/malware", extension=""),
        )
        assert scenario.severity == severity


def test_process_info_dataclass():
    """Test ProcessInfo dataclass behavior."""
    process = ProcessInfo(
        name="test",
        executable="/bin/test",
        args=["test", "arg"],
        working_dir="/tmp",
        user="root",
    )
    assert process.name == "test"
    assert process.executable == "/bin/test"
    assert process.args == ["test", "arg"]
    assert process.working_dir == "/tmp"
    assert process.user == "root"


def test_malware_file_dataclass():
    """Test MalwareFile dataclass behavior."""
    malware = MalwareFile(name="test.exe", path="/tmp/test.exe", extension=".exe")
    assert malware.name == "test.exe"
    assert malware.path == "/tmp/test.exe"
    assert malware.extension == ".exe"
