"""Tests for ProcessEventGenerator."""

from datetime import datetime, timedelta, timezone

from alerts_generator.generators.process import ProcessEventGenerator


def test_generate_returns_list_with_correct_number_of_events(sample_scenario):
    """Test that generate() returns list with correct number of events."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    assert isinstance(events, list)
    assert len(events) == len(sample_scenario.processes)


def test_process_hierarchy_matches_scenario_processes(sample_scenario):
    """Test that process hierarchy matches scenario processes."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2", "id3"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    # Each event should correspond to a scenario process
    for i, event in enumerate(events):
        process = event["process"]
        scenario_process = sample_scenario.processes[i]

        assert process["name"] == scenario_process.name
        assert process["executable"] == scenario_process.executable
        assert process["entity_id"] == entity_ids[i]


def test_entity_ids_properly_linked(sample_scenario):
    """Test that entity IDs are properly linked (parent, session_leader, entry_leader)."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2", "id3"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    # First event (root) should have no parent ancestry
    root_event = events[0]
    assert root_event["process"]["Ext"]["ancestry"] == []

    # Second event should have first event in ancestry
    second_event = events[1]
    assert entity_ids[0] in second_event["process"]["Ext"]["ancestry"]

    # All events should share same session_leader
    session_leader_id = entity_ids[0]
    for event in events:
        assert event["process"]["session_leader"]["entity_id"] == session_leader_id
        assert event["process"]["entry_leader"]["entity_id"] == session_leader_id
        assert event["process"]["group_leader"]["entity_id"] == session_leader_id


def test_ancestry_array_built_correctly(sample_scenario):
    """Test that ancestry array is built correctly."""
    generator = ProcessEventGenerator()

    # Create a scenario with at least 3 processes for this test
    from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario

    multi_process_scenario = Scenario(
        name="Multi Process Test",
        description="Test with multiple processes",
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
                name="bash",
                executable="/bin/bash",
                args=["/bin/bash"],
                working_dir="/tmp",
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

    entity_ids = ["id1", "id2", "id3"]
    events = generator.generate(multi_process_scenario, entity_ids, "test-host", "test-agent")

    # For third event (index 2), ancestry should have id2 and id1 in reverse order
    if len(events) >= 3:
        third_event = events[2]
        ancestry = third_event["process"]["Ext"]["ancestry"]
        # Ancestry should be [id2, id1] in reverse order of entity_ids up to current
        expected_ancestry = entity_ids[1::-1]  # [id2, id1]
        assert ancestry == expected_ancestry


def test_timestamps_are_sequential(sample_scenario):
    """Test that timestamps are sequential."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2", "id3"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    timestamps = [event["@timestamp"] for event in events]
    # All timestamps should be the same (within same generation)
    assert len(set(timestamps)) == 1

    # Process start times should be sequential (parent before child)
    starts = [event["process"]["start"] for event in events]
    # Earlier processes should have earlier start times
    for i in range(1, len(starts)):
        assert starts[i] >= starts[i - 1]


def test_process_events_contain_required_ecs_fields(sample_scenario):
    """Test that process events contain required ECS fields."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    for event in events:
        # Required ECS fields
        assert "@timestamp" in event
        assert "agent" in event
        assert "ecs" in event
        assert "event" in event
        assert "process" in event
        assert "host" in event
        assert "data_stream" in event

        # Process-specific required fields
        process = event["process"]
        assert "entity_id" in process
        assert "pid" in process
        assert "name" in process
        assert "executable" in process
        assert "command_line" in process
        assert "args" in process
        assert "working_directory" in process


def test_process_event_user_info_matches_scenario(sample_scenario):
    """Test that process event user info matches scenario."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2"]
    events = generator.generate(sample_scenario, entity_ids, "test-host", "test-agent")

    for i, event in enumerate(events):
        scenario_process = sample_scenario.processes[i]
        process = event["process"]

        assert process["user"]["name"] == scenario_process.user
        assert "user" in event
        assert event["user"]["name"] == scenario_process.user


def test_process_event_hostname_matches_input(sample_scenario):
    """Test that process event hostname matches input."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2"]
    hostname = "custom-host"
    events = generator.generate(sample_scenario, entity_ids, hostname, "test-agent")

    for event in events:
        assert event["host"]["hostname"] == hostname
        assert event["host"]["name"] == hostname


def test_timestamp_offset_applied_to_process_events(sample_scenario):
    """Test that timestamp offset is applied to process events."""
    generator = ProcessEventGenerator()
    entity_ids = ["id1", "id2"]
    offset_minutes = 60

    events = generator.generate(
        sample_scenario, entity_ids, "test-host", "test-agent", timestamp_offset=offset_minutes
    )

    now = datetime.now(timezone.utc)
    for event in events:
        timestamp_str = event["@timestamp"]
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        expected_time = now - timedelta(minutes=offset_minutes)

        # Allow tolerance for execution time
        time_diff = abs((timestamp - expected_time).total_seconds())
        assert time_diff < 60
