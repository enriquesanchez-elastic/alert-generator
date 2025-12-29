"""Tests for LLM generators."""

import tempfile
from unittest.mock import MagicMock, patch

import pytest

from secgen.llm.cache import ArtifactCache


class MockGeminiClient:
    """Mock Gemini client for testing."""

    def __init__(self):
        self.responses = {}
        self.calls = []

    def set_json_response(self, response: dict):
        """Set the response for generate_json calls."""
        self.responses["json"] = response

    def set_yaml_response(self, response: dict):
        """Set the response for generate_yaml calls."""
        self.responses["yaml"] = response

    def generate_json(self, prompt, **kwargs):
        """Mock generate_json."""
        self.calls.append(("json", prompt, kwargs))
        return self.responses.get("json", {})

    def generate_yaml(self, prompt, **kwargs):
        """Mock generate_yaml."""
        self.calls.append(("yaml", prompt, kwargs))
        return self.responses.get("yaml", {})


class TestCommandLibraryGenerator:
    """Tests for CommandLibraryGenerator."""

    @pytest.fixture
    def temp_cache(self):
        """Create temporary cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ArtifactCache(base_dir=tmpdir, enabled=True)

    @pytest.fixture
    def mock_client(self):
        """Create mock client."""
        return MockGeminiClient()

    def test_generate_returns_commands(self, mock_client, temp_cache):
        """Test that generate returns command library."""
        from secgen.llm.generators.commands import CommandLibraryGenerator

        mock_client.set_json_response({
            "commands": {
                "wmi": ["Invoke-WmiMethod -ComputerName {target}"],
                "psremoting": ["Invoke-Command -ComputerName {target}"],
            }
        })

        generator = CommandLibraryGenerator(client=mock_client, cache=temp_cache)
        result = generator.generate(tactic="lateral_movement", count=10)

        assert "commands" in result
        assert "wmi" in result["commands"]
        assert result["tactic"] == "lateral_movement"

    def test_generate_or_load_uses_cache(self, mock_client, temp_cache):
        """Test that generate_or_load uses cache."""
        from secgen.llm.generators.commands import CommandLibraryGenerator

        mock_client.set_json_response({"commands": {"test": ["cmd1"]}})

        generator = CommandLibraryGenerator(client=mock_client, cache=temp_cache)

        # First call should generate
        result1 = generator.generate_or_load(tactic="execution")
        assert len(mock_client.calls) == 1

        # Second call should use cache
        result2 = generator.generate_or_load(tactic="execution")
        assert len(mock_client.calls) == 1  # No new call

        assert result1["commands"] == result2["commands"]

    def test_force_regenerate_bypasses_cache(self, mock_client, temp_cache):
        """Test that force_regenerate bypasses cache."""
        from secgen.llm.generators.commands import CommandLibraryGenerator

        mock_client.set_json_response({"commands": {"test": ["cmd1"]}})

        generator = CommandLibraryGenerator(client=mock_client, cache=temp_cache)

        generator.generate_or_load(tactic="execution")
        generator.generate_or_load(tactic="execution", force_regenerate=True)

        assert len(mock_client.calls) == 2

    def test_list_tactics(self):
        """Test list_tactics static method."""
        from secgen.llm.generators.commands import CommandLibraryGenerator

        tactics = CommandLibraryGenerator.list_tactics()
        assert "execution" in tactics
        assert "lateral_movement" in tactics
        assert "discovery" in tactics

    def test_get_random_command(self, mock_client, temp_cache):
        """Test getting random command from library."""
        from secgen.llm.generators.commands import CommandLibraryGenerator

        mock_client.set_json_response({
            "commands": {
                "wmi": ["cmd1", "cmd2", "cmd3"],
            }
        })

        generator = CommandLibraryGenerator(client=mock_client, cache=temp_cache)
        cmd = generator.get_random_command(tactic="lateral_movement")

        assert cmd in ["cmd1", "cmd2", "cmd3"]


class TestScenarioVariationGenerator:
    """Tests for ScenarioVariationGenerator."""

    @pytest.fixture
    def temp_cache(self):
        """Create temporary cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ArtifactCache(base_dir=tmpdir, enabled=True)

    @pytest.fixture
    def mock_client(self):
        """Create mock client."""
        return MockGeminiClient()

    def test_generate_returns_scenarios(self, mock_client, temp_cache):
        """Test that generate returns scenario variations."""
        from secgen.llm.generators.scenarios import ScenarioVariationGenerator

        mock_client.set_yaml_response({
            "scenarios": [
                {
                    "name": "Ransomware via RDP",
                    "severity": "critical",
                    "processes": [
                        {"name": "svchost.exe", "executable": "C:\\Windows\\svchost.exe"},
                        {"name": "malware.exe", "executable": "C:\\Temp\\malware.exe"},
                    ],
                    "malware_file": {"name": "malware.exe", "path": "C:\\Temp", "extension": ".exe"},
                }
            ]
        })

        generator = ScenarioVariationGenerator(client=mock_client, cache=temp_cache)
        result = generator.generate(base_name="Ransomware", variation_count=1)

        assert "scenarios" in result
        assert len(result["scenarios"]) == 1
        assert result["scenarios"][0]["name"] == "Ransomware via RDP"

    def test_convert_to_scenario_objects(self, mock_client, temp_cache):
        """Test converting variation data to Scenario objects."""
        from secgen.llm.generators.scenarios import ScenarioVariationGenerator

        generator = ScenarioVariationGenerator(client=mock_client, cache=temp_cache)

        data = {
            "scenarios": [
                {
                    "name": "Test Scenario",
                    "description": "Test description",
                    "severity": "high",
                    "processes": [
                        {"name": "proc1.exe", "executable": "/path/1", "args": [], "working_dir": "/", "user": "root"},
                        {"name": "proc2.exe", "executable": "/path/2", "args": [], "working_dir": "/", "user": "root"},
                    ],
                    "malware_file": {"name": "mal.exe", "path": "/tmp/mal.exe", "extension": ".exe"},
                }
            ]
        }

        scenarios = generator.convert_to_scenario_objects(data)

        assert len(scenarios) == 1
        assert scenarios[0].name == "Test Scenario"
        assert len(scenarios[0].processes) == 2


class TestEntityProfileGenerator:
    """Tests for EntityProfileGenerator."""

    @pytest.fixture
    def temp_cache(self):
        """Create temporary cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ArtifactCache(base_dir=tmpdir, enabled=True)

    @pytest.fixture
    def mock_client(self):
        """Create mock client."""
        return MockGeminiClient()

    def test_generate_returns_personas(self, mock_client, temp_cache):
        """Test that generate returns personas."""
        from secgen.llm.generators.profiles import EntityProfileGenerator

        mock_client.set_yaml_response({
            "personas": [
                {
                    "role": "Software Engineer",
                    "department": "Engineering",
                    "username_pattern": "{firstname}.{lastname}",
                    "typical_behavior": {
                        "applications": ["vscode.exe", "git.exe"],
                        "working_hours": "9am-6pm weekdays",
                    },
                    "anomaly_indicators": [
                        {"indicator": "mimikatz.exe", "severity": "critical"},
                    ],
                    "privilege_level": "standard",
                }
            ]
        })

        generator = EntityProfileGenerator(client=mock_client, cache=temp_cache)
        result = generator.generate(industry="technology", role_count=1)

        assert "personas" in result
        assert len(result["personas"]) == 1
        assert result["personas"][0]["role"] == "Software Engineer"

    def test_generate_user_from_persona(self, mock_client, temp_cache):
        """Test generating user from persona template."""
        from secgen.llm.generators.profiles import EntityProfileGenerator

        generator = EntityProfileGenerator(client=mock_client, cache=temp_cache)

        persona = {
            "role": "Admin",
            "department": "IT",
            "username_pattern": "{firstname}.{lastname}",
            "typical_behavior": {"applications": ["app.exe"]},
            "privilege_level": "admin",
        }

        user = generator.generate_user_from_persona(
            persona, first_name="John", last_name="Doe"
        )

        assert user["username"] == "john.doe"
        assert user["first_name"] == "John"
        assert user["role"] == "Admin"

    def test_list_industries(self):
        """Test list_industries static method."""
        from secgen.llm.generators.profiles import EntityProfileGenerator

        industries = EntityProfileGenerator.list_industries()
        assert "healthcare" in industries
        assert "finance" in industries
        assert "technology" in industries


class TestCampaignNarrativeGenerator:
    """Tests for CampaignNarrativeGenerator."""

    @pytest.fixture
    def temp_cache(self):
        """Create temporary cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield ArtifactCache(base_dir=tmpdir, enabled=True)

    @pytest.fixture
    def mock_client(self):
        """Create mock client."""
        return MockGeminiClient()

    def test_generate_returns_campaign(self, mock_client, temp_cache):
        """Test that generate returns campaign narrative."""
        from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

        mock_client.set_yaml_response({
            "campaign": {
                "name": "Operation Test",
                "threat_actor": "APT29",
                "phases": [
                    {
                        "day": 1,
                        "name": "initial_access",
                        "ttp": "T1566.001",
                        "description": "Phishing",
                    }
                ],
                "infrastructure": {
                    "c2_domains": ["test.evil.com"],
                    "malware_family": "TestMalware",
                },
            }
        })

        generator = CampaignNarrativeGenerator(client=mock_client, cache=temp_cache)
        result = generator.generate(threat_actor="APT29", dwell_time_days=7)

        assert "campaign" in result
        assert result["campaign"]["name"] == "Operation Test"
        assert len(result["campaign"]["phases"]) == 1

    def test_get_phases(self, mock_client, temp_cache):
        """Test getting phases from campaign."""
        from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

        mock_client.set_yaml_response({
            "campaign": {
                "name": "Test",
                "phases": [
                    {"day": 1, "name": "phase1"},
                    {"day": 3, "name": "phase2"},
                ],
            }
        })

        generator = CampaignNarrativeGenerator(client=mock_client, cache=temp_cache)
        phases = generator.get_phases()

        assert len(phases) == 2
        assert phases[0]["name"] == "phase1"

    def test_get_indicators(self, mock_client, temp_cache):
        """Test getting indicators from campaign."""
        from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

        mock_client.set_yaml_response({
            "campaign": {
                "name": "Test",
                "phases": [
                    {
                        "day": 1,
                        "name": "phase1",
                        "indicators": [
                            {"type": "ip", "value": "1.2.3.4"},
                        ],
                    }
                ],
                "infrastructure": {
                    "c2_domains": ["evil.com"],
                    "c2_ips": ["5.6.7.8"],
                },
            }
        })

        generator = CampaignNarrativeGenerator(client=mock_client, cache=temp_cache)
        indicators = generator.get_indicators()

        assert len(indicators) >= 3  # From phase and infrastructure

    def test_list_threat_actors(self):
        """Test list_threat_actors static method."""
        from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

        actors = CampaignNarrativeGenerator.list_threat_actors()
        assert "APT29" in actors
        assert "FIN7" in actors

    def test_list_objectives(self):
        """Test list_objectives static method."""
        from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

        objectives = CampaignNarrativeGenerator.list_objectives()
        assert "data_theft" in objectives
        assert "ransomware" in objectives

