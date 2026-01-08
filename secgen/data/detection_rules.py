"""Detection rule templates for generating realistic alerts with MITRE mapping."""

from typing import Any

from secgen.data.mitre_attack import build_threat_mapping

# Detection rule templates matching Elastic Security prebuilt rules
DETECTION_RULES: dict[str, dict[str, Any]] = {
    "brute_force_attempt": {
        "rule_id": "e08cbe6c-7c3a-4c8d-ae98-f1fb0c123d67",
        "name": "Attempts to Brute Force a Microsoft 365 User Account",
        "description": "Identifies potential brute force attempts against Microsoft 365 user accounts by detecting multiple failed authentication attempts followed by a successful authentication.",
        "risk_score": 73,
        "severity": "high",
        "type": "threshold",
        "query": "event.dataset:o365.audit and event.provider:AzureActiveDirectory and event.category:authentication and event.action:UserLoginFailed",
        "threshold": {"field": "user.name", "value": 10},
        "ttps": ["T1110", "T1110.001", "T1110.003"],
        "tags": ["Elastic", "Cloud", "Microsoft 365", "Credential Access"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "ssh_brute_force": {
        "rule_id": "8e7da54d-eb19-47a8-8b89-6c2de0e7a7c0",
        "name": "SSH Brute Force Attempt",
        "description": "Identifies potential SSH brute force attempts by detecting multiple failed authentication attempts from the same source IP.",
        "risk_score": 47,
        "severity": "medium",
        "type": "threshold",
        "query": "event.category:authentication and event.outcome:failure and process.name:sshd",
        "threshold": {"field": "source.ip", "value": 20},
        "ttps": ["T1110", "T1110.001", "T1021.004"],
        "tags": ["Elastic", "Linux", "Credential Access", "Initial Access"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "malware_execution": {
        "rule_id": "6b25c5d1-fb6d-4c7a-8e9b-5c0a1d7f8e9a",
        "name": "Malware - Detected - Elastic Endpoint Security",
        "description": "Elastic Endpoint Security detected malware on the system.",
        "risk_score": 99,
        "severity": "critical",
        "type": "query",
        "query": "event.kind:alert and event.module:endpoint and event.category:malware",
        "ttps": ["T1204", "T1204.002"],
        "tags": ["Elastic", "Endpoint Security", "Malware"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "suspicious_powershell": {
        "rule_id": "a1234567-89ab-cdef-0123-456789abcdef",
        "name": "Suspicious PowerShell Execution",
        "description": "Identifies PowerShell execution with suspicious command line arguments commonly used by attackers.",
        "risk_score": 73,
        "severity": "high",
        "type": "eql",
        "query": 'process where process.name : "powershell.exe" and process.args : ("-enc*", "-exec bypass*", "IEX*", "Invoke-*")',
        "ttps": ["T1059", "T1059.001"],
        "tags": ["Elastic", "Windows", "Execution"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "c2_beacon": {
        "rule_id": "b2345678-90bc-def1-2345-67890abcdef1",
        "name": "Potential C2 Beaconing Activity",
        "description": "Identifies potential command and control beaconing by detecting regular interval connections to the same destination.",
        "risk_score": 73,
        "severity": "high",
        "type": "threshold",
        "query": "event.category:network and destination.port:(443 or 8443 or 8080)",
        "threshold": {"field": "destination.ip", "value": 10},
        "ttps": ["T1071", "T1071.001", "T1573"],
        "tags": ["Elastic", "Network", "Command and Control"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "dga_activity": {
        "rule_id": "c3456789-01cd-ef23-4567-890abcdef234",
        "name": "Potential DGA Activity",
        "description": "Identifies potential Domain Generation Algorithm activity by detecting high entropy DNS queries with high NXDOMAIN rates.",
        "risk_score": 73,
        "severity": "high",
        "type": "threshold",
        "query": "event.category:network and dns.response_code:NXDOMAIN",
        "threshold": {"field": "host.id", "value": 50},
        "ttps": ["T1568", "T1568.002"],
        "tags": ["Elastic", "Network", "Command and Control"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "registry_persistence": {
        "rule_id": "d4567890-12de-f345-6789-0abcdef34567",
        "name": "Registry Run Key Persistence",
        "description": "Identifies the creation or modification of registry run keys, which are commonly used for persistence.",
        "risk_score": 47,
        "severity": "medium",
        "type": "eql",
        "query": 'registry where registry.path : ("*\\\\Run\\\\*", "*\\\\RunOnce\\\\*")',
        "ttps": ["T1547", "T1547.001"],
        "tags": ["Elastic", "Windows", "Persistence"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "lateral_movement_rdp": {
        "rule_id": "e5678901-23ef-0456-7890-1bcdef456789",
        "name": "Remote Desktop Protocol from the Internet",
        "description": "Identifies RDP connections from external IP addresses, which may indicate lateral movement or unauthorized access.",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": "event.category:network and destination.port:3389 and not source.ip:(10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)",
        "ttps": ["T1021", "T1021.001"],
        "tags": ["Elastic", "Network", "Lateral Movement"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "credential_dumping": {
        "rule_id": "f6789012-34f0-1567-8901-2cdef5678901",
        "name": "Credential Dumping - LSASS Memory",
        "description": "Identifies potential LSASS memory access, which is commonly used for credential dumping.",
        "risk_score": 73,
        "severity": "high",
        "type": "eql",
        "query": 'process where process.name : ("mimikatz.exe", "procdump.exe") or (process.name : "rundll32.exe" and process.args : "*lsass*")',
        "ttps": ["T1003", "T1003.001"],
        "tags": ["Elastic", "Windows", "Credential Access"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "data_exfiltration": {
        "rule_id": "07890123-4501-2678-9012-3def67890123",
        "name": "Potential Data Exfiltration via HTTP",
        "description": "Identifies large outbound HTTP POST requests that may indicate data exfiltration.",
        "risk_score": 47,
        "severity": "medium",
        "type": "threshold",
        "query": "event.category:network and http.request.method:POST and http.request.bytes > 1000000",
        "threshold": {"field": "destination.ip", "value": 5},
        "ttps": ["T1041", "T1048"],
        "tags": ["Elastic", "Network", "Exfiltration"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "ransomware_behavior": {
        "rule_id": "18901234-5612-3789-0123-4ef789012345",
        "name": "Ransomware - Detected - Elastic Endpoint Security",
        "description": "Elastic Endpoint Security detected ransomware behavior on the system.",
        "risk_score": 99,
        "severity": "critical",
        "type": "query",
        "query": "event.kind:alert and event.module:endpoint and rule.name:*ransomware*",
        "ttps": ["T1486", "T1490"],
        "tags": ["Elastic", "Endpoint Security", "Ransomware", "Impact"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "webshell_detection": {
        "rule_id": "29012345-6723-4890-1234-5f0890123456",
        "name": "Web Shell Detection",
        "description": "Identifies potential web shell activity by detecting suspicious process spawned by web server processes.",
        "risk_score": 73,
        "severity": "high",
        "type": "eql",
        "query": 'process where process.parent.name : ("httpd", "nginx", "apache2", "w3wp.exe") and process.name : ("cmd.exe", "powershell.exe", "bash", "sh")',
        "ttps": ["T1505", "T1505.003"],
        "tags": ["Elastic", "Linux", "Windows", "Persistence"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "privilege_escalation_sudo": {
        "rule_id": "30123456-7834-5901-2345-601901234567",
        "name": "Sudo Command Execution",
        "description": "Identifies sudo command execution, which may indicate privilege escalation attempts.",
        "risk_score": 21,
        "severity": "low",
        "type": "query",
        "query": "event.category:process and process.name:sudo",
        "ttps": ["T1548", "T1548.003"],
        "tags": ["Elastic", "Linux", "Privilege Escalation"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "scheduled_task_creation": {
        "rule_id": "41234567-8945-6012-3456-712012345678",
        "name": "Scheduled Task Created via schtasks",
        "description": "Identifies scheduled task creation via schtasks.exe, which is commonly used for persistence.",
        "risk_score": 47,
        "severity": "medium",
        "type": "eql",
        "query": 'process where process.name : "schtasks.exe" and process.args : "/create"',
        "ttps": ["T1053", "T1053.005"],
        "tags": ["Elastic", "Windows", "Persistence"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
    "phishing_attachment": {
        "rule_id": "52345678-9056-7123-4567-823123456789",
        "name": "Suspicious Email Attachment Execution",
        "description": "Identifies execution of files from email attachment locations.",
        "risk_score": 73,
        "severity": "high",
        "type": "eql",
        "query": 'process where process.executable : "*\\\\Content.Outlook\\\\*" or process.executable : "*\\\\Temporary Internet Files\\\\*"',
        "ttps": ["T1566", "T1566.001", "T1204.002"],
        "tags": ["Elastic", "Windows", "Initial Access"],
        "author": ["Elastic"],
        "license": "Elastic License v2",
    },
}


def get_rule(rule_name: str) -> dict[str, Any] | None:
    """
    Get a detection rule by name.

    Args:
        rule_name: Rule name (e.g., "brute_force_attempt")

    Returns:
        Rule dictionary or None if not found
    """
    return DETECTION_RULES.get(rule_name)


def get_rule_with_threat_mapping(rule_name: str) -> dict[str, Any] | None:
    """
    Get a detection rule with full MITRE threat mapping.

    Args:
        rule_name: Rule name (e.g., "brute_force_attempt")

    Returns:
        Rule dictionary with threat array or None if not found
    """
    rule = get_rule(rule_name)
    if not rule:
        return None

    # Build threat mapping from TTPs
    threat_mapping = build_threat_mapping(rule.get("ttps", []))

    return {
        **rule,
        "threat": threat_mapping,
    }


def get_rules_by_severity(severity: str) -> list[dict[str, Any]]:
    """
    Get all rules matching a severity level.

    Args:
        severity: Severity level (low, medium, high, critical)

    Returns:
        List of rule dictionaries
    """
    return [
        {"name": name, **rule}
        for name, rule in DETECTION_RULES.items()
        if rule.get("severity") == severity
    ]


def get_rules_by_ttp(ttp: str) -> list[dict[str, Any]]:
    """
    Get all rules that detect a specific TTP.

    Args:
        ttp: MITRE technique ID (e.g., "T1110")

    Returns:
        List of rule dictionaries
    """
    return [
        {"name": name, **rule}
        for name, rule in DETECTION_RULES.items()
        if ttp in rule.get("ttps", [])
    ]


def build_kibana_rule_fields(
    rule_name: str,
    rule_uuid: str | None = None,
) -> dict[str, Any]:
    """
    Build the kibana.alert.rule.* fields for an alert.

    Args:
        rule_name: Detection rule name
        rule_uuid: Optional rule UUID (generated if not provided)

    Returns:
        Dictionary of kibana.alert.rule.* fields
    """
    import uuid

    rule = get_rule_with_threat_mapping(rule_name)
    if not rule:
        # Return default rule fields
        return {
            "kibana.alert.rule.name": "Unknown Rule",
            "kibana.alert.rule.risk_score": 50,
            "kibana.alert.rule.severity": "medium",
            "kibana.alert.rule.threat": [],
        }

    rule_uuid = rule_uuid or str(uuid.uuid4())

    severity_mapping = [
        {"field": "event.severity", "operator": "equals", "severity": "low", "value": "21"},
        {"field": "event.severity", "operator": "equals", "severity": "medium", "value": "47"},
        {"field": "event.severity", "operator": "equals", "severity": "high", "value": "73"},
        {"field": "event.severity", "operator": "equals", "severity": "critical", "value": "99"},
    ]

    return {
        "kibana.alert.rule.actions": [],
        "kibana.alert.rule.author": rule.get("author", ["Elastic"]),
        "kibana.alert.rule.category": f"{rule.get('type', 'query').title()} Rule",
        "kibana.alert.rule.consumer": "siem",
        "kibana.alert.rule.created_at": "2024-01-01T00:00:00.000Z",
        "kibana.alert.rule.created_by": "elastic",
        "kibana.alert.rule.description": rule.get("description", ""),
        "kibana.alert.rule.enabled": True,
        "kibana.alert.rule.exceptions_list": [],
        "kibana.alert.rule.execution.uuid": str(uuid.uuid4()),
        "kibana.alert.rule.false_positives": [],
        "kibana.alert.rule.from": "now-10m",
        "kibana.alert.rule.immutable": False,
        "kibana.alert.rule.indices": ["logs-*", "auditbeat-*", "packetbeat-*", "filebeat-*"],
        "kibana.alert.rule.interval": "5m",
        "kibana.alert.rule.license": rule.get("license", "Elastic License v2"),
        "kibana.alert.rule.max_signals": 100,
        "kibana.alert.rule.name": rule.get("name", ""),
        "kibana.alert.rule.producer": "siem",
        "kibana.alert.rule.references": [],
        "kibana.alert.rule.risk_score": rule.get("risk_score", 50),
        "kibana.alert.rule.risk_score_mapping": [
            {"field": "event.risk_score", "operator": "equals", "value": ""}
        ],
        "kibana.alert.rule.rule_id": rule.get("rule_id", rule_uuid),
        "kibana.alert.rule.rule_type_id": f"siem.{rule.get('type', 'query')}Rule",
        "kibana.alert.rule.severity": rule.get("severity", "medium"),
        "kibana.alert.rule.severity_mapping": severity_mapping,
        "kibana.alert.rule.tags": rule.get("tags", []),
        "kibana.alert.rule.threat": rule.get("threat", []),
        "kibana.alert.rule.to": "now",
        "kibana.alert.rule.type": rule.get("type", "query"),
        "kibana.alert.rule.updated_at": "2024-01-01T00:00:00.000Z",
        "kibana.alert.rule.updated_by": "elastic",
        "kibana.alert.rule.uuid": rule_uuid,
        "kibana.alert.rule.version": 1,
    }


# Mapping from attack patterns to appropriate detection rules
ATTACK_PATTERN_RULES: dict[str, str] = {
    "brute-force": "brute_force_attempt",
    "ssh-brute-force": "ssh_brute_force",
    "auditbeat-brute-force": "ssh_brute_force",
    "filebeat-ssh-brute-force": "ssh_brute_force",
    "malware-drop": "malware_execution",
    "c2-beacon": "c2_beacon",
    "packetbeat-c2-beacon": "c2_beacon",
    "dga": "dga_activity",
    "packetbeat-dga": "dga_activity",
    "registry-persistence": "registry_persistence",
    "lateral-movement": "lateral_movement_rdp",
    "credential-dump": "credential_dumping",
    "data-exfiltration": "data_exfiltration",
    "ransomware": "ransomware_behavior",
    "webshell": "webshell_detection",
    "scheduled-task": "scheduled_task_creation",
    "phishing": "phishing_attachment",
    "auditbeat-suspicious-process": "suspicious_powershell",
    "filebeat-web-attack": "webshell_detection",
}


def get_rule_for_attack_pattern(pattern_name: str) -> dict[str, Any] | None:
    """
    Get the appropriate detection rule for an attack pattern.

    Args:
        pattern_name: Attack pattern name

    Returns:
        Rule dictionary with threat mapping or None
    """
    rule_name = ATTACK_PATTERN_RULES.get(pattern_name)
    if rule_name:
        return get_rule_with_threat_mapping(rule_name)
    return None

