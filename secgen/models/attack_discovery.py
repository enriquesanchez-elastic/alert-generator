"""Attack Discovery model and data structures."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class AttackDiscovery:
    """
    Model for Elastic Security Attack Discovery documents.

    Attack Discovery uses AI to analyze alerts and identify attack patterns,
    providing a narrative summary of the attack and affected entities.

    Attributes:
        id: Unique discovery ID
        title: Human-readable attack title
        alert_ids: List of alert UUIDs that are part of this discovery
        timestamp: When the discovery was created
        details_markdown: Detailed attack description in markdown
        summary_markdown: Brief summary in markdown
        entity_summary_markdown: Summary of affected entities
        mitre_attack_tactics: List of MITRE ATT&CK tactic IDs
        mitre_attack_techniques: List of MITRE ATT&CK technique IDs
        risk_score: Overall risk score (0-100)
        status: Discovery status (open, acknowledged, closed)
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    alert_ids: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    details_markdown: str = ""
    summary_markdown: str = ""
    entity_summary_markdown: str = ""
    mitre_attack_tactics: list[str] = field(default_factory=list)
    mitre_attack_techniques: list[str] = field(default_factory=list)
    risk_score: int = 50
    status: str = "open"
    generation_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    api_config: dict[str, Any] = field(default_factory=dict)
    users: list[dict[str, str]] = field(default_factory=list)
    hosts: list[dict[str, str]] = field(default_factory=list)
    namespace: str = "default"
    attack_first_seen: str = ""
    attack_last_seen: str = ""
    case_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Set default timestamps if not provided."""
        if not self.attack_first_seen:
            self.attack_first_seen = self.timestamp
        if not self.attack_last_seen:
            self.attack_last_seen = self.timestamp

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary format for Elasticsearch indexing.

        Returns:
            Dictionary in Elastic Attack Discovery format
        """
        return {
            "@timestamp": self.timestamp,
            "kibana.alert.attack_discovery.id": self.id,
            "kibana.alert.attack_discovery.title": self.title,
            "kibana.alert.attack_discovery.alert_ids": self.alert_ids,
            "kibana.alert.attack_discovery.details_markdown": self.details_markdown,
            "kibana.alert.attack_discovery.summary_markdown": self.summary_markdown,
            "kibana.alert.attack_discovery.entity_summary_markdown": self.entity_summary_markdown,
            "kibana.alert.attack_discovery.mitre_attack_tactics": self.mitre_attack_tactics,
            "kibana.alert.attack_discovery.mitre_attack_techniques": self.mitre_attack_techniques,
            "kibana.alert.attack_discovery.timestamp": self.timestamp,
            "kibana.alert.attack_discovery.attack_first_seen": self.attack_first_seen,
            "kibana.alert.attack_discovery.attack_last_seen": self.attack_last_seen,
            "kibana.alert.attack_discovery.risk_score": self.risk_score,
            "kibana.alert.attack_discovery.status": self.status,
            "kibana.alert.attack_discovery.generation_uuid": self.generation_uuid,
            "kibana.alert.attack_discovery.api_config": self.api_config,
            "kibana.alert.attack_discovery.users": self.users,
            "kibana.alert.attack_discovery.hosts": self.hosts,
            "kibana.alert.attack_discovery.case_ids": self.case_ids,
            "kibana.space_ids": [self.namespace],
        }

    def link_case(self, case_id: str) -> None:
        """
        Link a case to this attack discovery.

        Args:
            case_id: Case ID to link
        """
        if case_id and case_id not in self.case_ids:
            self.case_ids.append(case_id)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackDiscovery":
        """
        Create AttackDiscovery from dictionary.

        Args:
            data: Dictionary with attack discovery fields

        Returns:
            AttackDiscovery instance
        """
        prefix = "kibana.alert.attack_discovery."
        return cls(
            id=data.get(f"{prefix}id", str(uuid.uuid4())),
            title=data.get(f"{prefix}title", ""),
            alert_ids=data.get(f"{prefix}alert_ids", []),
            timestamp=data.get(f"{prefix}timestamp", data.get("@timestamp", "")),
            details_markdown=data.get(f"{prefix}details_markdown", ""),
            summary_markdown=data.get(f"{prefix}summary_markdown", ""),
            entity_summary_markdown=data.get(f"{prefix}entity_summary_markdown", ""),
            mitre_attack_tactics=data.get(f"{prefix}mitre_attack_tactics", []),
            mitre_attack_techniques=data.get(f"{prefix}mitre_attack_techniques", []),
            risk_score=data.get(f"{prefix}risk_score", 50),
            status=data.get(f"{prefix}status", "open"),
            users=data.get(f"{prefix}users", []),
            hosts=data.get(f"{prefix}hosts", []),
        )


# Static templates for attack discovery summaries
ATTACK_DISCOVERY_TEMPLATES: dict[str, dict[str, Any]] = {
    "brute-force": {
        "title": "Brute Force Attack Detected",
        "summary_markdown": "Multiple failed authentication attempts followed by a successful login have been detected, indicating a potential brute force attack.",
        "details_markdown": """## Attack Overview

A brute force attack has been identified targeting user accounts in the environment.

### Key Findings
- **Attack Pattern**: Multiple failed login attempts from a single source IP
- **Outcome**: Successful authentication after numerous failures
- **Risk Level**: High

### Attack Timeline
The attacker systematically attempted to guess credentials, eventually succeeding in gaining access.

### Recommendations
1. Reset the compromised account password immediately
2. Review all activity from the compromised account
3. Implement account lockout policies
4. Enable multi-factor authentication
5. Block the source IP address""",
        "ttps": ["T1110", "T1110.001", "T1110.003"],
        "tactics": ["TA0006"],
        "risk_score": 73,
    },
    "c2-beacon": {
        "title": "Command and Control Beaconing Activity",
        "summary_markdown": "Regular interval network connections to a suspicious destination suggest command and control (C2) beaconing activity.",
        "details_markdown": """## Attack Overview

Command and Control beaconing has been detected from hosts in the environment.

### Key Findings
- **Attack Pattern**: Regular interval connections to external destination
- **Protocol**: HTTPS/TLS encrypted traffic
- **Risk Level**: Critical

### Attack Timeline
The compromised system has been communicating with an external C2 server at regular intervals, typical of beacon behavior used by malware and RATs.

### Recommendations
1. Isolate affected hosts immediately
2. Capture network traffic for forensic analysis
3. Search for additional indicators of compromise
4. Block C2 destination at network perimeter
5. Perform full malware scan on affected systems""",
        "ttps": ["T1071", "T1071.001", "T1573"],
        "tactics": ["TA0011"],
        "risk_score": 99,
    },
    "dga": {
        "title": "Domain Generation Algorithm Activity Detected",
        "summary_markdown": "High volume of DNS queries to algorithmically generated domains with high NXDOMAIN rates indicates DGA malware activity.",
        "details_markdown": """## Attack Overview

Domain Generation Algorithm (DGA) activity has been detected from hosts in the environment.

### Key Findings
- **Attack Pattern**: High entropy domain queries
- **NXDOMAIN Rate**: >90% of queries returning NXDOMAIN
- **Risk Level**: High

### Attack Timeline
The affected host is querying numerous randomly-generated domains, a technique used by malware to locate C2 servers dynamically.

### Recommendations
1. Isolate the affected host
2. Perform full malware scan
3. Analyze network traffic for successful C2 connections
4. Implement DNS sinkholing for known DGA patterns
5. Review endpoint detection logs for malware indicators""",
        "ttps": ["T1568", "T1568.002"],
        "tactics": ["TA0011"],
        "risk_score": 73,
    },
    "lateral-movement": {
        "title": "Lateral Movement Detected",
        "summary_markdown": "Evidence of lateral movement has been detected, with compromised credentials being used to access additional systems.",
        "details_markdown": """## Attack Overview

An attacker is actively moving through the network using compromised credentials.

### Key Findings
- **Attack Pattern**: Authentication to multiple systems using same credentials
- **Techniques Used**: RDP, SMB, or SSH lateral movement
- **Risk Level**: Critical

### Attack Timeline
After initial compromise, the attacker has been observed authenticating to additional systems in the network, indicating active lateral movement.

### Recommendations
1. Isolate affected systems immediately
2. Reset credentials for compromised accounts
3. Review authentication logs across all systems
4. Enable enhanced monitoring on high-value targets
5. Implement network segmentation""",
        "ttps": ["T1021", "T1021.001", "T1021.002", "T1570"],
        "tactics": ["TA0008"],
        "risk_score": 99,
    },
    "ransomware": {
        "title": "Ransomware Activity Detected",
        "summary_markdown": "Ransomware behavior has been detected, including file encryption and shadow copy deletion.",
        "details_markdown": """## Attack Overview

Active ransomware execution has been detected in the environment.

### Key Findings
- **Attack Pattern**: Mass file encryption, shadow copy deletion
- **Impact**: Data encryption in progress
- **Risk Level**: Critical - Immediate action required

### Attack Timeline
Ransomware has been deployed and is actively encrypting files. Shadow copies and backup mechanisms may have been targeted.

### Recommendations
1. **IMMEDIATE**: Isolate affected systems from network
2. Do NOT pay ransom
3. Preserve encrypted files for potential decryption
4. Restore from clean backups
5. Conduct full forensic investigation
6. Report to law enforcement""",
        "ttps": ["T1486", "T1490"],
        "tactics": ["TA0040"],
        "risk_score": 99,
    },
    "data-exfiltration": {
        "title": "Data Exfiltration Detected",
        "summary_markdown": "Large outbound data transfers to external destinations suggest active data exfiltration.",
        "details_markdown": """## Attack Overview

Evidence of data exfiltration has been detected from the environment.

### Key Findings
- **Attack Pattern**: Large outbound data transfers
- **Destination**: External/suspicious endpoints
- **Risk Level**: Critical

### Attack Timeline
Unusual volumes of data are being transferred to external destinations, indicating potential theft of sensitive information.

### Recommendations
1. Block identified exfiltration destinations
2. Identify what data may have been compromised
3. Preserve logs for forensic analysis
4. Notify relevant stakeholders (legal, compliance)
5. Implement DLP controls""",
        "ttps": ["T1041", "T1048"],
        "tactics": ["TA0010"],
        "risk_score": 99,
    },
    "credential-dump": {
        "title": "Credential Dumping Activity Detected",
        "summary_markdown": "Tools or techniques associated with credential dumping have been detected, indicating an attacker is harvesting credentials.",
        "details_markdown": """## Attack Overview

Credential harvesting activity has been detected in the environment.

### Key Findings
- **Attack Pattern**: Access to credential stores (LSASS, SAM, NTDS)
- **Tools**: Mimikatz or similar credential dumping tools
- **Risk Level**: High

### Attack Timeline
An attacker has accessed credential stores to extract passwords, hashes, or Kerberos tickets for use in further attacks.

### Recommendations
1. Isolate affected systems
2. Reset all potentially compromised credentials
3. Review for lateral movement using dumped credentials
4. Implement credential guard and protected users
5. Enable enhanced credential protection""",
        "ttps": ["T1003", "T1003.001"],
        "tactics": ["TA0006"],
        "risk_score": 73,
    },
    "malware-drop": {
        "title": "Malware Delivery Detected",
        "summary_markdown": "Malware has been delivered and executed on systems in the environment.",
        "details_markdown": """## Attack Overview

Malicious software delivery and execution has been detected.

### Key Findings
- **Attack Pattern**: File drop and execution
- **Delivery Method**: Unknown (requires investigation)
- **Risk Level**: High

### Attack Timeline
Malicious files have been written to disk and executed, potentially establishing persistence or beginning malicious activity.

### Recommendations
1. Quarantine the malicious file
2. Isolate affected systems
3. Perform full malware analysis
4. Search for indicators of compromise across environment
5. Determine delivery vector and remediate""",
        "ttps": ["T1204", "T1204.002", "T1105"],
        "tactics": ["TA0002"],
        "risk_score": 73,
    },
    "phishing": {
        "title": "Phishing Attack Detected",
        "summary_markdown": "A phishing attack has been identified, with users receiving and potentially interacting with malicious content.",
        "details_markdown": """## Attack Overview

A phishing campaign targeting the organization has been detected.

### Key Findings
- **Attack Pattern**: Spearphishing with malicious attachment/link
- **Delivery**: Email
- **Risk Level**: Medium to High

### Attack Timeline
Users received phishing emails containing malicious content. Investigation is needed to determine if any users interacted with the content.

### Recommendations
1. Block sender domains and IPs
2. Remove phishing emails from all mailboxes
3. Identify users who clicked links or opened attachments
4. Scan affected systems for malware
5. Conduct user awareness training""",
        "ttps": ["T1566", "T1566.001", "T1566.002"],
        "tactics": ["TA0001"],
        "risk_score": 47,
    },
    "webshell": {
        "title": "Web Shell Detected",
        "summary_markdown": "A web shell has been detected on a web server, providing attackers with remote command execution capability.",
        "details_markdown": """## Attack Overview

A web shell has been installed on a web server in the environment.

### Key Findings
- **Attack Pattern**: Web shell deployment on public-facing server
- **Capability**: Remote command execution
- **Risk Level**: Critical

### Attack Timeline
An attacker has successfully deployed a web shell, likely through exploitation of a web application vulnerability or compromised credentials.

### Recommendations
1. Take affected server offline immediately
2. Preserve evidence for forensic analysis
3. Identify and remove all web shells
4. Patch the vulnerability that allowed access
5. Review all web server logs for attacker activity""",
        "ttps": ["T1505", "T1505.003"],
        "tactics": ["TA0003"],
        "risk_score": 99,
    },
}

