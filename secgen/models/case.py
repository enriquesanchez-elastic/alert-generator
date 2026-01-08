"""Security Case model and data structures for Elastic Security Case Management."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

CaseStatus = Literal["open", "in-progress", "closed"]
CaseSeverity = Literal["low", "medium", "high", "critical"]
ConnectorType = Literal["none", "jira", "servicenow", "swimlane", "resilient"]

# Kibana API requires connector types with dot prefix
CONNECTOR_TYPE_API_MAP = {
    "none": ".none",
    "jira": ".jira",
    "servicenow": ".servicenow-sir",
    "swimlane": ".swimlane",
    "resilient": ".resilient",
}


@dataclass
class CaseConnector:
    """
    External connector configuration for a case.

    Attributes:
        id: Connector ID
        name: Connector name
        type: Connector type (jira, servicenow, etc.)
        fields: Connector-specific fields
    """

    id: str = "none"
    name: str = "none"
    type: ConnectorType = "none"
    fields: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for Kibana API."""
        # Kibana API expects type with dot prefix and null fields when empty
        api_type = CONNECTOR_TYPE_API_MAP.get(self.type, f".{self.type}")
        return {
            "id": self.id,
            "name": self.name,
            "type": api_type,
            "fields": self.fields,  # None serializes to null in JSON
        }


@dataclass
class CaseComment:
    """
    Comment on a security case.

    Attributes:
        id: Comment ID
        comment: Comment text
        type: Comment type (user or alert)
        created_at: Creation timestamp
        created_by: User who created the comment
        owner: Application owner
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    comment: str = ""
    type: str = "user"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    created_by: str = "elastic"
    owner: str = "securitySolution"
    pushed_at: str | None = None
    pushed_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "comment": self.comment,
            "type": self.type,
            "created_at": self.created_at,
            "created_by": {
                "username": self.created_by,
                "full_name": self.created_by.title(),
                "email": f"{self.created_by}@example.com",
            },
            "owner": self.owner,
        }
        if self.pushed_at:
            result["pushed_at"] = self.pushed_at
        if self.pushed_by:
            result["pushed_by"] = {
                "username": self.pushed_by,
                "full_name": self.pushed_by.title(),
            }
        return result


@dataclass
class CaseAlertAttachment:
    """
    Alert attachment for a case.

    Attributes:
        alert_id: Alert UUID
        index: Alert index
        rule_id: Detection rule ID
        rule_name: Detection rule name
    """

    alert_id: str
    index: str = ".alerts-security.alerts-default"
    rule_id: str = ""
    rule_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alertId": self.alert_id,
            "index": self.index,
            "type": "alert",
            "rule": {
                "id": self.rule_id,
                "name": self.rule_name,
            },
        }


@dataclass
class SecurityCase:
    """
    Model for Elastic Security Case Management.

    Cases allow analysts to track and manage security investigations,
    linking alerts, comments, and external systems.

    Attributes:
        id: Case ID
        title: Case title
        description: Case description
        status: Case status (open, in-progress, closed)
        severity: Case severity (low, medium, high, critical)
        tags: List of tags
        assignees: List of assigned usernames
        created_at: Creation timestamp
        created_by: User who created the case
        updated_at: Last update timestamp
        updated_by: User who last updated
        closed_at: Closure timestamp
        closed_by: User who closed the case
        connector: External connector configuration
        settings: Case settings
        owner: Application owner
        comments: List of case comments
        alerts: List of attached alerts
        attack_discovery_ids: List of linked attack discovery IDs
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    status: CaseStatus = "open"
    severity: CaseSeverity = "medium"
    tags: list[str] = field(default_factory=list)
    assignees: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    created_by: str = "elastic"
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_by: str = "elastic"
    closed_at: str | None = None
    closed_by: str | None = None
    connector: CaseConnector = field(default_factory=CaseConnector)
    settings: dict[str, Any] = field(default_factory=lambda: {"syncAlerts": True})
    owner: str = "securitySolution"
    comments: list[CaseComment] = field(default_factory=list)
    alerts: list[CaseAlertAttachment] = field(default_factory=list)
    attack_discovery_ids: list[str] = field(default_factory=list)
    total_alerts: int = 0
    total_comments: int = 0
    version: str = "WzE2NywxXQ=="  # Base64 encoded version

    def __post_init__(self) -> None:
        """Update counts after initialization."""
        self.total_alerts = len(self.alerts)
        self.total_comments = len(self.comments)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary format for Kibana Cases API.

        Returns:
            Dictionary in Kibana Case format
        """
        result = {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "tags": self.tags,
            "assignees": [
                {"uid": username, "username": username}
                for username in self.assignees
            ],
            "created_at": self.created_at,
            "created_by": {
                "username": self.created_by,
                "full_name": self.created_by.title(),
                "email": f"{self.created_by}@example.com",
            },
            "updated_at": self.updated_at,
            "updated_by": {
                "username": self.updated_by,
                "full_name": self.updated_by.title(),
            },
            "connector": self.connector.to_dict(),
            "settings": self.settings,
            "owner": self.owner,
            "totalAlerts": self.total_alerts,
            "totalComment": self.total_comments,
        }

        if self.closed_at:
            result["closed_at"] = self.closed_at
        if self.closed_by:
            result["closed_by"] = {
                "username": self.closed_by,
                "full_name": self.closed_by.title(),
            }

        # Add attack discovery linkage as custom field
        if self.attack_discovery_ids:
            result["customFields"] = [
                {
                    "key": "attack_discovery_ids",
                    "type": "text",
                    "value": ",".join(self.attack_discovery_ids),
                }
            ]

        return result

    def to_create_payload(self) -> dict[str, Any]:
        """
        Convert to payload format for Kibana Cases create API.

        Returns:
            Dictionary for POST /api/cases
        """
        return {
            "title": self.title,
            "description": self.description,
            "tags": self.tags,
            "severity": self.severity,
            "assignees": [{"uid": username} for username in self.assignees],
            "connector": self.connector.to_dict(),
            "settings": self.settings,
            "owner": self.owner,
        }

    def add_comment(self, comment: str, created_by: str = "elastic") -> CaseComment:
        """
        Add a comment to the case.

        Args:
            comment: Comment text
            created_by: Username of commenter

        Returns:
            Created CaseComment instance
        """
        case_comment = CaseComment(
            comment=comment,
            created_by=created_by,
            type="user",
        )
        self.comments.append(case_comment)
        self.total_comments = len(self.comments)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        self.updated_by = created_by
        return case_comment

    def attach_alert(
        self,
        alert_id: str,
        index: str = ".alerts-security.alerts-default",
        rule_id: str = "",
        rule_name: str = "",
    ) -> CaseAlertAttachment:
        """
        Attach an alert to the case.

        Args:
            alert_id: Alert UUID
            index: Alert index
            rule_id: Detection rule ID
            rule_name: Detection rule name

        Returns:
            Created CaseAlertAttachment instance
        """
        attachment = CaseAlertAttachment(
            alert_id=alert_id,
            index=index,
            rule_id=rule_id,
            rule_name=rule_name,
        )
        self.alerts.append(attachment)
        self.total_alerts = len(self.alerts)
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return attachment

    def link_attack_discovery(self, discovery_id: str) -> None:
        """
        Link an attack discovery to this case.

        Args:
            discovery_id: Attack Discovery UUID
        """
        if discovery_id not in self.attack_discovery_ids:
            self.attack_discovery_ids.append(discovery_id)
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def close(self, closed_by: str = "elastic") -> None:
        """
        Close the case.

        Args:
            closed_by: Username of closer
        """
        self.status = "closed"
        self.closed_at = datetime.now(timezone.utc).isoformat()
        self.closed_by = closed_by
        self.updated_at = self.closed_at
        self.updated_by = closed_by

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityCase":
        """
        Create SecurityCase from dictionary.

        Args:
            data: Dictionary with case fields

        Returns:
            SecurityCase instance
        """
        # Parse connector
        connector_data = data.get("connector", {})
        connector = CaseConnector(
            id=connector_data.get("id", "none"),
            name=connector_data.get("name", "none"),
            type=connector_data.get("type", "none"),
            fields=connector_data.get("fields", {}),
        )

        # Parse assignees
        assignees = []
        for assignee in data.get("assignees", []):
            if isinstance(assignee, dict):
                assignees.append(assignee.get("username", ""))
            else:
                assignees.append(assignee)

        # Parse created_by
        created_by = data.get("created_by", {})
        if isinstance(created_by, dict):
            created_by = created_by.get("username", "elastic")

        # Parse updated_by
        updated_by = data.get("updated_by", {})
        if isinstance(updated_by, dict):
            updated_by = updated_by.get("username", "elastic")

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data.get("title", ""),
            description=data.get("description", ""),
            status=data.get("status", "open"),
            severity=data.get("severity", "medium"),
            tags=data.get("tags", []),
            assignees=assignees,
            created_at=data.get("created_at", ""),
            created_by=created_by,
            updated_at=data.get("updated_at", ""),
            updated_by=updated_by,
            closed_at=data.get("closed_at"),
            closed_by=data.get("closed_by", {}).get("username") if isinstance(data.get("closed_by"), dict) else data.get("closed_by"),
            connector=connector,
            settings=data.get("settings", {"syncAlerts": True}),
            owner=data.get("owner", "securitySolution"),
        )


# Case templates for common investigation scenarios
CASE_TEMPLATES: dict[str, dict[str, Any]] = {
    "brute-force-investigation": {
        "title": "Brute Force Attack Investigation",
        "description": """## Case Summary
A brute force attack has been detected targeting user accounts.

## Investigation Steps
1. Identify all affected accounts
2. Review authentication logs for attack timeline
3. Determine if any accounts were compromised
4. Check for lateral movement from compromised accounts
5. Document findings and remediation actions""",
        "tags": ["brute-force", "credential-access", "investigation"],
        "severity": "high",
        "initial_comments": [
            "Case created from Attack Discovery findings",
            "Initial analysis indicates multiple failed login attempts followed by successful authentication",
        ],
    },
    "malware-incident": {
        "title": "Malware Incident Response",
        "description": """## Case Summary
Malware has been detected on systems in the environment.

## Investigation Steps
1. Isolate affected systems
2. Collect forensic evidence
3. Identify malware family and capabilities
4. Determine initial access vector
5. Search for additional indicators of compromise
6. Document timeline and remediate""",
        "tags": ["malware", "incident-response", "containment"],
        "severity": "critical",
        "initial_comments": [
            "Case created for malware incident response",
            "Affected systems should be isolated immediately",
        ],
    },
    "data-exfiltration-investigation": {
        "title": "Data Exfiltration Investigation",
        "description": """## Case Summary
Evidence of data exfiltration has been detected.

## Investigation Steps
1. Identify what data may have been exfiltrated
2. Review network logs for exfiltration timeline
3. Identify affected systems and users
4. Assess business impact
5. Notify relevant stakeholders
6. Document findings for compliance""",
        "tags": ["data-exfiltration", "data-loss", "compliance"],
        "severity": "critical",
        "initial_comments": [
            "Case created for data exfiltration investigation",
            "Legal and compliance teams may need to be notified",
        ],
    },
    "lateral-movement-investigation": {
        "title": "Lateral Movement Investigation",
        "description": """## Case Summary
Lateral movement activity has been detected in the environment.

## Investigation Steps
1. Map the scope of lateral movement
2. Identify compromised credentials
3. Review authentication logs across systems
4. Determine attacker objectives
5. Contain and remediate""",
        "tags": ["lateral-movement", "post-exploitation", "containment"],
        "severity": "high",
        "initial_comments": [
            "Case created for lateral movement investigation",
            "Focus on identifying all compromised systems",
        ],
    },
    "ransomware-incident": {
        "title": "Ransomware Incident Response",
        "description": """## Case Summary
CRITICAL: Active ransomware incident in progress.

## Immediate Actions Required
1. **ISOLATE** all affected systems immediately
2. Do NOT pay ransom
3. Preserve encrypted files for potential recovery
4. Contact incident response team
5. Document everything

## Investigation Steps
1. Determine ransomware variant
2. Identify initial access vector
3. Map encryption scope
4. Assess backup integrity
5. Plan recovery""",
        "tags": ["ransomware", "critical-incident", "business-impact"],
        "severity": "critical",
        "initial_comments": [
            "CRITICAL: Ransomware incident detected",
            "All affected systems should be isolated immediately",
            "Do NOT interact with ransom notes or contact threat actors",
        ],
    },
    "c2-investigation": {
        "title": "Command and Control Investigation",
        "description": """## Case Summary
Command and control (C2) activity has been detected.

## Investigation Steps
1. Identify all hosts with C2 indicators
2. Block C2 infrastructure
3. Analyze C2 traffic patterns
4. Determine malware capabilities
5. Search for additional compromised systems
6. Contain and remediate""",
        "tags": ["c2", "command-and-control", "network"],
        "severity": "high",
        "initial_comments": [
            "Case created for C2 activity investigation",
            "C2 destinations should be blocked at network perimeter",
        ],
    },
}

