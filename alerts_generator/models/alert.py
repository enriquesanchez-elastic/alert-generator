"""Alert data models and type definitions."""

from typing import Any, Dict, List, Optional

# Type aliases for alert structures
AlertDict = Dict[str, Any]
ProcessEventDict = Dict[str, Any]
EndpointAlertDict = Dict[str, Any]


class AlertData:
    """
    Container for all alert-related data generated for a single alert.

    Attributes:
        alert_number: Sequential alert number (1-indexed)
        scenario_name: Name of the scenario used
        hostname: Target hostname
        severity: Alert severity level
        process_count: Number of process events
        malware_file_name: Name of the malicious file
        detection_alert: Detection rule alert document
        process_events: List of process event documents
        endpoint_alert: Endpoint alert document
        phase: Optional attack phase (for campaigns)
        campaign_id: Optional campaign ID (for campaigns)
        indexed: Whether the alert was successfully indexed
        alert_id: Optional Elasticsearch document ID after indexing
    """

    def __init__(
        self,
        alert_number: int,
        scenario_name: str,
        hostname: str,
        severity: str,
        process_count: int,
        malware_file_name: str,
        detection_alert: AlertDict,
        process_events: List[ProcessEventDict],
        endpoint_alert: EndpointAlertDict,
        phase: Optional[str] = None,
        campaign_id: Optional[str] = None,
        indexed: bool = False,
        alert_id: Optional[str] = None,
    ) -> None:
        """Initialize alert data."""
        self.alert_number = alert_number
        self.scenario_name = scenario_name
        self.hostname = hostname
        self.severity = severity
        self.process_count = process_count
        self.malware_file_name = malware_file_name
        self.detection_alert = detection_alert
        self.process_events = process_events
        self.endpoint_alert = endpoint_alert
        self.phase = phase
        self.campaign_id = campaign_id
        self.indexed = indexed
        self.alert_id = alert_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert data to dictionary for serialization."""
        return {
            "alert_number": self.alert_number,
            "scenario": self.scenario_name,
            "hostname": self.hostname,
            "severity": self.severity,
            "process_count": self.process_count,
            "malware_file": self.malware_file_name,
            "detection_alert": self.detection_alert,
            "process_events": self.process_events,
            "endpoint_alert": self.endpoint_alert,
            **({"phase": self.phase} if self.phase else {}),
            **({"campaign_id": self.campaign_id} if self.campaign_id else {}),
        }
