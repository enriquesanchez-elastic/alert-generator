"""Alert generator for creating detection rule alerts."""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from alerts_generator.config.settings import Settings
from alerts_generator.generators.randomizers import RandomDataGenerator
from alerts_generator.models.campaign import Campaign
from alerts_generator.models.scenario import Scenario


class AlertGenerator:
    """Generator for creating detection rule alerts."""

    def __init__(
        self,
        settings: Settings,
        randomizer: Optional[RandomDataGenerator] = None,
    ) -> None:
        """
        Initialize alert generator.

        Args:
            settings: Application settings
            randomizer: Optional RandomDataGenerator instance
        """
        self.settings = settings
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        scenario: Scenario,
        hostname: Optional[str] = None,
        agent_id: Optional[str] = None,
        timestamp_offset: int = 0,
        campaign: Optional[Campaign] = None,
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Generate a detection rule alert based on an attack scenario.

        Args:
            scenario: Attack scenario
            hostname: Optional hostname override
            agent_id: Optional agent ID override
            timestamp_offset: Minutes to offset the timestamp
            campaign: Optional Campaign object for correlated attacks

        Returns:
            Tuple of (alert dictionary, list of entity IDs)
        """
        now = (datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)).isoformat()

        if agent_id is None:
            agent_id = self.randomizer.generate_uuid()
        if hostname is None:
            hostname = self.randomizer.generate_hostname()

        # Generate entity IDs for the process hierarchy
        num_processes = len(scenario.processes)
        entity_ids = [self.randomizer.generate_entity_id() for _ in range(num_processes)]

        # The last process is the malware (leaf node)
        process_entity_id = entity_ids[-1]
        # The first process is the session leader (root)
        session_leader_id = entity_ids[0]
        # Build ancestry from leaf to root (excluding the process itself)
        ancestry = entity_ids[-2::-1] if num_processes > 1 else []

        # Get process details for the malicious process
        malware_process = scenario.processes[-1]

        # Generate hashes - use campaign base if in campaign mode
        file_md5, file_sha1, file_sha256 = self._generate_hashes(campaign)

        # Get severity
        risk_score = self.randomizer.severity_to_risk_score(scenario.severity)

        alert: Dict[str, Any] = {
            "@timestamp": now,
            **self._build_agent_info(agent_id),
            **self._build_host_info(hostname),
            **self._build_data_stream(),
            "ecs": {"version": "1.4.0"},
            **self._build_file_info(scenario, malware_process, file_md5, file_sha1, file_sha256),
            **self._build_process_info(
                scenario,
                malware_process,
                process_entity_id,
                session_leader_id,
                entity_ids,
                ancestry,
                file_md5,
                file_sha1,
                file_sha256,
            ),
            **self._build_event_info(now),
            **self._build_kibana_alert_fields(
                scenario,
                malware_process,
                hostname,
                risk_score,
                now,
                entity_ids,
            ),
            **self._build_kibana_rule_fields(scenario.severity, risk_score),
            **self._build_alert_status(scenario.severity, now),
        }

        return alert, entity_ids

    def _generate_hashes(self, campaign: Optional[Campaign]) -> Tuple[str, str, str]:
        """Generate file hashes, using campaign base if available."""
        if campaign:
            file_md5 = campaign.file_hash_base + self.randomizer.generate_hash("md5")[:12]
            file_sha1 = campaign.file_hash_base + self.randomizer.generate_hash("sha1")[:20]
            file_sha256 = campaign.file_hash_base + self.randomizer.generate_hash("sha256")[:44]
        else:
            file_md5 = self.randomizer.generate_hash("md5")
            file_sha1 = self.randomizer.generate_hash("sha1")
            file_sha256 = self.randomizer.generate_hash("sha256")

        return file_md5, file_sha1, file_sha256

    def _build_agent_info(self, agent_id: str) -> Dict[str, Any]:
        """Build agent information section."""
        return {"agent": {"id": agent_id, "type": "endpoint", "version": "8.17.0"}}

    def _build_host_info(self, hostname: str) -> Dict[str, Any]:
        """Build host information section."""
        host_ip = self.randomizer.generate_ip()
        host_mac = self.randomizer.generate_mac()

        return {
            "host": {
                "architecture": "x86_64",
                "hostname": hostname,
                "id": self.randomizer.generate_uuid(),
                "ip": [host_ip, self.randomizer.generate_ip()],
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
            }
        }

    def _build_data_stream(self) -> Dict[str, Any]:
        """Build data stream information."""
        return {
            "data_stream": {
                "dataset": "endpoint.alerts",
                "namespace": "default",
                "type": "logs",
            }
        }

    def _build_file_info(
        self,
        scenario: Scenario,
        malware_process: Any,
        file_md5: str,
        file_sha1: str,
        file_sha256: str,
    ) -> Dict[str, Any]:
        """Build file information section."""
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        return {
            "file": {
                "Ext": {
                    "code_signature": [{"subject_name": "bad signer", "trusted": False}],
                    "malware_classification": {
                        "identifier": "endpointpe",
                        "score": 1.0,
                        "threshold": 0.66,
                        "version": "3.0.33",
                    },
                    "quarantine_message": f"{scenario.name} detected and quarantined",
                    "quarantine_result": True,
                    "temp_file_path": scenario.malware_file.path,
                },
                "accessed": now_ms,
                "created": now_ms,
                "hash": {
                    "md5": file_md5,
                    "sha1": file_sha1,
                    "sha256": file_sha256,
                },
                "mtime": now_ms,
                "name": scenario.malware_file.name,
                "owner": malware_process.user,
                "path": scenario.malware_file.path,
                "size": random.randint(1024, 1024000),
            }
        }

    def _build_process_info(
        self,
        scenario: Scenario,
        malware_process: Any,
        process_entity_id: str,
        session_leader_id: str,
        entity_ids: List[str],
        ancestry: List[str],
        file_md5: str,
        file_sha1: str,
        file_sha256: str,
    ) -> Dict[str, Any]:
        """Build process information section."""
        num_processes = len(scenario.processes)
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        return {
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
                        "user": malware_process.user,
                    },
                    "user": malware_process.user,
                },
                "entity_id": process_entity_id,
                "entry_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario.processes[0].name,
                    "pid": 100 + random.randint(0, 50),
                    "start": ["1970-01-01T00:00:00.000Z"],
                },
                "executable": malware_process.executable,
                "group_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario.processes[0].name,
                    "pid": 100 + random.randint(0, 50),
                },
                "hash": {
                    "md5": file_md5,
                    "sha1": file_sha1,
                    "sha256": file_sha256,
                },
                "name": malware_process.name,
                "parent": {
                    "entity_id": entity_ids[-2] if num_processes > 1 else session_leader_id,
                    "pid": 1000 + random.randint(0, 1000),
                },
                "pid": 2000 + random.randint(0, 3000),
                "session_leader": {
                    "entity_id": session_leader_id,
                    "name": scenario.processes[0].name,
                    "pid": 100 + random.randint(0, 50),
                },
                "start": now_ms,
                "uptime": 0,
            }
        }

    def _build_event_info(self, now: str) -> Dict[str, Any]:
        """Build event information section."""
        return {
            "event.action": "creation",
            "event.agent_id_status": "verified",
            "event.category": "malware",
            "event.code": "malicious_file",
            "event.dataset": "endpoint",
            "event.id": self.randomizer.generate_uuid(),
            "event.ingested": now,
            "event.kind": "signal",
            "event.module": "endpoint",
            "event.sequence": random.randint(1, 100),
            "event.type": "creation",
        }

    def _build_kibana_alert_fields(
        self,
        scenario: Scenario,
        malware_process: Any,
        hostname: str,
        risk_score: int,
        now: str,
        entity_ids: List[str],
    ) -> Dict[str, Any]:
        """Build Kibana alert fields."""
        return {
            "kibana.alert.ancestors": [
                {
                    "depth": 0,
                    "id": self.randomizer.generate_uuid()[:20],
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
            "kibana.alert.original_event.id": self.randomizer.generate_uuid(),
            "kibana.alert.original_event.ingested": now,
            "kibana.alert.original_event.kind": "alert",
            "kibana.alert.original_event.module": "endpoint",
            "kibana.alert.original_event.sequence": random.randint(1, 100),
            "kibana.alert.original_event.type": "creation",
            "kibana.alert.original_time": now,
            "kibana.alert.reason": (
                f"malware event with process {malware_process.name}, "
                f"file {scenario.malware_file.name}, on {hostname} "
                f"created {scenario.severity} alert {scenario.name}."
            ),
            "kibana.alert.risk_score": risk_score,
        }

    def _build_kibana_rule_fields(self, severity: str, risk_score: int) -> Dict[str, Any]:
        """Build Kibana rule fields."""
        rule_id = self.settings.elastic_security_rule_id

        severity_mapping = [
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
        ]

        return {
            "kibana.alert.rule.actions": [],
            "kibana.alert.rule.author": ["Elastic"],
            "kibana.alert.rule.category": "Custom Query Rule",
            "kibana.alert.rule.consumer": "siem",
            "kibana.alert.rule.created_at": "2024-10-26T21:02:00.237Z",
            "kibana.alert.rule.created_by": "elastic",
            "kibana.alert.rule.description": (
                "Generates a detection alert each time an Elastic Endpoint Security "
                "alert is received. Enabling this rule allows you to immediately begin "
                "investigating your Endpoint alerts."
            ),
            "kibana.alert.rule.enabled": True,
            "kibana.alert.rule.exceptions_list": [
                {
                    "id": "endpoint_list",
                    "list_id": "endpoint_list",
                    "namespace_type": "agnostic",
                    "type": "endpoint",
                }
            ],
            "kibana.alert.rule.execution.uuid": self.randomizer.generate_uuid(),
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
                "description": (
                    "Generates a detection alert each time an Elastic Endpoint Security "
                    "alert is received. Enabling this rule allows you to immediately begin "
                    "investigating your Endpoint alerts."
                ),
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
                "rule_id": rule_id,
                "rule_name_override": "message",
                "severity": severity,
                "severity_mapping": severity_mapping,
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
            "kibana.alert.rule.rule_id": rule_id,
            "kibana.alert.rule.rule_name_override": "message",
            "kibana.alert.rule.rule_type_id": "siem.queryRule",
            "kibana.alert.rule.severity": severity,
            "kibana.alert.rule.severity_mapping": severity_mapping,
            "kibana.alert.rule.tags": ["Elastic", "Endpoint Security"],
            "kibana.alert.rule.threat": [],
            "kibana.alert.rule.timestamp_override": "event.ingested",
            "kibana.alert.rule.to": "now",
            "kibana.alert.rule.type": "query",
            "kibana.alert.rule.updated_at": "2024-10-26T21:02:00.237Z",
            "kibana.alert.rule.updated_by": "elastic",
            "kibana.alert.rule.uuid": "6eae8572-5571-11ed-a602-953b659b2e32",
            "kibana.alert.rule.version": 100,
        }

    def _build_alert_status(self, severity: str, now: str) -> Dict[str, Any]:
        """Build alert status and workflow fields."""
        return {
            "kibana.alert.severity": severity,
            "kibana.alert.status": "active",
            "kibana.alert.uuid": self.randomizer.generate_uuid(),
            "kibana.alert.workflow_status": "open",
            "kibana.space_ids": ["default"],
            "kibana.version": "8.17.0",
        }

    def generate_endpoint_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an endpoint alert from the detection rule alert.

        Args:
            alert: Detection rule alert dictionary

        Returns:
            Endpoint alert dictionary with event.kind="alert"
        """
        return {
            "@timestamp": alert["@timestamp"],
            "agent": alert["agent"],
            "ecs": alert["ecs"],
            "event": {
                "action": "creation",
                "kind": "alert",
                "category": ["malware"],
                "code": "malicious_file",
                "id": self.randomizer.generate_uuid(),
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
