"""Elasticsearch indexer implementation."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal

import requests

from secgen.config.settings import Settings
from secgen.indexers.base import BaseIndexer

logger = logging.getLogger(__name__)

# Index patterns for different event types
INDEX_PATTERNS = {
    "process": "logs-endpoint.events.process-default",
    "file": "logs-endpoint.events.file-default",
    "registry": "logs-endpoint.events.registry-default",
    "network": "logs-endpoint.events.network-default",
    "endpoint_alert": "logs-endpoint.alerts-default",
    "authentication": "logs-system.auth-default",
    "dns": "logs-dns.query-default",
    "network_flow": "logs-network_traffic.flow-default",
    "http": "logs-network_traffic.http-default",
    "tls": "logs-network_traffic.tls-default",
    "aws_cloudtrail": "logs-aws.cloudtrail-default",
    "azure_signin": "logs-azure.signinlogs-default",
    "azure_audit": "logs-azure.auditlogs-default",
    "gcp_audit": "logs-gcp.audit-default",
    "threat_indicator": "logs-ti_util.logs-default",
    # Beat index patterns (date-based)
    "auditbeat": "auditbeat-8.17.0-{date}",
    "packetbeat": "packetbeat-8.17.0-{date}",
    "filebeat": "filebeat-8.17.0-{date}",
    # Attack Discovery
    "attack_discovery": ".ai-attack-discovery-default",
}

EventType = Literal[
    "process",
    "file",
    "registry",
    "network",
    "endpoint_alert",
    "authentication",
    "dns",
    "network_flow",
    "http",
    "tls",
    "aws_cloudtrail",
    "azure_signin",
    "azure_audit",
    "gcp_audit",
    "threat_indicator",
    "auditbeat",
    "packetbeat",
    "filebeat",
    "attack_discovery",
]


class ElasticsearchIndexer(BaseIndexer):
    """Elasticsearch implementation of the indexer interface."""

    def __init__(self, settings: Settings) -> None:
        """
        Initialize Elasticsearch indexer.

        Args:
            settings: Application settings with Elasticsearch configuration
        """
        self.settings = settings
        self.base_url = settings.elastic_url_with_protocol
        # Use configured kibana_url or derive from elastic_url
        kibana_url = getattr(settings, "kibana_url", "")
        if kibana_url:
            self.kibana_url = kibana_url if "://" in kibana_url else f"http://{kibana_url}"
        else:
            # Default: derive from elastic URL
            self.kibana_url = self.base_url.replace(":9200", ":5601")
        # Kibana base path (e.g., /dvx for cloud deployments)
        self.kibana_base_path = getattr(settings, "kibana_base_path", "").rstrip("/")
        # Kibana space (use "default" to avoid space prefix in URL)
        self.kibana_space = getattr(settings, "kibana_space", "default")
        self.username = settings.elastic_username
        self.password = settings.elastic_password
        self.alerts_index = settings.alerts_index
        # Track which templates have been ensured this session
        self._ensured_templates: set[str] = set()

    def ensure_beat_template(
        self,
        beat_type: Literal["auditbeat", "packetbeat", "filebeat"],
    ) -> bool:
        """
        Ensure the index template exists for a beat type with proper ECS mappings.

        This creates an index template that maps ECS fields correctly, particularly
        ensuring host.name, user.name, etc. are keyword fields for aggregations.

        Args:
            beat_type: Type of Beat (auditbeat, packetbeat, filebeat)

        Returns:
            True if template exists or was created, False on failure
        """
        template_name = f"{beat_type}-secgen"

        # Skip if already ensured this session
        if template_name in self._ensured_templates:
            return True

        # Check if template exists
        url = f"{self.base_url}/_index_template/{template_name}"
        try:
            response = requests.get(
                url,
                auth=(self.username, self.password),
                timeout=10,
            )
            if response.status_code == 200:
                self._ensured_templates.add(template_name)
                return True
        except Exception:
            pass

        # Create the template with ECS-compliant mappings
        template = {
            "index_patterns": [f"{beat_type}-*"],
            "priority": 100,  # Higher priority than default templates
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
                "mappings": {
                    "dynamic": "true",
                    "dynamic_templates": [
                        {
                            "strings_as_keywords": {
                                "match_mapping_type": "string",
                                "mapping": {
                                    "type": "keyword",
                                    "ignore_above": 1024,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "message": {"type": "text"},
                        "host": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "hostname": {"type": "keyword"},
                                "ip": {"type": "ip"},
                                "mac": {"type": "keyword"},
                                "architecture": {"type": "keyword"},
                                "os": {
                                    "properties": {
                                        "family": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "platform": {"type": "keyword"},
                                        "type": {"type": "keyword"},
                                        "version": {"type": "keyword"},
                                        "kernel": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "user": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "domain": {"type": "keyword"},
                                "email": {"type": "keyword"},
                                "full_name": {"type": "keyword"},
                                "group": {
                                    "properties": {
                                        "id": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                    }
                                },
                                "effective": {
                                    "properties": {
                                        "id": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                    }
                                },
                                "audit": {
                                    "properties": {
                                        "id": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "process": {
                            "properties": {
                                "pid": {"type": "long"},
                                "ppid": {"type": "long"},
                                "name": {"type": "keyword"},
                                "executable": {"type": "keyword"},
                                "command_line": {"type": "keyword"},
                                "args": {"type": "keyword"},
                                "entity_id": {"type": "keyword"},
                                "working_directory": {"type": "keyword"},
                                "start": {"type": "date"},
                                "hash": {
                                    "properties": {
                                        "md5": {"type": "keyword"},
                                        "sha1": {"type": "keyword"},
                                        "sha256": {"type": "keyword"},
                                    }
                                },
                                "user": {
                                    "properties": {
                                        "id": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "file": {
                            "properties": {
                                "path": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "directory": {"type": "keyword"},
                                "extension": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "size": {"type": "long"},
                                "owner": {"type": "keyword"},
                                "group": {"type": "keyword"},
                                "mode": {"type": "keyword"},
                                "hash": {
                                    "properties": {
                                        "md5": {"type": "keyword"},
                                        "sha1": {"type": "keyword"},
                                        "sha256": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"},
                                "address": {"type": "keyword"},
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"},
                                "address": {"type": "keyword"},
                            }
                        },
                        "event": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "kind": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                                "module": {"type": "keyword"},
                                "dataset": {"type": "keyword"},
                            }
                        },
                        "agent": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "ephemeral_id": {"type": "keyword"},
                            }
                        },
                        "ecs": {
                            "properties": {
                                "version": {"type": "keyword"},
                            }
                        },
                        "related": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "user": {"type": "keyword"},
                                "hash": {"type": "keyword"},
                                "hosts": {"type": "keyword"},
                            }
                        },
                        "auditd": {
                            "properties": {
                                "result": {"type": "keyword"},
                                "session": {"type": "keyword"},
                                "log": {
                                    "properties": {
                                        "sequence": {"type": "long"},
                                    }
                                },
                                "summary": {
                                    "properties": {
                                        "actor": {
                                            "properties": {
                                                "primary": {"type": "keyword"},
                                                "secondary": {"type": "keyword"},
                                            }
                                        },
                                        "object": {
                                            "properties": {
                                                "type": {"type": "keyword"},
                                                "primary": {"type": "keyword"},
                                            }
                                        },
                                        "how": {"type": "keyword"},
                                    }
                                },
                                "data": {
                                    "properties": {
                                        "syscall": {"type": "keyword"},
                                        "arch": {"type": "keyword"},
                                        "success": {"type": "keyword"},
                                        "exit": {"type": "keyword"},
                                        "tty": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "system": {
                            "properties": {
                                "auth": {
                                    "properties": {
                                        "ssh": {
                                            "properties": {
                                                "method": {"type": "keyword"},
                                                "event": {"type": "keyword"},
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    },
                },
            },
        }

        try:
            response = requests.put(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
                json=template,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                logger.info(f"Created index template: {template_name}")
                self._ensured_templates.add(template_name)
                return True
            else:
                logger.warning(
                    f"Failed to create index template {template_name}: "
                    f"{response.status_code} - {response.text}"
                )
                return False
        except Exception as e:
            logger.warning(f"Error creating index template {template_name}: {e}")
            return False

    def _get_kibana_api_url(self, endpoint: str) -> str:
        """
        Build Kibana API URL with base path and optional space prefix.

        Args:
            endpoint: API endpoint (e.g., "/api/cases")

        Returns:
            Full URL with base path and space prefix if configured

        Examples:
            - Default: http://localhost:5601/api/cases
            - With base path: http://localhost:5601/dvx/api/cases
            - With space: http://localhost:5601/dvx/s/security/api/cases
        """
        parts = [self.kibana_url]

        # Add base path if configured
        if self.kibana_base_path:
            parts.append(self.kibana_base_path)

        # Add space prefix if not default
        if self.kibana_space and self.kibana_space != "default":
            parts.append(f"/s/{self.kibana_space}")

        # Add the endpoint
        parts.append(endpoint)

        url = "".join(parts)
        # Clean up any double slashes (except in http://)
        return url.replace("://", "___PROTO___").replace("//", "/").replace("___PROTO___", "://")

    def index_alert(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """
        Index a detection rule alert.

        Args:
            alert: Alert dictionary to index

        Returns:
            Index response or None on failure
        """
        url = f"{self.base_url}/{self.alerts_index}/_doc"

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
                json=alert,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Failed to index alert: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error indexing alert: {e}", exc_info=True)
            return None

    def index_events(
        self, events: list[dict[str, Any]], endpoint_alert: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Index process events and endpoint alert using bulk API.

        Args:
            events: List of process event dictionaries
            endpoint_alert: Endpoint alert dictionary

        Returns:
            Bulk index response or None on failure
        """
        url = f"{self.base_url}/_bulk"

        bulk_body = ""

        # Add process events
        for event in events:
            bulk_body += json.dumps({"create": {"_index": INDEX_PATTERNS["process"]}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        # Add endpoint alert
        bulk_body += json.dumps({"create": {"_index": INDEX_PATTERNS["endpoint_alert"]}}) + "\n"
        bulk_body += json.dumps(endpoint_alert) + "\n"

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/x-ndjson"},
                data=bulk_body,
                verify=True,
                timeout=60,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                if result.get("errors"):
                    logger.warning("Some documents failed to index")
                    for item in result.get("items", []):
                        if "error" in item.get("create", {}):
                            logger.error(f"Bulk item error: {item['create']['error']}")
                return result
            else:
                logger.error(f"Failed to index documents: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error indexing events: {e}", exc_info=True)
            return None

    def index_typed_events(
        self,
        events: list[dict[str, Any]],
        event_type: EventType,
    ) -> dict[str, Any] | None:
        """
        Index events of a specific type using bulk API.

        Args:
            events: List of event dictionaries
            event_type: Type of events (determines index pattern)

        Returns:
            Bulk index response or None on failure
        """
        if not events:
            return {"items": [], "errors": False}

        # Ensure beat templates exist before indexing beat events
        if event_type in ("auditbeat", "packetbeat", "filebeat"):
            self.ensure_beat_template(event_type)  # type: ignore[arg-type]

        index_pattern = self._get_index_pattern(event_type)
        if not index_pattern:
            logger.error(f"Unknown event type: {event_type}")
            return None

        url = f"{self.base_url}/_bulk"
        bulk_body = ""

        for event in events:
            bulk_body += json.dumps({"create": {"_index": index_pattern}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/x-ndjson"},
                data=bulk_body,
                verify=True,
                timeout=60,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                if result.get("errors"):
                    logger.warning(f"Some {event_type} documents failed to index")
                    for item in result.get("items", []):
                        if "error" in item.get("create", {}):
                            logger.error(f"Bulk item error: {item['create']['error']}")
                else:
                    logger.info(f"Successfully indexed {len(events)} {event_type} events")
                return result
            else:
                logger.error(
                    f"Failed to index {event_type} documents: "
                    f"{response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error indexing {event_type} events: {e}", exc_info=True)
            return None

    def _get_index_pattern(self, event_type: EventType) -> str | None:
        """Get index pattern for event type, handling date-based indices."""
        pattern = INDEX_PATTERNS.get(event_type)
        if not pattern:
            return None

        # Handle date-based index patterns for beats
        if "{date}" in pattern:
            date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            pattern = pattern.format(date=date_str)

        return pattern

    def index_beat_events(
        self,
        events: list[dict[str, Any]],
        beat_type: Literal["auditbeat", "packetbeat", "filebeat"],
    ) -> dict[str, Any] | None:
        """
        Index Beat-format events.

        Automatically ensures the index template with proper ECS mappings exists
        before indexing to avoid fielddata errors on text fields like host.name.

        Args:
            events: List of Beat event dictionaries
            beat_type: Type of Beat (auditbeat, packetbeat, filebeat)

        Returns:
            Bulk index response or None on failure
        """
        # Ensure the index template exists before indexing
        self.ensure_beat_template(beat_type)
        return self.index_typed_events(events, beat_type)

    def index_attack_discovery(
        self,
        discovery: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Index an Attack Discovery document.

        Args:
            discovery: Attack Discovery dictionary

        Returns:
            Index response or None on failure
        """
        index = INDEX_PATTERNS["attack_discovery"]
        url = f"{self.base_url}/{index}/_doc"

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
                json=discovery,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"Successfully indexed attack discovery: {result.get('_id')}")
                return result
            else:
                logger.error(
                    f"Failed to index attack discovery: "
                    f"{response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error indexing attack discovery: {e}", exc_info=True)
            return None

    def index_case_document(
        self,
        case_doc: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Index a case as a document (fallback when Kibana API unavailable).

        Args:
            case_doc: Case document to index

        Returns:
            Index response or None on failure
        """
        index_pattern = INDEX_PATTERNS.get("case", "logs-case-default")
        url = f"{self.base_url}/{index_pattern}/_doc"

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
                json=case_doc,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"Successfully indexed case document: {result.get('_id')}")
                return result
            else:
                logger.error(
                    f"Failed to index case document: "
                    f"{response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error indexing case document: {e}", exc_info=True)
            return None

    def create_case(
        self,
        case_payload: dict[str, Any],
        fallback_to_index: bool = True,
    ) -> dict[str, Any] | None:
        """
        Create a security case via Kibana API.

        Args:
            case_payload: Case creation payload
            fallback_to_index: If True, index as document when API fails

        Returns:
            Created case response or None on failure
        """
        url = self._get_kibana_api_url("/api/cases")
        logger.debug(f"Creating case via Kibana API: {url}")

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={
                    "Content-Type": "application/json",
                    "kbn-xsrf": "true",
                },
                json=case_payload,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"Successfully created case via API: {result.get('id')}")
                return result
            elif response.status_code == 404:
                # 404 often means wrong URL or Cases feature not enabled
                logger.warning(
                    f"Kibana Cases API not found at {url}. "
                    f"Check KIBANA_URL and KIBANA_SPACE settings. "
                    f"Falling back to document indexing."
                )
                if fallback_to_index:
                    return self.index_case_document(case_payload)
                return None
            elif response.status_code == 400:
                # Bad request - log payload issue for debugging
                logger.error(
                    f"Kibana Cases API rejected payload: {response.text}"
                )
                if fallback_to_index:
                    return self.index_case_document(case_payload)
                return None
            else:
                logger.warning(
                    f"Kibana Cases API error ({response.status_code}): {response.text}. "
                    f"Falling back to document indexing."
                )
                if fallback_to_index:
                    return self.index_case_document(case_payload)
                return None
        except requests.exceptions.ConnectionError:
            logger.warning(
                f"Could not connect to Kibana at {self.kibana_url}, "
                f"falling back to document indexing"
            )
            if fallback_to_index:
                return self.index_case_document(case_payload)
            return None
        except Exception as e:
            logger.error(f"Error creating case: {e}", exc_info=True)
            if fallback_to_index:
                return self.index_case_document(case_payload)
            return None

    def add_case_comment(
        self,
        case_id: str,
        comment: str,
        owner: str = "securitySolution",
    ) -> dict[str, Any] | None:
        """
        Add a comment to a case.

        Args:
            case_id: Case ID
            comment: Comment text
            owner: Case owner

        Returns:
            Comment response or None on failure
        """
        url = self._get_kibana_api_url(f"/api/cases/{case_id}/comments")

        payload = {
            "comment": comment,
            "type": "user",
            "owner": owner,
        }

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={
                    "Content-Type": "application/json",
                    "kbn-xsrf": "true",
                },
                json=payload,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(
                    f"Failed to add case comment: "
                    f"{response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error adding case comment: {e}", exc_info=True)
            return None

    def attach_alerts_to_case(
        self,
        case_id: str,
        alert_ids: list[str],
        owner: str = "securitySolution",
    ) -> dict[str, Any] | None:
        """
        Attach alerts to a case.

        Args:
            case_id: Case ID
            alert_ids: List of alert UUIDs
            owner: Case owner

        Returns:
            Attachment response or None on failure
        """
        url = self._get_kibana_api_url(f"/api/cases/{case_id}/comments")

        payload = {
            "type": "alert",
            "alertId": alert_ids,
            "index": [self.alerts_index] * len(alert_ids),
            "owner": owner,
        }

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={
                    "Content-Type": "application/json",
                    "kbn-xsrf": "true",
                },
                json=payload,
                verify=True,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                logger.info(f"Successfully attached {len(alert_ids)} alerts to case {case_id}")
                return response.json()
            else:
                logger.error(
                    f"Failed to attach alerts to case: "
                    f"{response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            logger.error(f"Error attaching alerts to case: {e}", exc_info=True)
            return None

    def index_multi_type_events(
        self,
        events_by_type: dict[EventType, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """
        Index events of multiple types in a single bulk request.

        Args:
            events_by_type: Dictionary mapping event type to list of events

        Returns:
            Dictionary with results per event type
        """
        url = f"{self.base_url}/_bulk"
        bulk_body = ""
        event_counts: dict[str, int] = {}

        for event_type, events in events_by_type.items():
            index_pattern = self._get_index_pattern(event_type)
            if not index_pattern:
                logger.warning(f"Unknown event type: {event_type}, skipping")
                continue

            event_counts[event_type] = len(events)
            for event in events:
                bulk_body += json.dumps({"create": {"_index": index_pattern}}) + "\n"
                bulk_body += json.dumps(event) + "\n"

        if not bulk_body:
            return {"success": True, "indexed": {}, "errors": []}

        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/x-ndjson"},
                data=bulk_body,
                verify=True,
                timeout=120,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                errors = []

                if result.get("errors"):
                    for item in result.get("items", []):
                        if "error" in item.get("create", {}):
                            errors.append(item["create"]["error"])

                total_indexed = sum(event_counts.values())
                logger.info(f"Indexed {total_indexed} events across {len(event_counts)} types")

                return {
                    "success": True,
                    "indexed": event_counts,
                    "errors": errors,
                }
            else:
                logger.error(f"Failed to index documents: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "indexed": {},
                    "errors": [response.text],
                }
        except Exception as e:
            logger.error(f"Error indexing multi-type events: {e}", exc_info=True)
            return {
                "success": False,
                "indexed": {},
                "errors": [str(e)],
            }

    def delete_all(self) -> dict[str, Any]:
        """
        Delete all data from Elasticsearch indices.

        Returns:
            Dictionary with deletion results
        """
        results: dict[str, Any] = {}

        # Index patterns to delete from
        delete_patterns = [
            ("alerts_index", self.alerts_index),
            ("process_events", "logs-endpoint.events.process-*"),
            ("file_events", "logs-endpoint.events.file-*"),
            ("registry_events", "logs-endpoint.events.registry-*"),
            ("network_events", "logs-endpoint.events.network-*"),
            ("endpoint_alerts", "logs-endpoint.alerts-*"),
            ("auth_events", "logs-system.auth-*"),
            ("dns_events", "logs-dns.query-*"),
            ("network_flow", "logs-network_traffic.flow-*"),
            ("http_events", "logs-network_traffic.http-*"),
            ("tls_events", "logs-network_traffic.tls-*"),
            ("aws_cloudtrail", "logs-aws.cloudtrail-*"),
            ("azure_signin", "logs-azure.signinlogs-*"),
            ("azure_audit", "logs-azure.auditlogs-*"),
            ("gcp_audit", "logs-gcp.audit-*"),
            ("threat_intel", "logs-ti_util.logs-*"),
            # Beat indices
            ("auditbeat", "auditbeat-*"),
            ("packetbeat", "packetbeat-*"),
            ("filebeat", "filebeat-*"),
            # Attack Discovery
            ("attack_discovery", ".ai-attack-discovery-*"),
        ]

        for name, pattern in delete_patterns:
            results[name] = {"success": False, "deleted_count": 0}

            logger.info(f"Deleting from {pattern}...")
            url = f"{self.base_url}/{pattern}/_delete_by_query"
            payload = {"query": {"match_all": {}}}

            try:
                response = requests.post(
                    url,
                    auth=(self.username, self.password),
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    verify=True,
                    params={"refresh": "true"},
                    timeout=60,
                )

                if response.status_code in [200, 201]:
                    result = response.json()
                    deleted_count = result.get("deleted", 0)
                    results[name]["success"] = True
                    results[name]["deleted_count"] = deleted_count
                    if deleted_count > 0:
                        logger.info(f"Deleted {deleted_count} documents from {pattern}")
                elif response.status_code == 404:
                    logger.debug(f"Index {pattern} does not exist (skipping)")
                else:
                    logger.error(
                        f"Failed to delete from {pattern}: "
                        f"{response.status_code} - {response.text}"
                    )
            except Exception as e:
                logger.error(f"Error deleting from {pattern}: {e}", exc_info=True)

        total_deleted = sum(r["deleted_count"] for r in results.values())
        logger.info(f"Total documents deleted: {total_deleted}")
        return results
