"""Elasticsearch indexer implementation."""

import json
import logging
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
        self.username = settings.elastic_username
        self.password = settings.elastic_password
        self.alerts_index = settings.alerts_index

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

        index_pattern = INDEX_PATTERNS.get(event_type)
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
            index_pattern = INDEX_PATTERNS.get(event_type)
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
