"""Elasticsearch indexer implementation."""

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from alerts_generator.config.settings import Settings
from alerts_generator.indexers.base import BaseIndexer

logger = logging.getLogger(__name__)


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

    def index_alert(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        self, events: List[Dict[str, Any]], endpoint_alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
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
            bulk_body += (
                json.dumps({"create": {"_index": "logs-endpoint.events.process-default"}}) + "\n"
            )
            bulk_body += json.dumps(event) + "\n"

        # Add endpoint alert
        bulk_body += json.dumps({"create": {"_index": "logs-endpoint.alerts-default"}}) + "\n"
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

    def delete_all(self) -> Dict[str, Any]:
        """
        Delete all data from Elasticsearch indices.

        Returns:
            Dictionary with deletion results
        """
        results = {
            "alerts_index": {"success": False, "deleted_count": 0},
            "process_events": {"success": False, "deleted_count": 0},
            "endpoint_alerts": {"success": False, "deleted_count": 0},
        }

        # Delete from Kibana alerts index
        logger.info(f"Deleting from {self.alerts_index}...")
        url = f"{self.base_url}/{self.alerts_index}/_delete_by_query"
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
                results["alerts_index"]["success"] = True
                results["alerts_index"]["deleted_count"] = deleted_count
                logger.info(f"Deleted {deleted_count} documents from {self.alerts_index}")
            elif response.status_code == 404:
                logger.warning(f"Index {self.alerts_index} does not exist (skipping)")
            else:
                logger.error(
                    f"Failed to delete from {self.alerts_index}: "
                    f"{response.status_code} - {response.text}"
                )
        except Exception as e:
            logger.error(f"Error deleting from {self.alerts_index}: {e}", exc_info=True)

        # Delete from process events indices
        logger.info("Deleting from logs-endpoint.events.process-*...")
        url = f"{self.base_url}/logs-endpoint.events.process-*/_delete_by_query"
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
                results["process_events"]["success"] = True
                results["process_events"]["deleted_count"] = deleted_count
                logger.info(f"Deleted {deleted_count} documents from process events indices")
            elif response.status_code == 404:
                logger.warning("No process events indices found (skipping)")
            else:
                logger.error(
                    f"Failed to delete process events: " f"{response.status_code} - {response.text}"
                )
        except Exception as e:
            logger.error(f"Error deleting process events: {e}", exc_info=True)

        # Delete from endpoint alerts indices
        logger.info("Deleting from logs-endpoint.alerts-*...")
        url = f"{self.base_url}/logs-endpoint.alerts-*/_delete_by_query"
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
                results["endpoint_alerts"]["success"] = True
                results["endpoint_alerts"]["deleted_count"] = deleted_count
                logger.info(f"Deleted {deleted_count} documents from endpoint alerts indices")
            elif response.status_code == 404:
                logger.warning("No endpoint alerts indices found (skipping)")
            else:
                logger.error(
                    f"Failed to delete endpoint alerts: "
                    f"{response.status_code} - {response.text}"
                )
        except Exception as e:
            logger.error(f"Error deleting endpoint alerts: {e}", exc_info=True)

        total_deleted = (
            results["alerts_index"]["deleted_count"]
            + results["process_events"]["deleted_count"]
            + results["endpoint_alerts"]["deleted_count"]
        )

        logger.info(f"Total documents deleted: {total_deleted}")
        return results
