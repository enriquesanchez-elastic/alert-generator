"""Abstract base class for indexers."""

from abc import ABC, abstractmethod
from typing import Any


class BaseIndexer(ABC):
    """Abstract base class for all indexers."""

    @abstractmethod
    def index_alert(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """
        Index a detection rule alert.

        Args:
            alert: Alert dictionary to index

        Returns:
            Index response or None on failure
        """
        pass

    @abstractmethod
    def index_events(
        self, events: list[dict[str, Any]], endpoint_alert: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Index process events and endpoint alert.

        Args:
            events: List of process event dictionaries
            endpoint_alert: Endpoint alert dictionary

        Returns:
            Bulk index response or None on failure
        """
        pass

    @abstractmethod
    def delete_all(self) -> dict[str, Any]:
        """
        Delete all indexed data.

        Returns:
            Dictionary with deletion results
        """
        pass
