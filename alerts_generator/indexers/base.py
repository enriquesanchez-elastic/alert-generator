"""Abstract base class for indexers."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseIndexer(ABC):
    """Abstract base class for all indexers."""

    @abstractmethod
    def index_alert(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        self, events: List[Dict[str, Any]], endpoint_alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
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
    def delete_all(self) -> Dict[str, Any]:
        """
        Delete all indexed data.

        Returns:
            Dictionary with deletion results
        """
        pass
