"""Base interface for time distribution strategies."""

from abc import ABC, abstractmethod


class TimeDistributionStrategy(ABC):
    """Abstract base class for time distribution strategies."""

    @abstractmethod
    def calculate_offset(self, index: int, total: int) -> int:
        """
        Calculate timestamp offset in minutes.

        Args:
            index: Current alert index (0 to total-1)
            total: Total number of alerts

        Returns:
            Offset in minutes from now (going backwards in time)
        """
        pass
