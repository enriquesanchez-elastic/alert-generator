"""Base class for Beat-format event generators."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

BeatType = Literal["auditbeat", "packetbeat", "filebeat"]


class BeatEventGenerator(ABC):
    """
    Abstract base class for Beat-format event generators.

    Beats are lightweight data shippers from Elastic that send data to
    Elasticsearch. Each Beat type has specific metadata fields and index patterns.

    This base class provides:
    - Common Beat metadata fields (agent.type, agent.version, ecs.version)
    - Beat-specific index pattern mapping
    - Shared timestamp and host handling
    """

    # Beat versions and metadata
    BEAT_VERSIONS = {
        "auditbeat": "8.17.0",
        "packetbeat": "8.17.0",
        "filebeat": "8.17.0",
    }

    ECS_VERSION = "8.11.0"

    # Index patterns for each beat type
    INDEX_PATTERNS = {
        "auditbeat": "auditbeat-{version}-{date}",
        "packetbeat": "packetbeat-{version}-{date}",
        "filebeat": "filebeat-{version}-{date}",
    }

    def __init__(
        self,
        beat_type: BeatType,
        randomizer: RandomDataGenerator | None = None,
    ) -> None:
        """
        Initialize Beat event generator.

        Args:
            beat_type: Type of Beat (auditbeat, packetbeat, filebeat)
            randomizer: Optional RandomDataGenerator instance
        """
        self.beat_type = beat_type
        self.randomizer = randomizer or RandomDataGenerator()
        self.beat_version = self.BEAT_VERSIONS[beat_type]

    def _build_base_event(
        self,
        timestamp: datetime | None = None,
        host: Optional["Host"] = None,
        dataset: str | None = None,
    ) -> dict[str, Any]:
        """
        Build the base event structure common to all Beat events.

        Args:
            timestamp: Event timestamp (defaults to now)
            host: Optional Host entity for proper correlation
            dataset: Dataset name for data_stream field (e.g., "auditd.log")

        Returns:
            Base event dictionary with Beat metadata
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # Generate Beat UUID for this event
        beat_id = self.randomizer.generate_uuid()

        event: dict[str, Any] = {
            "@timestamp": timestamp.isoformat(),
            "agent": {
                "type": self.beat_type,
                "version": self.beat_version,
                "name": host.name if host else self.randomizer.generate_hostname(),
                "id": host.agent_id if host else self.randomizer.generate_uuid(),
                "ephemeral_id": self.randomizer.generate_uuid(),
            },
            "ecs": {"version": self.ECS_VERSION},
        }

        # Add data_stream field for proper indexing and categorization
        if dataset:
            event["data_stream"] = {
                "type": "logs",
                "dataset": dataset,
                "namespace": "default",
            }

        # Add host information
        if host:
            event["host"] = self._build_host_from_entity(host)
        else:
            event["host"] = self._build_random_host()

        return event

    def _build_host_from_entity(self, host: "Host") -> dict[str, Any]:
        """Build host fields from Host entity."""
        return {
            "id": host.id,
            "name": host.name,
            "hostname": host.name,
            "ip": host.ip,
            "mac": host.mac,
            "architecture": host.architecture,
            "os": {
                "family": host.os.family,
                "name": host.os.name,
                "platform": host.os.platform,
                "type": host.os.type,
                "version": host.os.version,
                "kernel": host.os.kernel,
            },
        }

    def _build_random_host(self) -> dict[str, Any]:
        """Build random host fields."""
        hostname = self.randomizer.generate_hostname()
        return {
            "id": self.randomizer.generate_uuid(),
            "name": hostname,
            "hostname": hostname,
            "ip": [self.randomizer.generate_ip()],
            "mac": [self.randomizer.generate_mac()],
            "architecture": "x86_64",
            "os": {
                "family": "linux",
                "name": "Ubuntu",
                "platform": "linux",
                "type": "linux",
                "version": "22.04",
                "kernel": "5.15.0-generic",
            },
        }

    def get_index_pattern(self, date: datetime | None = None) -> str:
        """
        Get the index pattern for this Beat type.

        Args:
            date: Date for the index (defaults to today)

        Returns:
            Index pattern string (e.g., 'auditbeat-8.17.0-2024.01.15')
        """
        if date is None:
            date = datetime.now(timezone.utc)

        date_str = date.strftime("%Y.%m.%d")
        return self.INDEX_PATTERNS[self.beat_type].format(
            version=self.beat_version,
            date=date_str,
        )

    def get_simple_index_pattern(self) -> str:
        """
        Get the simple index pattern for this Beat type.

        Returns:
            Simple index pattern (e.g., 'auditbeat-*')
        """
        return f"{self.beat_type}-*"

    @abstractmethod
    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_offset: int = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a single Beat event.

        Args:
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            timestamp_offset: Minutes to offset timestamp
            **kwargs: Additional generator-specific parameters

        Returns:
            ECS-compliant event dictionary
        """
        pass

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_spread_minutes: int = 60,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of Beat events.

        Args:
            count: Number of events to generate
            host: Optional Host entity for correlation
            user: Optional User entity for correlation
            timestamp_spread_minutes: Time spread for events
            **kwargs: Additional generator-specific parameters

        Returns:
            List of ECS-compliant event dictionaries
        """
        events = []
        for i in range(count):
            offset = int((count - i) * timestamp_spread_minutes / count)
            event = self.generate(
                host=host,
                user=user,
                timestamp_offset=offset,
                **kwargs,
            )
            events.append(event)
        return events

