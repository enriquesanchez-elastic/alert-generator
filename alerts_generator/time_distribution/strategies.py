"""Time distribution strategy implementations."""

import random
from datetime import datetime, timedelta, timezone

from alerts_generator.time_distribution.base import TimeDistributionStrategy


class BasicTimeStrategy(TimeDistributionStrategy):
    """Basic linear time distribution strategy."""

    def __init__(self, max_offset_minutes: int, jitter: float = 0.1) -> None:
        """
        Initialize basic time strategy.

        Args:
            max_offset_minutes: Maximum offset in minutes
            jitter: Randomness factor (0.0 to 1.0)
        """
        self.max_offset_minutes = max_offset_minutes
        self.jitter = jitter

    def calculate_offset(self, index: int, total: int) -> int:
        """Calculate timestamp offset with linear distribution."""
        if total <= 1:
            return 0

        # Calculate base offset (linear distribution)
        base_offset = int((index / (total - 1)) * self.max_offset_minutes)

        # Add jitter (±jitter% of range)
        jitter_range = int(self.max_offset_minutes * self.jitter)
        jitter = random.randint(-jitter_range, jitter_range)
        offset = max(0, base_offset + jitter)

        return offset


class MinutesStrategy(BasicTimeStrategy):
    """Distribute alerts over the last hour."""

    def __init__(self) -> None:
        """Initialize minutes strategy (last 60 minutes)."""
        super().__init__(max_offset_minutes=60, jitter=0.1)


class HoursStrategy(BasicTimeStrategy):
    """Distribute alerts over the last 24 hours."""

    def __init__(self) -> None:
        """Initialize hours strategy (last 24 hours)."""
        super().__init__(max_offset_minutes=24 * 60, jitter=0.1)


class DaysStrategy(BasicTimeStrategy):
    """Distribute alerts over the last 7 days."""

    def __init__(self) -> None:
        """Initialize days strategy (last 7 days)."""
        super().__init__(max_offset_minutes=7 * 24 * 60, jitter=0.1)


class WeeksStrategy(BasicTimeStrategy):
    """Distribute alerts over the last 30 days."""

    def __init__(self) -> None:
        """Initialize weeks strategy (last 30 days)."""
        super().__init__(max_offset_minutes=30 * 24 * 60, jitter=0.1)


class BusinessHoursStrategy(TimeDistributionStrategy):
    """
    Time distribution strategy that weights alerts toward business hours.

    Adjusts timestamps to favor:
    - Weekdays (not weekends)
    - Business hours (8am-6pm)
    """

    def __init__(
        self,
        base_strategy: TimeDistributionStrategy,
        start_hour: int = 8,
        end_hour: int = 18,
    ) -> None:
        """
        Initialize business hours strategy.

        Args:
            base_strategy: Base strategy to wrap
            start_hour: Start of business hours (default: 8)
            end_hour: End of business hours (default: 18)
        """
        self.base_strategy = base_strategy
        self.start_hour = start_hour
        self.end_hour = end_hour

    def calculate_offset(self, index: int, total: int) -> int:
        """Calculate offset with business hours weighting."""
        # Get base offset from wrapped strategy
        base_offset = self.base_strategy.calculate_offset(index, total)

        # Calculate the target timestamp
        target_time = datetime.now(timezone.utc) - timedelta(minutes=base_offset)

        # Check if it's a weekend (Saturday=5, Sunday=6)
        if target_time.weekday() >= 5:
            # Move to Friday
            days_to_subtract = target_time.weekday() - 4
            target_time -= timedelta(days=days_to_subtract)

        # Check if it's outside business hours
        hour = target_time.hour
        if hour < self.start_hour:
            # Move to morning hours
            target_time = target_time.replace(
                hour=random.randint(self.start_hour, self.start_hour + 4)
            )
        elif hour >= self.end_hour:
            # Move to afternoon hours
            target_time = target_time.replace(
                hour=random.randint(self.end_hour - 5, self.end_hour - 1)
            )

        # Recalculate offset
        new_offset = int((datetime.now(timezone.utc) - target_time).total_seconds() / 60)
        return max(0, new_offset)


def get_strategy(spread_type: str, working_hours: bool = False) -> TimeDistributionStrategy:
    """
    Get a time distribution strategy.

    Args:
        spread_type: Type of spread (minutes, hours, days, weeks)
        working_hours: If True, wrap with business hours weighting

    Returns:
        TimeDistributionStrategy instance
    """
    # Create base strategy
    if spread_type == "minutes":
        base_strategy: TimeDistributionStrategy = MinutesStrategy()
    elif spread_type == "hours":
        base_strategy = HoursStrategy()
    elif spread_type == "days":
        base_strategy = DaysStrategy()
    elif spread_type == "weeks":
        base_strategy = WeeksStrategy()
    else:
        # Default to minutes
        base_strategy = MinutesStrategy()

    # Wrap with business hours if requested
    if working_hours:
        return BusinessHoursStrategy(base_strategy)

    return base_strategy


# Campaign phase time distribution
def get_campaign_phase_offset(phase: str, attack_speed: str = "medium") -> tuple[int, int]:
    """
    Get the time offset range for a campaign phase based on attack speed.

    Args:
        phase: Attack phase ('initial', 'execution', 'lateral', 'exfiltration')
        attack_speed: 'fast', 'medium', or 'slow'

    Returns:
        Tuple of (min_offset, max_offset) in minutes
    """
    speed_configs = {
        "fast": {  # Minutes to hours
            "initial": (50, 60),  # 50-60 min ago
            "execution": (30, 50),  # 30-50 min ago
            "lateral": (10, 30),  # 10-30 min ago
            "exfiltration": (0, 10),  # 0-10 min ago
        },
        "medium": {  # Hours to half day
            "initial": (480, 720),  # 8-12 hours ago
            "execution": (240, 480),  # 4-8 hours ago
            "lateral": (60, 240),  # 1-4 hours ago
            "exfiltration": (0, 60),  # 0-1 hour ago
        },
        "slow": {  # Days to weeks
            "initial": (10080, 20160),  # 7-14 days ago
            "execution": (5040, 10080),  # 3.5-7 days ago
            "lateral": (1440, 5040),  # 1-3.5 days ago
            "exfiltration": (0, 1440),  # 0-1 day ago
        },
    }

    return speed_configs.get(attack_speed, speed_configs["medium"]).get(phase, (0, 60))
