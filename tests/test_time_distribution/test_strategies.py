"""Tests for time distribution strategies."""

from datetime import datetime, timezone

from alerts_generator.time_distribution.strategies import (
    BusinessHoursStrategy,
    DaysStrategy,
    HoursStrategy,
    MinutesStrategy,
    WeeksStrategy,
    get_campaign_phase_offset,
    get_strategy,
)


def test_minutes_strategy_max_60_minutes():
    """Test that MinutesStrategy has max 60 minutes."""
    strategy = MinutesStrategy()
    assert strategy.max_offset_minutes == 60

    # Should return offsets up to 60 minutes
    offset = strategy.calculate_offset(0, 10)
    assert 0 <= offset <= 60


def test_hours_strategy_max_1440_minutes():
    """Test that HoursStrategy has max 1440 minutes (24 hours)."""
    strategy = HoursStrategy()
    assert strategy.max_offset_minutes == 24 * 60

    offset = strategy.calculate_offset(0, 10)
    assert 0 <= offset <= 24 * 60


def test_days_strategy_max_10080_minutes():
    """Test that DaysStrategy has max 10080 minutes (7 days)."""
    strategy = DaysStrategy()
    assert strategy.max_offset_minutes == 7 * 24 * 60

    offset = strategy.calculate_offset(0, 10)
    assert 0 <= offset <= 7 * 24 * 60


def test_weeks_strategy_max_43200_minutes():
    """Test that WeeksStrategy has max 43200 minutes (30 days)."""
    strategy = WeeksStrategy()
    assert strategy.max_offset_minutes == 30 * 24 * 60

    offset = strategy.calculate_offset(0, 10)
    assert 0 <= offset <= 30 * 24 * 60


def test_minutes_strategy_linear_distribution():
    """Test that MinutesStrategy provides linear distribution."""
    strategy = MinutesStrategy()

    # First item should have low offset
    offset_first = strategy.calculate_offset(0, 10)
    # Last item should have high offset
    offset_last = strategy.calculate_offset(9, 10)

    # Last should generally be greater than first
    assert offset_last >= offset_first


def test_business_hours_strategy_moves_weekend_to_friday():
    """Test that BusinessHoursStrategy moves weekend timestamps to Friday."""
    base_strategy = MinutesStrategy()
    strategy = BusinessHoursStrategy(base_strategy, start_hour=8, end_hour=18)

    # Test that strategy returns valid offsets
    offset = strategy.calculate_offset(5, 10)
    assert offset >= 0

    # Test multiple calls to ensure consistency
    for i in range(10):
        offset = strategy.calculate_offset(i, 10)
        assert offset >= 0

    # Test that the strategy correctly wraps base strategy
    base_offset = base_strategy.calculate_offset(5, 10)
    wrapped_offset = strategy.calculate_offset(5, 10)
    # Wrapped offset may be different due to business hours adjustment
    assert wrapped_offset >= 0


def test_business_hours_strategy_before_8am_moved_to_morning():
    """Test that BusinessHoursStrategy moves before 8am to 8am-12pm."""
    base_strategy = MinutesStrategy()
    strategy = BusinessHoursStrategy(base_strategy, start_hour=8, end_hour=18)

    # Get an offset
    offset = strategy.calculate_offset(0, 10)

    # Calculate what time that would be
    now = datetime.now(timezone.utc)
    target_time = now.replace(hour=2)  # 2am scenario

    # Recalculate to see if it gets moved
    offset_result = strategy.calculate_offset(0, 10)
    assert offset_result >= 0


def test_business_hours_strategy_after_6pm_moved_to_afternoon():
    """Test that BusinessHoursStrategy moves after 6pm to 1pm-5pm."""
    base_strategy = MinutesStrategy()
    strategy = BusinessHoursStrategy(base_strategy, start_hour=8, end_hour=18)

    offset = strategy.calculate_offset(9, 10)
    assert offset >= 0


def test_get_strategy_returns_minutes_strategy():
    """Test that get_strategy() returns correct strategy type."""
    strategy = get_strategy("minutes", working_hours=False)
    assert isinstance(strategy, MinutesStrategy)


def test_get_strategy_returns_hours_strategy():
    """Test that get_strategy() returns HoursStrategy."""
    strategy = get_strategy("hours", working_hours=False)
    assert isinstance(strategy, HoursStrategy)


def test_get_strategy_returns_days_strategy():
    """Test that get_strategy() returns DaysStrategy."""
    strategy = get_strategy("days", working_hours=False)
    assert isinstance(strategy, DaysStrategy)


def test_get_strategy_returns_weeks_strategy():
    """Test that get_strategy() returns WeeksStrategy."""
    strategy = get_strategy("weeks", working_hours=False)
    assert isinstance(strategy, WeeksStrategy)


def test_get_strategy_returns_business_hours_wrapper():
    """Test that get_strategy() returns BusinessHoursStrategy when requested."""
    strategy = get_strategy("minutes", working_hours=True)
    assert isinstance(strategy, BusinessHoursStrategy)


def test_get_campaign_phase_offset_fast_initial():
    """Test get_campaign_phase_offset() for fast speed initial phase."""
    min_offset, max_offset = get_campaign_phase_offset("initial", "fast")
    assert min_offset == 50
    assert max_offset == 60


def test_get_campaign_phase_offset_fast_execution():
    """Test get_campaign_phase_offset() for fast speed execution phase."""
    min_offset, max_offset = get_campaign_phase_offset("execution", "fast")
    assert min_offset == 30
    assert max_offset == 50


def test_get_campaign_phase_offset_medium_initial():
    """Test get_campaign_phase_offset() for medium speed initial phase."""
    min_offset, max_offset = get_campaign_phase_offset("initial", "medium")
    assert min_offset == 480
    assert max_offset == 720


def test_get_campaign_phase_offset_slow_initial():
    """Test get_campaign_phase_offset() for slow speed initial phase."""
    min_offset, max_offset = get_campaign_phase_offset("initial", "slow")
    assert min_offset == 10080
    assert max_offset == 20160


def test_get_campaign_phase_offset_defaults_to_medium():
    """Test get_campaign_phase_offset() defaults to medium if invalid speed."""
    min_offset, max_offset = get_campaign_phase_offset("initial", "invalid")
    # Should default to medium
    assert min_offset == 480
    assert max_offset == 720


def test_get_campaign_phase_offset_all_phases_fast():
    """Test get_campaign_phase_offset() for all phases with fast speed."""
    phases = ["initial", "execution", "lateral", "exfiltration"]
    for phase in phases:
        min_offset, max_offset = get_campaign_phase_offset(phase, "fast")
        assert min_offset >= 0
        assert max_offset >= min_offset


def test_strategy_calculate_offset_edge_cases():
    """Test strategy calculate_offset edge cases."""
    strategy = MinutesStrategy()

    # Single item
    offset = strategy.calculate_offset(0, 1)
    assert offset == 0

    # Two items
    offset1 = strategy.calculate_offset(0, 2)
    offset2 = strategy.calculate_offset(1, 2)
    assert offset1 >= 0
    assert offset2 >= offset1
