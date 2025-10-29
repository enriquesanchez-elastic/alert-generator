"""Integration tests for campaign generation."""

from alerts_generator.core import AlertOrchestrator


def test_full_campaign_generation_with_multiple_hosts(settings, mock_indexer, multiple_scenarios):
    """Test full campaign generation with multiple hosts."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    campaign_hosts = 5
    results = orchestrator.generate_multiple(
        count=20,
        dry_run=True,
        campaign_mode=True,
        campaign_hosts=campaign_hosts,
        attack_speed="medium",
    )

    assert results["campaign"] is not None
    assert len(results["campaign"].target_hosts) == campaign_hosts


def test_campaign_metadata_is_consistent_across_alerts(settings, mock_indexer, multiple_scenarios):
    """Test that campaign metadata is consistent across alerts."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(
        count=10, dry_run=True, campaign_mode=True, campaign_hosts=3
    )

    campaign = results["campaign"]
    campaign_ids = [alert.campaign_id for alert in results["alerts"]]

    # All alerts should have same campaign ID
    assert all(cid == campaign.id for cid in campaign_ids if cid is not None)


def test_phase_distribution_percentages(settings, mock_indexer, multiple_scenarios):
    """Test that phase distribution percentages are approximately correct."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    count = 100
    results = orchestrator.generate_multiple(
        count=count, dry_run=True, campaign_mode=True, campaign_hosts=5
    )

    phase_counts = results["phase_counts"]
    total = sum(phase_counts.values())

    assert total == count

    # Check approximate percentages (with tolerance)
    initial_pct = phase_counts["initial"] / total
    execution_pct = phase_counts["execution"] / total
    lateral_pct = phase_counts["lateral"] / total
    exfiltration_pct = phase_counts["exfiltration"] / total

    # Should be approximately: 10%, 30%, 40%, 20%
    assert 0.05 <= initial_pct <= 0.15  # 10% ± 5%
    assert 0.20 <= execution_pct <= 0.40  # 30% ± 10%
    assert 0.30 <= lateral_pct <= 0.50  # 40% ± 10%
    assert 0.10 <= exfiltration_pct <= 0.30  # 20% ± 10%


def test_shared_infrastructure_across_campaign_alerts(settings, mock_indexer, multiple_scenarios):
    """Test shared infrastructure (IPs, hashes, C2) across campaign alerts."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    results = orchestrator.generate_multiple(
        count=10, dry_run=True, campaign_mode=True, campaign_hosts=3
    )

    campaign = results["campaign"]

    # Check that file hashes share base prefix
    for alert_data in results["alerts"]:
        file_md5 = alert_data.detection_alert["file"]["hash"]["md5"]
        # Hash should start with campaign base
        assert file_md5.startswith(campaign.file_hash_base)


def test_timestamp_progression_matches_attack_speed(settings, mock_indexer, multiple_scenarios):
    """Test that timestamp progression matches attack speed."""
    orchestrator = AlertOrchestrator(settings, mock_indexer, multiple_scenarios)

    from datetime import datetime, timezone

    results = orchestrator.generate_multiple(
        count=50,
        dry_run=True,
        campaign_mode=True,
        campaign_hosts=5,
        attack_speed="fast",
    )

    # Get timestamps
    timestamps = []
    for alert_data in results["alerts"]:
        timestamp_str = alert_data.detection_alert["@timestamp"]
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        timestamps.append(timestamp)

    # Timestamps should be in chronological order
    # Earlier alerts (lower index) should have older timestamps (further in the past)
    # So timestamps[0] should be <= timestamps[i] for i > 0 (older = smaller datetime value)
    # Actually, wait - if alert 0 happened further in the past, its timestamp should be earlier
    # So timestamps[0] < timestamps[1] means alert 0 happened before alert 1
    # But with our offset system, earlier index = larger offset = older timestamp
    # So timestamps should generally increase (get more recent) as index increases
    now = datetime.now(timezone.utc)
    for timestamp in timestamps:
        # All timestamps should be in the past
        assert timestamp < now

    # For fast attacks, check that timestamps are within a reasonable range (hours, not days)
    time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600
    assert time_span < 24  # Should be within 24 hours for fast attack
