"""Tests for Campaign model."""

import pytest

from alerts_generator.models.campaign import Campaign


def test_campaign_creation_succeeds(sample_campaign):
    """Test that valid campaign creation works."""
    assert sample_campaign.id == "test1234"
    assert sample_campaign.attacker_ip == "203.0.113.42"
    assert sample_campaign.c2_domain == "evil-c2.badactor.com"
    assert sample_campaign.c2_ip == "198.51.100.15"
    assert sample_campaign.malware_family == "RedTeam-Ransomware"
    assert len(sample_campaign.target_hosts) == 3
    assert sample_campaign.file_hash_base == "abc123def456"


def test_campaign_empty_id_raises_value_error():
    """Test that empty ID raises ValueError."""
    with pytest.raises(ValueError, match="Campaign ID cannot be empty"):
        Campaign(
            id="",
            attacker_ip="203.0.113.1",
            c2_domain="evil.com",
            c2_ip="198.51.100.1",
            malware_family="Test",
            target_hosts=["host1"],
            file_hash_base="abc",
        )


def test_campaign_empty_attacker_ip_raises_value_error():
    """Test that empty attacker_ip raises ValueError."""
    with pytest.raises(ValueError, match="Attacker IP cannot be empty"):
        Campaign(
            id="test1234",
            attacker_ip="",
            c2_domain="evil.com",
            c2_ip="198.51.100.1",
            malware_family="Test",
            target_hosts=["host1"],
            file_hash_base="abc",
        )


def test_campaign_empty_target_hosts_raises_value_error():
    """Test that empty target_hosts raises ValueError."""
    with pytest.raises(ValueError, match="Campaign must have at least one target host"):
        Campaign(
            id="test1234",
            attacker_ip="203.0.113.1",
            c2_domain="evil.com",
            c2_ip="198.51.100.1",
            malware_family="Test",
            target_hosts=[],
            file_hash_base="abc",
        )


def test_campaign_with_multiple_hosts():
    """Test campaign with multiple target hosts."""
    hosts = ["host1", "host2", "host3", "host4", "host5"]
    campaign = Campaign(
        id="test",
        attacker_ip="203.0.113.1",
        c2_domain="evil.com",
        c2_ip="198.51.100.1",
        malware_family="Test",
        target_hosts=hosts,
        file_hash_base="abc",
    )
    assert len(campaign.target_hosts) == 5
    assert campaign.target_hosts == hosts
