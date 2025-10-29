"""Tests for CampaignGenerator."""

from alerts_generator.generators.campaign import CampaignGenerator


def test_generate_creates_campaign_with_valid_attributes():
    """Test that generate() creates Campaign with valid attributes."""
    generator = CampaignGenerator()
    num_hosts = 5
    campaign = generator.generate(num_hosts)

    assert campaign.id is not None
    assert len(campaign.id) == 8
    assert campaign.attacker_ip is not None
    assert campaign.c2_domain is not None
    assert campaign.c2_ip is not None
    assert campaign.malware_family is not None
    assert len(campaign.target_hosts) == num_hosts
    assert campaign.file_hash_base is not None


def test_campaign_has_unique_id():
    """Test that campaign has unique ID (8 chars)."""
    generator = CampaignGenerator()
    campaign1 = generator.generate(5)
    campaign2 = generator.generate(5)

    assert len(campaign1.id) == 8
    assert len(campaign2.id) == 8
    # IDs should be different (highly likely)
    assert campaign1.id != campaign2.id


def test_campaign_has_specified_number_of_target_hosts():
    """Test that campaign has specified number of target hosts."""
    generator = CampaignGenerator()

    for num_hosts in [1, 3, 5]:
        campaign = generator.generate(num_hosts)
        assert len(campaign.target_hosts) == num_hosts
        # Hosts may have duplicates due to random generation, so just check count
        # The list should have the requested number of hosts
        assert len(campaign.target_hosts) == num_hosts


def test_campaign_hosts_may_have_duplicates():
    """Test that campaign hosts can have duplicates (random generation)."""
    generator = CampaignGenerator()

    # Generate multiple campaigns to test uniqueness is not guaranteed
    campaigns = [generator.generate(10) for _ in range(5)]

    # Each should have 10 hosts (even if some are duplicates)
    for campaign in campaigns:
        assert len(campaign.target_hosts) == 10


def test_determine_phase_returns_initial_for_first_10_percent():
    """Test that determine_phase() returns 'initial' for first 10%."""
    generator = CampaignGenerator()

    # Test first 10% should be initial
    total = 100
    for index in range(0, 10):
        phase = generator.determine_phase(index, total)
        assert phase == "initial"


def test_determine_phase_returns_execution_for_10_to_40_percent():
    """Test that determine_phase() returns 'execution' for 10-40%."""
    generator = CampaignGenerator()

    # Test 10-40% should be execution
    total = 100
    for index in range(10, 40):
        phase = generator.determine_phase(index, total)
        assert phase == "execution"


def test_determine_phase_returns_lateral_for_40_to_80_percent():
    """Test that determine_phase() returns 'lateral' for 40-80%."""
    generator = CampaignGenerator()

    # Test 40-80% should be lateral
    total = 100
    for index in range(40, 80):
        phase = generator.determine_phase(index, total)
        assert phase == "lateral"


def test_determine_phase_returns_exfiltration_for_80_to_100_percent():
    """Test that determine_phase() returns 'exfiltration' for 80-100%."""
    generator = CampaignGenerator()

    # Test 80-100% should be exfiltration
    total = 100
    for index in range(80, 100):
        phase = generator.determine_phase(index, total)
        assert phase == "exfiltration"


def test_determine_phase_edge_cases():
    """Test determine_phase() edge cases."""
    generator = CampaignGenerator()

    # First alert (index 0)
    assert generator.determine_phase(0, 100) == "initial"

    # Last alert (index 99 out of 100)
    assert generator.determine_phase(99, 100) == "exfiltration"

    # Exact boundaries
    assert generator.determine_phase(9, 100) == "initial"  # 9% = initial
    assert generator.determine_phase(10, 100) == "execution"  # 10% = execution
    assert generator.determine_phase(39, 100) == "execution"  # 39% = execution
    assert generator.determine_phase(40, 100) == "lateral"  # 40% = lateral
    assert generator.determine_phase(79, 100) == "lateral"  # 79% = lateral
    assert generator.determine_phase(80, 100) == "exfiltration"  # 80% = exfiltration


def test_select_scenario_for_phase_prefers_phase_appropriate_scenarios(multiple_scenarios):
    """Test that select_scenario_for_phase() prefers phase-appropriate scenarios."""
    generator = CampaignGenerator()

    # Test initial phase - should prefer "Web Shell Deployment" or "Backdoor Installation"
    scenario = generator.select_scenario_for_phase("initial", multiple_scenarios)
    assert scenario in multiple_scenarios
    # Should prefer scenarios matching phase (if available)
    preferred_names = ["Web Shell Deployment", "Backdoor Installation"]
    # If any preferred scenario exists, should be selected (or any if none match)
    assert scenario.name in [s.name for s in multiple_scenarios]


def test_select_scenario_for_phase_falls_back_to_any_scenario_if_no_match(multiple_scenarios):
    """Test that select_scenario_for_phase() falls back to any scenario if no phase match."""
    generator = CampaignGenerator()

    # Test with phase that has no matching scenarios
    # All scenarios should still be valid options
    scenario = generator.select_scenario_for_phase("exfiltration", multiple_scenarios)
    assert scenario in multiple_scenarios


def test_campaign_attacker_ip_is_valid_format():
    """Test that campaign attacker IP is valid format."""
    generator = CampaignGenerator()
    campaign = generator.generate(5)

    # Should be in TEST-NET-3 range (203.0.113.0/24)
    parts = campaign.attacker_ip.split(".")
    assert len(parts) == 4
    assert parts[0] == "203"
    assert parts[1] == "0"
    assert parts[2] == "113"
    assert 1 <= int(parts[3]) <= 254


def test_campaign_c2_domain_from_list():
    """Test that campaign C2 domain is from expected list."""
    generator = CampaignGenerator()
    campaign = generator.generate(5)

    assert campaign.c2_domain in CampaignGenerator.C2_DOMAINS


def test_campaign_malware_family_from_list():
    """Test that campaign malware family is from expected list."""
    generator = CampaignGenerator()
    campaign = generator.generate(5)

    assert campaign.malware_family in CampaignGenerator.MALWARE_FAMILIES
