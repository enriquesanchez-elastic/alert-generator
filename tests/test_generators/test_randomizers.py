"""Tests for RandomDataGenerator."""

import re
import uuid

from alerts_generator.generators.randomizers import RandomDataGenerator


def test_generate_uuid_returns_valid_uuid_format():
    """Test that generate_uuid() returns valid UUID format."""
    generator = RandomDataGenerator()
    result = generator.generate_uuid()
    # Should be able to parse as UUID
    parsed = uuid.UUID(result)
    assert str(parsed) == result


def test_generate_entity_id_returns_10_character_string():
    """Test that generate_entity_id() returns 10-character string."""
    generator = RandomDataGenerator()
    result = generator.generate_entity_id()
    assert len(result) == 10
    assert isinstance(result, str)


def test_generate_hostname_returns_expected_format():
    """Test that generate_hostname() returns expected format (prefix-suffix)."""
    generator = RandomDataGenerator()
    result = generator.generate_hostname()
    # Should match pattern like "web-server-01" or "file-server-57"
    # Prefix can have hyphens (like "web-server"), suffix is 2 digits
    pattern = re.compile(r"^[\w-]+-\d{2}$")
    assert pattern.match(result) is not None
    # Should have a known prefix (split on last hyphen)
    parts = result.rsplit("-", 1)
    assert parts[0] in RandomDataGenerator.HOSTNAME_PREFIXES


def test_generate_ip_returns_valid_private_ip_addresses():
    """Test that generate_ip() returns valid private IP addresses."""
    generator = RandomDataGenerator()
    for _ in range(10):  # Test multiple times
        ip = generator.generate_ip()
        # Should be one of private IP ranges
        parts = ip.split(".")
        assert len(parts) == 4
        first_octet = int(parts[0])
        second_octet = int(parts[1])

        # 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16
        assert (
            (first_octet == 10)
            or (first_octet == 172 and 16 <= second_octet <= 31)
            or (first_octet == 192 and second_octet == 168)
        )


def test_generate_mac_returns_valid_mac_format():
    """Test that generate_mac() returns valid MAC format (XX:XX:XX:XX:XX:XX)."""
    generator = RandomDataGenerator()
    result = generator.generate_mac()
    # Should match MAC format: XX:XX:XX:XX:XX:XX
    pattern = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
    assert pattern.match(result) is not None


def test_generate_hash_md5_returns_correct_length():
    """Test that generate_hash('md5') returns correct length."""
    generator = RandomDataGenerator()
    result = generator.generate_hash("md5")
    # MD5 should be 32 hex characters (16 bytes)
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result.lower())


def test_generate_hash_sha1_returns_correct_length():
    """Test that generate_hash('sha1') returns correct length."""
    generator = RandomDataGenerator()
    result = generator.generate_hash("sha1")
    # SHA1 should be 40 hex characters (20 bytes)
    assert len(result) == 40
    assert all(c in "0123456789abcdef" for c in result.lower())


def test_generate_hash_sha256_returns_correct_length():
    """Test that generate_hash('sha256') returns correct length."""
    generator = RandomDataGenerator()
    result = generator.generate_hash("sha256")
    # SHA256 should be 64 hex characters (32 bytes)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result.lower())


def test_generate_username_returns_value_from_usernames_list():
    """Test that generate_username() returns value from USERNAMES list."""
    generator = RandomDataGenerator()
    result = generator.generate_username()
    assert result in RandomDataGenerator.USERNAMES


def test_severity_to_risk_score_maps_correctly():
    """Test that severity_to_risk_score() maps correctly."""
    generator = RandomDataGenerator()

    assert generator.severity_to_risk_score("low") == 21
    assert generator.severity_to_risk_score("medium") == 47
    assert generator.severity_to_risk_score("high") == 73
    assert generator.severity_to_risk_score("critical") == 99


def test_severity_to_risk_score_case_insensitive():
    """Test that severity_to_risk_score() is case insensitive."""
    generator = RandomDataGenerator()

    assert generator.severity_to_risk_score("LOW") == 21
    assert generator.severity_to_risk_score("Medium") == 47
    assert generator.severity_to_risk_score("HIGH") == 73
    assert generator.severity_to_risk_score("Critical") == 99


def test_severity_to_risk_score_unknown_defaults_to_47():
    """Test that unknown severity defaults to 47."""
    generator = RandomDataGenerator()
    result = generator.severity_to_risk_score("unknown")
    assert result == 47
