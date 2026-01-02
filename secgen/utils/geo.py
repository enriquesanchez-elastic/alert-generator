"""Geo-enrichment utilities for generating realistic location data."""

import random
from typing import Any

# Comprehensive geo database for realistic location generation
GEO_DATABASE = [
    # United States
    {
        "country_name": "United States",
        "country_iso_code": "US",
        "region_name": "Washington",
        "city_name": "Seattle",
        "location": {"lat": 47.6062, "lon": -122.3321},
        "timezone": "America/Los_Angeles",
        "as_org": "Amazon.com, Inc.",
    },
    {
        "country_name": "United States",
        "country_iso_code": "US",
        "region_name": "California",
        "city_name": "San Francisco",
        "location": {"lat": 37.7749, "lon": -122.4194},
        "timezone": "America/Los_Angeles",
        "as_org": "Google LLC",
    },
    {
        "country_name": "United States",
        "country_iso_code": "US",
        "region_name": "Virginia",
        "city_name": "Ashburn",
        "location": {"lat": 39.0437, "lon": -77.4875},
        "timezone": "America/New_York",
        "as_org": "Amazon.com, Inc.",
    },
    {
        "country_name": "United States",
        "country_iso_code": "US",
        "region_name": "New York",
        "city_name": "New York City",
        "location": {"lat": 40.7128, "lon": -74.0060},
        "timezone": "America/New_York",
        "as_org": "Verizon Communications",
    },
    {
        "country_name": "United States",
        "country_iso_code": "US",
        "region_name": "Texas",
        "city_name": "Dallas",
        "location": {"lat": 32.7767, "lon": -96.7970},
        "timezone": "America/Chicago",
        "as_org": "AT&T Services, Inc.",
    },
    # Europe
    {
        "country_name": "United Kingdom",
        "country_iso_code": "GB",
        "region_name": "England",
        "city_name": "London",
        "location": {"lat": 51.5074, "lon": -0.1278},
        "timezone": "Europe/London",
        "as_org": "British Telecommunications PLC",
    },
    {
        "country_name": "Germany",
        "country_iso_code": "DE",
        "region_name": "Hesse",
        "city_name": "Frankfurt",
        "location": {"lat": 50.1109, "lon": 8.6821},
        "timezone": "Europe/Berlin",
        "as_org": "Deutsche Telekom AG",
    },
    {
        "country_name": "Netherlands",
        "country_iso_code": "NL",
        "region_name": "North Holland",
        "city_name": "Amsterdam",
        "location": {"lat": 52.3676, "lon": 4.9041},
        "timezone": "Europe/Amsterdam",
        "as_org": "Microsoft Corporation",
    },
    {
        "country_name": "France",
        "country_iso_code": "FR",
        "region_name": "Île-de-France",
        "city_name": "Paris",
        "location": {"lat": 48.8566, "lon": 2.3522},
        "timezone": "Europe/Paris",
        "as_org": "Orange S.A.",
    },
    # Asia Pacific
    {
        "country_name": "Japan",
        "country_iso_code": "JP",
        "region_name": "Tokyo",
        "city_name": "Tokyo",
        "location": {"lat": 35.6762, "lon": 139.6503},
        "timezone": "Asia/Tokyo",
        "as_org": "NTT Communications Corporation",
    },
    {
        "country_name": "Singapore",
        "country_iso_code": "SG",
        "region_name": "Singapore",
        "city_name": "Singapore",
        "location": {"lat": 1.3521, "lon": 103.8198},
        "timezone": "Asia/Singapore",
        "as_org": "Amazon.com, Inc.",
    },
    {
        "country_name": "Australia",
        "country_iso_code": "AU",
        "region_name": "New South Wales",
        "city_name": "Sydney",
        "location": {"lat": -33.8688, "lon": 151.2093},
        "timezone": "Australia/Sydney",
        "as_org": "Telstra Corporation Ltd",
    },
    # Suspicious locations (for malicious activity)
    {
        "country_name": "Russia",
        "country_iso_code": "RU",
        "region_name": "Moscow",
        "city_name": "Moscow",
        "location": {"lat": 55.7558, "lon": 37.6173},
        "timezone": "Europe/Moscow",
        "as_org": "PJSC Rostelecom",
    },
    {
        "country_name": "China",
        "country_iso_code": "CN",
        "region_name": "Beijing",
        "city_name": "Beijing",
        "location": {"lat": 39.9042, "lon": 116.4074},
        "timezone": "Asia/Shanghai",
        "as_org": "China Telecom",
    },
    {
        "country_name": "North Korea",
        "country_iso_code": "KP",
        "region_name": "Pyongyang",
        "city_name": "Pyongyang",
        "location": {"lat": 39.0392, "lon": 125.7625},
        "timezone": "Asia/Pyongyang",
        "as_org": "Star Joint Venture Co.",
    },
    {
        "country_name": "Iran",
        "country_iso_code": "IR",
        "region_name": "Tehran",
        "city_name": "Tehran",
        "location": {"lat": 35.6892, "lon": 51.3890},
        "timezone": "Asia/Tehran",
        "as_org": "Telecommunication Company of Iran",
    },
]

# Countries commonly associated with threat actors
SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP", "IR", "BY"]

# Corporate HQ locations
CORPORATE_LOCATIONS = [
    loc
    for loc in GEO_DATABASE
    if loc["country_iso_code"] in ["US", "GB", "DE", "NL", "JP", "SG", "AU", "FR"]
]


def get_random_geo(is_malicious: bool = False) -> dict[str, Any]:
    """
    Get a random geo location.

    Args:
        is_malicious: If True, prefer suspicious locations

    Returns:
        Geo location dictionary with ECS-compliant fields
    """
    if is_malicious and random.random() < 0.7:
        # 70% chance of suspicious location for malicious events
        suspicious_locs = [
            loc for loc in GEO_DATABASE if loc["country_iso_code"] in SUSPICIOUS_COUNTRIES
        ]
        geo = random.choice(suspicious_locs) if suspicious_locs else random.choice(GEO_DATABASE)
    else:
        geo = random.choice(CORPORATE_LOCATIONS)

    return _format_geo(geo)


def get_geo_by_country(country_code: str) -> dict[str, Any] | None:
    """
    Get geo location for a specific country.

    Args:
        country_code: ISO country code (e.g., "US", "GB")

    Returns:
        Geo location dictionary or None if not found
    """
    matching = [loc for loc in GEO_DATABASE if loc["country_iso_code"] == country_code.upper()]
    if matching:
        return _format_geo(random.choice(matching))
    return None


def get_impossible_travel_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Get two geographically distant locations for impossible travel detection.

    Returns:
        Tuple of two distant geo locations
    """
    # Pick locations from different continents
    us_locations = [loc for loc in GEO_DATABASE if loc["country_iso_code"] == "US"]
    asia_locations = [loc for loc in GEO_DATABASE if loc["country_iso_code"] in ["JP", "SG", "AU"]]
    europe_locations = [
        loc for loc in GEO_DATABASE if loc["country_iso_code"] in ["GB", "DE", "NL", "FR"]
    ]

    # Randomly select two locations from different continents
    first_continent = random.choice([us_locations, europe_locations, asia_locations])
    remaining = [us_locations, europe_locations, asia_locations]
    remaining.remove(first_continent)
    second_continent = random.choice(remaining)

    first = _format_geo(random.choice(first_continent))
    second = _format_geo(random.choice(second_continent))

    return (first, second)


def calculate_distance_km(geo1: dict[str, Any], geo2: dict[str, Any]) -> float:
    """
    Calculate approximate distance between two geo locations.

    Args:
        geo1: First geo location
        geo2: Second geo location

    Returns:
        Distance in kilometers (approximate)
    """
    import math

    lat1 = geo1.get("location", {}).get("lat", 0)
    lon1 = geo1.get("location", {}).get("lon", 0)
    lat2 = geo2.get("location", {}).get("lat", 0)
    lon2 = geo2.get("location", {}).get("lon", 0)

    # Haversine formula (simplified)
    R = 6371  # Earth's radius in km

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def _format_geo(geo_data: dict[str, Any]) -> dict[str, Any]:
    """Format geo data into ECS-compliant structure."""
    return {
        "country_name": geo_data["country_name"],
        "country_iso_code": geo_data["country_iso_code"],
        "region_name": geo_data["region_name"],
        "city_name": geo_data["city_name"],
        "location": geo_data["location"],  # geo_point format
        "timezone": geo_data.get("timezone"),
    }


def get_as_info(geo_data: dict[str, Any]) -> dict[str, Any]:
    """
    Get AS (Autonomous System) info for a geo location.

    Args:
        geo_data: Geo location with as_org field

    Returns:
        AS information dictionary
    """
    return {
        "organization": {
            "name": geo_data.get("as_org", "Unknown ISP"),
        },
    }

