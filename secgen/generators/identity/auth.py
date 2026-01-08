"""Authentication event generator for creating ECS-compliant authentication events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import (
    GeneratorCategory,
    register_attack_pattern,
    register_event_type,
)

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

AuthOutcome = Literal["success", "failure", "unknown"]
AuthMethod = Literal["password", "publickey", "kerberos", "ntlm", "certificate", "mfa", "sso"]


@register_event_type(
    name="authentication",
    category=GeneratorCategory.IDENTITY,
    description="Authentication events for login attempts and identity verification",
    ecs_fields=[
        "event.outcome",
        "user.name",
        "source.ip",
        "source.geo",
        "authentication.method",
    ],
    index_pattern="logs-system.auth-default",
    example_params={"outcome": "failure", "method": "password"},
)
class AuthenticationEventGenerator:
    """
    Generator for creating ECS-compliant authentication events.

    Authentication events are critical for:
    - Entity Analytics risk scoring
    - Brute force detection
    - Impossible travel detection
    - Account compromise detection
    - Privilege escalation detection
    """

    # Failure reasons
    FAILURE_REASONS = [
        "INVALID_CREDENTIALS",
        "ACCOUNT_LOCKED",
        "ACCOUNT_DISABLED",
        "PASSWORD_EXPIRED",
        "MFA_FAILED",
        "MFA_TIMEOUT",
        "CERTIFICATE_EXPIRED",
        "IP_BLOCKED",
        "INVALID_TOKEN",
        "SESSION_EXPIRED",
    ]

    # Geographic locations for impossible travel scenarios
    GEO_LOCATIONS = [
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "city_name": "Seattle",
            "location": {"lat": 47.6062, "lon": -122.3321},
        },
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "city_name": "New York",
            "location": {"lat": 40.7128, "lon": -74.0060},
        },
        {
            "country_name": "United States",
            "country_iso_code": "US",
            "city_name": "San Francisco",
            "location": {"lat": 37.7749, "lon": -122.4194},
        },
        {
            "country_name": "United Kingdom",
            "country_iso_code": "GB",
            "city_name": "London",
            "location": {"lat": 51.5074, "lon": -0.1278},
        },
        {
            "country_name": "Germany",
            "country_iso_code": "DE",
            "city_name": "Berlin",
            "location": {"lat": 52.5200, "lon": 13.4050},
        },
        {
            "country_name": "Japan",
            "country_iso_code": "JP",
            "city_name": "Tokyo",
            "location": {"lat": 35.6762, "lon": 139.6503},
        },
        {
            "country_name": "Australia",
            "country_iso_code": "AU",
            "city_name": "Sydney",
            "location": {"lat": -33.8688, "lon": 151.2093},
        },
        {
            "country_name": "Brazil",
            "country_iso_code": "BR",
            "city_name": "São Paulo",
            "location": {"lat": -23.5505, "lon": -46.6333},
        },
        {
            "country_name": "Russia",
            "country_iso_code": "RU",
            "city_name": "Moscow",
            "location": {"lat": 55.7558, "lon": 37.6173},
        },
        {
            "country_name": "China",
            "country_iso_code": "CN",
            "city_name": "Beijing",
            "location": {"lat": 39.9042, "lon": 116.4074},
        },
    ]

    # Auth providers/applications
    AUTH_PROVIDERS = [
        "ActiveDirectory",
        "AzureAD",
        "Okta",
        "LDAP",
        "RADIUS",
        "Local",
        "SSO",
        "OAuth2",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize authentication event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        outcome: AuthOutcome | None = None,
        method: AuthMethod | None = None,
        user: Optional["User"] = None,
        host: Optional["Host"] = None,
        source_ip: str | None = None,
        source_geo: dict[str, Any] | None = None,
        timestamp_offset: int = 0,
        failure_reason: str | None = None,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single authentication event.

        Args:
            outcome: Authentication outcome (success, failure)
            method: Authentication method
            user: Optional User entity
            host: Optional Host entity (target of authentication)
            source_ip: Source IP address
            source_geo: Source geographic information
            timestamp_offset: Minutes to offset timestamp
            failure_reason: Reason for failure (if outcome is failure)
            provider: Authentication provider

        Returns:
            ECS-compliant authentication event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Set defaults
        if outcome is None:
            outcome = random.choices(["success", "failure"], weights=[0.85, 0.15])[0]
        if method is None:
            method = random.choice(["password", "kerberos", "ntlm", "sso"])
        if provider is None:
            provider = random.choice(self.AUTH_PROVIDERS)

        # Generate source IP if not provided
        if source_ip is None:
            # Mix of internal and external IPs
            if random.random() < 0.7:
                source_ip = self.randomizer.generate_ip()  # Internal
            else:
                source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Generate geo information
        if source_geo is None and random.random() < 0.8:
            source_geo = random.choice(self.GEO_LOCATIONS)

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["authentication"],
                "type": ["start"],
                "action": "user-login",
                "outcome": outcome,
                "provider": provider,
                "id": self.randomizer.generate_uuid(),
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "system.auth",
                "namespace": "default",
            },
        }

        # Add failure reason if applicable
        if outcome == "failure":
            if failure_reason is None:
                failure_reason = random.choice(self.FAILURE_REASONS)
            event["event"]["reason"] = failure_reason

        # Add user information
        if user:
            event["user"] = user.to_ecs_dict()
            event["related"] = {"user": user.to_related_user()}
        else:
            username = self.randomizer.generate_username()
            event["user"] = {
                "name": username,
                "id": str(random.randint(1000, 65000)),
                "domain": "CORPORATE",
            }
            event["related"] = {"user": [username]}

        # Add source information
        event["source"] = {
            "ip": source_ip,
            "port": random.randint(49152, 65535),
        }

        if source_geo:
            event["source"]["geo"] = source_geo

        # Add related IPs
        if "related" not in event:
            event["related"] = {}
        event["related"]["ip"] = [source_ip]

        # Add host (target) information
        if host:
            event["host"] = host.to_ecs_dict()
            event["destination"] = {
                "ip": random.choice(host.ip),
            }
        else:
            hostname = self.randomizer.generate_hostname()
            dest_ip = self.randomizer.generate_ip()
            event["host"] = {
                "name": hostname,
                "hostname": hostname,
            }
            event["destination"] = {
                "ip": dest_ip,
            }
            event["related"]["ip"].append(dest_ip)

        # Add authentication-specific fields
        event["authentication"] = {
            "method": method,
            "provider": provider,
        }

        # Add service information
        event["service"] = {
            "type": "system",
            "name": "sshd" if method == "publickey" else "login",
        }

        return event

    def generate_batch(
        self,
        count: int,
        user: Optional["User"] = None,
        host: Optional["Host"] = None,
        failure_ratio: float = 0.15,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of authentication events.

        Args:
            count: Number of events to generate
            user: Optional User entity (same user for all events)
            host: Optional Host entity
            failure_ratio: Ratio of failed authentication attempts
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of authentication event dictionaries
        """
        events = []

        for i in range(count):
            outcome: AuthOutcome = "failure" if random.random() < failure_ratio else "success"
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                outcome=outcome,
                user=user,
                host=host,
                timestamp_offset=timestamp_offset,
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="brute-force",
        description="Password brute force attack with multiple failed login attempts",
        ttps=["T1110.001", "T1110.003"],
        category=GeneratorCategory.IDENTITY,
        required_params=["target_user", "host", "source_ip"],
        optional_params=["attempts", "success_at_end", "duration_minutes"],
        event_types=["authentication"],
        detection_recommendations=[
            "Multiple failed authentication attempts from same source",
            "Account lockout events",
            "Threshold-based detection rules",
        ],
    )
    def generate_brute_force(
        self,
        target_user: "User",
        host: "Host",
        source_ip: str,
        attempts: int = 50,
        success_at_end: bool = False,
        duration_minutes: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate a brute force authentication attack.

        Args:
            target_user: Target user being attacked
            host: Target host
            source_ip: Attacker source IP
            attempts: Number of failed attempts
            success_at_end: If True, last attempt succeeds
            duration_minutes: Duration of the attack

        Returns:
            List of authentication events representing brute force
        """
        events = []

        # Generate failed attempts
        failure_reasons = ["INVALID_CREDENTIALS"] * (attempts - 1)
        if not success_at_end:
            failure_reasons.append("ACCOUNT_LOCKED")

        for i in range(attempts):
            if i == attempts - 1 and success_at_end:
                outcome: AuthOutcome = "success"
                failure_reason = None
            else:
                outcome = "failure"
                failure_reason = failure_reasons[min(i, len(failure_reasons) - 1)]

            # Spread attempts over duration
            timestamp_offset = int((attempts - i) * (duration_minutes / attempts))

            event = self.generate(
                outcome=outcome,
                method="password",
                user=target_user,
                host=host,
                source_ip=source_ip,
                timestamp_offset=timestamp_offset,
                failure_reason=failure_reason,
            )
            events.append(event)

        return events

    @register_attack_pattern(
        name="impossible-travel",
        description="Impossible travel detection - logins from distant locations in short time",
        ttps=["T1078"],
        category=GeneratorCategory.IDENTITY,
        required_params=["user"],
        optional_params=["first_location", "second_location", "time_gap_minutes"],
        event_types=["authentication"],
        detection_recommendations=[
            "Geographic distance vs time correlation",
            "Unusual login locations",
            "Entity Analytics risk scoring",
        ],
    )
    def generate_impossible_travel(
        self,
        user: "User",
        first_location: dict[str, Any] | None = None,
        second_location: dict[str, Any] | None = None,
        time_gap_minutes: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Generate impossible travel authentication events.

        Two successful logins from geographically distant locations
        within a short time period.

        Args:
            user: User entity
            first_location: First login location (geo dict)
            second_location: Second login location (geo dict)
            time_gap_minutes: Time between logins

        Returns:
            Two authentication events representing impossible travel
        """
        # Select distant locations if not provided
        if first_location is None or second_location is None:
            locations = random.sample(self.GEO_LOCATIONS, 2)
            first_location = first_location or locations[0]
            second_location = second_location or locations[1]

        # Generate corresponding IPs
        first_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        second_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        events = []

        # First login (older)
        event1 = self.generate(
            outcome="success",
            method="sso",
            user=user,
            source_ip=first_ip,
            source_geo=first_location,
            timestamp_offset=time_gap_minutes,
        )
        events.append(event1)

        # Second login (recent)
        event2 = self.generate(
            outcome="success",
            method="sso",
            user=user,
            source_ip=second_ip,
            source_geo=second_location,
            timestamp_offset=0,
        )
        events.append(event2)

        return events

    @register_attack_pattern(
        name="mfa-bypass",
        description="MFA bypass attempt - password success followed by MFA failures",
        ttps=["T1556.006", "T1111"],
        category=GeneratorCategory.IDENTITY,
        required_params=["user", "host", "source_ip"],
        event_types=["authentication"],
        detection_recommendations=[
            "Password success followed by MFA failures",
            "MFA timeout patterns",
            "Unusual MFA failure rates",
        ],
    )
    def generate_mfa_bypass_attempt(
        self,
        user: "User",
        host: "Host",
        source_ip: str,
    ) -> list[dict[str, Any]]:
        """
        Generate MFA bypass attempt events.

        Password success followed by MFA failures.

        Args:
            user: User entity
            host: Target host
            source_ip: Source IP

        Returns:
            List of authentication events
        """
        events = []

        # Password authentication succeeds
        password_event = self.generate(
            outcome="success",
            method="password",
            user=user,
            host=host,
            source_ip=source_ip,
            timestamp_offset=5,
        )
        events.append(password_event)

        # Multiple MFA failures
        for i in range(3):
            mfa_event = self.generate(
                outcome="failure",
                method="mfa",
                user=user,
                host=host,
                source_ip=source_ip,
                timestamp_offset=4 - i,
                failure_reason="MFA_FAILED",
            )
            events.append(mfa_event)

        # Optional: MFA timeout
        timeout_event = self.generate(
            outcome="failure",
            method="mfa",
            user=user,
            host=host,
            source_ip=source_ip,
            timestamp_offset=0,
            failure_reason="MFA_TIMEOUT",
        )
        events.append(timeout_event)

        return events

    @register_attack_pattern(
        name="credential-stuffing",
        description="Credential stuffing attack using leaked credentials against multiple accounts",
        ttps=["T1110.004"],
        category=GeneratorCategory.IDENTITY,
        required_params=["host", "source_ip", "usernames"],
        optional_params=["success_ratio"],
        event_types=["authentication"],
        detection_recommendations=[
            "Many different usernames from same source IP",
            "Low success rate across attempts",
            "Known credential dump patterns",
        ],
    )
    def generate_credential_stuffing(
        self,
        host: "Host",
        source_ip: str,
        usernames: list[str],
        success_ratio: float = 0.05,
    ) -> list[dict[str, Any]]:
        """
        Generate credential stuffing attack events.

        Many different usernames from the same source with low success rate.

        Args:
            host: Target host
            source_ip: Attacker source IP
            usernames: List of usernames to try
            success_ratio: Ratio of successful logins

        Returns:
            List of authentication events
        """
        events = []

        for i, username in enumerate(usernames):
            outcome: AuthOutcome = "success" if random.random() < success_ratio else "failure"
            timestamp_offset = len(usernames) - i

            # Create a temporary user for each attempt
            event = self.generate(
                outcome=outcome,
                method="password",
                host=host,
                source_ip=source_ip,
                timestamp_offset=timestamp_offset,
                failure_reason="INVALID_CREDENTIALS" if outcome == "failure" else None,
            )
            # Override username
            event["user"]["name"] = username
            event["related"]["user"] = [username]

            events.append(event)

        return events
