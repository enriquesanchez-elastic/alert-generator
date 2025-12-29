"""User entity model for persistent world state."""

import random
from dataclasses import dataclass, field
from typing import Literal

UserType = Literal["standard", "admin", "service", "system"]


@dataclass
class User:
    """
    User entity representing an identity in the simulated environment.

    This is a persistent entity that maintains consistent identifiers
    across all events generated for this user, enabling proper correlation
    in Entity Analytics and authentication-based detection.

    Attributes:
        name: Username (primary correlation key for user.name)
        id: User ID (UID on Unix, SID on Windows)
        domain: Domain or realm (CORPORATE, WORKGROUP, etc.)
        email: Email address (for cloud/identity providers)
        full_name: Display name
        user_type: Type of user account
        roles: List of assigned roles
        assigned_hosts: List of host.ids this user regularly uses
        groups: List of group memberships
        is_privileged: Whether this is a privileged/admin account
    """

    name: str
    id: str
    domain: str | None = None
    email: str | None = None
    full_name: str | None = None
    user_type: UserType = "standard"
    roles: list[str] = field(default_factory=list)
    assigned_hosts: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    is_privileged: bool = False

    # Common first names for generation
    FIRST_NAMES = [
        "alice",
        "bob",
        "charlie",
        "diana",
        "eve",
        "frank",
        "grace",
        "henry",
        "iris",
        "jack",
        "kate",
        "leo",
        "maya",
        "noah",
        "olivia",
        "peter",
        "quinn",
        "rachel",
        "sam",
        "tara",
        "uma",
        "victor",
        "wendy",
        "xavier",
    ]

    # Common last names for generation
    LAST_NAMES = [
        "smith",
        "johnson",
        "williams",
        "brown",
        "jones",
        "garcia",
        "miller",
        "davis",
        "rodriguez",
        "martinez",
        "hernandez",
        "lopez",
        "wilson",
        "anderson",
        "thomas",
        "taylor",
        "moore",
        "jackson",
    ]

    # Service account names
    SERVICE_ACCOUNTS = [
        "www-data",
        "nginx",
        "apache",
        "postgres",
        "mysql",
        "redis",
        "elasticsearch",
        "mongodb",
        "jenkins",
        "gitlab-runner",
        "prometheus",
        "grafana",
        "vault",
        "consul",
        "nomad",
    ]

    # System accounts
    SYSTEM_ACCOUNTS = {
        "linux": ["root", "daemon", "bin", "sys", "nobody"],
        "windows": ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "Administrator"],
    }

    @classmethod
    def generate(
        cls,
        template: str = "standard",
        domain: str | None = None,
        name_override: str | None = None,
    ) -> "User":
        """
        Generate a new user based on a template.

        Args:
            template: User template type (standard, admin, service, system_linux, system_windows)
            domain: Domain override
            name_override: Override generated username

        Returns:
            New User instance with generated attributes
        """
        if template == "service":
            return cls._generate_service_user(domain, name_override)
        elif template == "system_linux":
            return cls._generate_system_user("linux", domain, name_override)
        elif template == "system_windows":
            return cls._generate_system_user("windows", domain, name_override)
        elif template == "admin":
            return cls._generate_admin_user(domain, name_override)
        else:
            return cls._generate_standard_user(domain, name_override)

    @classmethod
    def _generate_standard_user(cls, domain: str | None, name_override: str | None) -> "User":
        """Generate a standard user account."""
        first = random.choice(cls.FIRST_NAMES)
        last = random.choice(cls.LAST_NAMES)

        if name_override:
            username = name_override
        else:
            # Various username formats
            formats = [
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{first}_{last}",
            ]
            username = random.choice(formats)

        uid = str(random.randint(1000, 65000))
        email_domain = domain.lower() if domain else "company.com"

        return cls(
            name=username,
            id=uid,
            domain=domain or "CORPORATE",
            email=f"{username}@{email_domain}",
            full_name=f"{first.title()} {last.title()}",
            user_type="standard",
            roles=["user"],
            groups=["Domain Users", "Users"],
            is_privileged=False,
        )

    @classmethod
    def _generate_admin_user(cls, domain: str | None, name_override: str | None) -> "User":
        """Generate an admin user account."""
        user = cls._generate_standard_user(domain, name_override)

        # Modify to admin
        user.user_type = "admin"
        user.is_privileged = True
        user.roles = ["admin", "user"]
        user.groups = ["Domain Admins", "Administrators", "Domain Users"]

        # Sometimes prefix with admin indicator
        if random.random() < 0.3 and not name_override:
            user.name = f"adm_{user.name}"
            user.email = f"{user.name}@{user.email.split('@')[1]}"

        return user

    @classmethod
    def _generate_service_user(cls, domain: str | None, name_override: str | None) -> "User":
        """Generate a service account."""
        if name_override:
            username = name_override
        else:
            username = random.choice(cls.SERVICE_ACCOUNTS)

        # Service accounts typically have low UIDs
        uid = str(random.randint(100, 999))

        return cls(
            name=username,
            id=uid,
            domain=domain,
            email=None,
            full_name=f"{username} service account",
            user_type="service",
            roles=["service"],
            groups=[],
            is_privileged=False,
        )

    @classmethod
    def _generate_system_user(
        cls, os_type: str, domain: str | None, name_override: str | None
    ) -> "User":
        """Generate a system account."""
        if name_override:
            username = name_override
        else:
            username = random.choice(cls.SYSTEM_ACCOUNTS.get(os_type, ["root"]))

        # System accounts have UID 0 or special SIDs
        if os_type == "windows":
            uid = "S-1-5-18"  # SYSTEM SID
            if username == "LOCAL SERVICE":
                uid = "S-1-5-19"
            elif username == "NETWORK SERVICE":
                uid = "S-1-5-20"
            elif username == "Administrator":
                uid = "S-1-5-21-0-0-0-500"
        else:
            uid = "0" if username == "root" else str(random.randint(1, 99))

        return cls(
            name=username,
            id=uid,
            domain=domain or ("NT AUTHORITY" if os_type == "windows" else None),
            email=None,
            full_name=username,
            user_type="system",
            roles=["system"],
            groups=["root"] if os_type == "linux" else ["BUILTIN\\Administrators"],
            is_privileged=True,
        )

    def assign_to_host(self, host_id: str) -> None:
        """Assign this user to a host."""
        if host_id not in self.assigned_hosts:
            self.assigned_hosts.append(host_id)

    def to_ecs_dict(self) -> dict:
        """
        Convert to ECS-compatible user fields dictionary.

        Returns:
            Dictionary with ECS user.* fields
        """
        result = {
            "name": self.name,
            "id": self.id,
        }

        if self.domain:
            result["domain"] = self.domain

        if self.email:
            result["email"] = self.email

        if self.full_name:
            result["full_name"] = self.full_name

        if self.roles:
            result["roles"] = self.roles

        if self.groups:
            result["group"] = {"name": self.groups[0]} if self.groups else {}

        return result

    def to_related_user(self) -> list[str]:
        """
        Get values for related.user field.

        Returns:
            List of user identifiers for correlation
        """
        related = [self.name]
        if self.email:
            related.append(self.email)
        return related
