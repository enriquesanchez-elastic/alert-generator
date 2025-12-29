"""IAM event generator for creating ECS-compliant identity and access management events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import User

IAMAction = Literal[
    "user_created",
    "user_deleted",
    "user_modified",
    "group_created",
    "group_deleted",
    "group_member_added",
    "group_member_removed",
    "role_created",
    "role_deleted",
    "role_assigned",
    "role_revoked",
    "policy_attached",
    "policy_detached",
    "permission_granted",
    "permission_revoked",
    "password_changed",
    "password_reset",
    "mfa_enabled",
    "mfa_disabled",
]


@register_event_type(
    name="iam",
    category=GeneratorCategory.IDENTITY,
    description="Identity and access management events for privilege escalation detection",
    ecs_fields=[
        "event.action",
        "user.name",
        "user.target.name",
        "user.target.group.name",
        "event.outcome",
    ],
    index_pattern="logs-system.auth-default",
    example_params={"action": "role_assigned", "is_malicious": True},
)
class IAMEventGenerator:
    """
    Generator for creating ECS-compliant IAM (Identity and Access Management) events.

    IAM events are critical for detecting:
    - Unauthorized user creation
    - Privilege escalation via role changes
    - Account takeover via password reset
    - Security bypass via MFA disabling
    - Persistence via backdoor account creation
    """

    # Sensitive roles that should trigger alerts
    SENSITIVE_ROLES = [
        "Administrator",
        "Domain Admin",
        "Enterprise Admin",
        "Global Admin",
        "Security Admin",
        "Privileged Role Administrator",
        "Exchange Admin",
        "SharePoint Admin",
        "Compliance Admin",
        "Billing Admin",
    ]

    # Sensitive groups
    SENSITIVE_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
    ]

    # IAM providers
    PROVIDERS = [
        "ActiveDirectory",
        "AzureAD",
        "Okta",
        "AWS IAM",
        "Google Cloud IAM",
        "LDAP",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize IAM event generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        action: IAMAction,
        actor: Optional["User"] = None,
        target_user: Optional["User"] = None,
        target_name: str | None = None,
        group_name: str | None = None,
        role_name: str | None = None,
        timestamp_offset: int = 0,
        is_suspicious: bool = False,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single IAM event.

        Args:
            action: IAM action type
            actor: User performing the action
            target_user: Target user being modified (if applicable)
            target_name: Target name for non-user targets
            group_name: Group name (for group operations)
            role_name: Role name (for role operations)
            timestamp_offset: Minutes to offset timestamp
            is_suspicious: If True, use sensitive targets
            provider: IAM provider

        Returns:
            ECS-compliant IAM event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        if provider is None:
            provider = random.choice(self.PROVIDERS)

        # Determine event type and category based on action
        event_type, event_category = self._get_event_type_category(action)

        # Build base event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": event_category,
                "type": event_type,
                "action": action,
                "outcome": "success",
                "provider": provider,
                "id": self.randomizer.generate_uuid(),
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "system.security",
                "namespace": "default",
            },
        }

        # Add actor (user performing the action)
        if actor:
            event["user"] = actor.to_ecs_dict()
            event["related"] = {"user": actor.to_related_user()}
        else:
            actor_name = self.randomizer.generate_username()
            event["user"] = {
                "name": actor_name,
                "id": str(random.randint(1000, 65000)),
                "domain": "CORPORATE",
            }
            event["related"] = {"user": [actor_name]}

        # Add target user if applicable
        if target_user:
            event["user"]["target"] = target_user.to_ecs_dict()
            if "related" not in event:
                event["related"] = {"user": []}
            event["related"]["user"].extend(target_user.to_related_user())
        elif target_name:
            event["user"]["target"] = {
                "name": target_name,
                "id": str(random.randint(1000, 65000)),
            }
            if "related" not in event:
                event["related"] = {"user": []}
            event["related"]["user"].append(target_name)

        # Add group information
        if group_name or "group" in action:
            if group_name is None:
                group_name = (
                    random.choice(self.SENSITIVE_GROUPS)
                    if is_suspicious
                    else f"Group_{random.randint(1, 100)}"
                )
            event["group"] = {
                "name": group_name,
                "id": str(random.randint(1000, 65000)),
            }

        # Add role information
        if role_name or "role" in action:
            if role_name is None:
                role_name = (
                    random.choice(self.SENSITIVE_ROLES)
                    if is_suspicious
                    else f"Role_{random.randint(1, 100)}"
                )
            event["user"]["roles"] = [role_name]

        # Add changes field for modifications
        if "modified" in action or "changed" in action:
            event["user"]["changes"] = self._generate_user_changes(action)

        # Add service information
        event["service"] = {
            "type": "iam",
            "name": provider,
        }

        return event

    def _get_event_type_category(self, action: IAMAction) -> tuple:
        """Map IAM action to ECS event type and category."""
        action_mapping = {
            "user_created": (["user", "creation"], ["iam"]),
            "user_deleted": (["user", "deletion"], ["iam"]),
            "user_modified": (["user", "change"], ["iam"]),
            "group_created": (["group", "creation"], ["iam"]),
            "group_deleted": (["group", "deletion"], ["iam"]),
            "group_member_added": (["group", "change"], ["iam"]),
            "group_member_removed": (["group", "change"], ["iam"]),
            "role_created": (["admin", "creation"], ["iam"]),
            "role_deleted": (["admin", "deletion"], ["iam"]),
            "role_assigned": (["admin", "change"], ["iam"]),
            "role_revoked": (["admin", "change"], ["iam"]),
            "policy_attached": (["admin", "change"], ["iam", "configuration"]),
            "policy_detached": (["admin", "change"], ["iam", "configuration"]),
            "permission_granted": (["admin", "change"], ["iam"]),
            "permission_revoked": (["admin", "change"], ["iam"]),
            "password_changed": (["user", "change"], ["iam", "authentication"]),
            "password_reset": (["user", "change"], ["iam", "authentication"]),
            "mfa_enabled": (["user", "change"], ["iam", "authentication"]),
            "mfa_disabled": (["user", "change"], ["iam", "authentication"]),
        }
        return action_mapping.get(action, (["info"], ["iam"]))

    def _generate_user_changes(self, action: str) -> dict[str, Any]:
        """Generate user changes based on action type."""
        if "password" in action:
            return {"password": {"old": "********", "new": "********"}}
        elif "mfa" in action:
            return {
                "mfa_enabled": {
                    "old": "mfa" not in action or "disabled" in action,
                    "new": "enabled" in action,
                }
            }
        elif "role" in action:
            return {"roles": {"old": [], "new": [random.choice(self.SENSITIVE_ROLES)]}}
        return {}

    def generate_batch(
        self,
        count: int,
        actor: Optional["User"] = None,
        suspicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of IAM events.

        Args:
            count: Number of events to generate
            actor: Optional User performing actions
            suspicious_ratio: Ratio of suspicious events
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of IAM event dictionaries
        """
        events = []
        actions: list[IAMAction] = [
            "user_created",
            "user_modified",
            "group_member_added",
            "role_assigned",
            "password_changed",
            "mfa_enabled",
        ]

        for i in range(count):
            action = random.choice(actions)
            is_suspicious = random.random() < suspicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                action=action,
                actor=actor,
                timestamp_offset=timestamp_offset,
                is_suspicious=is_suspicious,
            )
            events.append(event)

        return events

    def generate_privilege_escalation(
        self,
        actor: "User",
        target_user: "User",
        escalation_type: str = "admin_group",
    ) -> list[dict[str, Any]]:
        """
        Generate privilege escalation events.

        Args:
            actor: User performing the escalation
            target_user: User receiving elevated privileges
            escalation_type: Type of escalation (admin_group, admin_role, service_account)

        Returns:
            List of IAM events representing privilege escalation
        """
        events = []

        if escalation_type == "admin_group":
            # Add to sensitive group
            event = self.generate(
                action="group_member_added",
                actor=actor,
                target_user=target_user,
                group_name=random.choice(self.SENSITIVE_GROUPS),
                timestamp_offset=0,
                is_suspicious=True,
            )
            events.append(event)

        elif escalation_type == "admin_role":
            # Assign admin role
            event = self.generate(
                action="role_assigned",
                actor=actor,
                target_user=target_user,
                role_name=random.choice(self.SENSITIVE_ROLES),
                timestamp_offset=0,
                is_suspicious=True,
            )
            events.append(event)

        elif escalation_type == "service_account":
            # Create service account and assign high privileges
            create_event = self.generate(
                action="user_created",
                actor=actor,
                target_name=f"svc_{random.randint(100, 999)}",
                timestamp_offset=2,
            )
            events.append(create_event)

            role_event = self.generate(
                action="role_assigned",
                actor=actor,
                target_name=create_event["user"]["target"]["name"],
                role_name=random.choice(self.SENSITIVE_ROLES),
                timestamp_offset=1,
                is_suspicious=True,
            )
            events.append(role_event)

        return events

    def generate_backdoor_account(
        self,
        actor: "User",
        account_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate events for creating a backdoor account.

        Args:
            actor: User creating the backdoor
            account_name: Optional specific account name

        Returns:
            List of IAM events for backdoor creation
        """
        events = []

        if account_name is None:
            # Suspicious account names
            names = [
                "svc_backup",
                "admin_temp",
                "support_user",
                "system_update",
                "monitor_agent",
            ]
            account_name = random.choice(names)

        # Create user
        create_event = self.generate(
            action="user_created",
            actor=actor,
            target_name=account_name,
            timestamp_offset=3,
        )
        events.append(create_event)

        # Add to admin group
        group_event = self.generate(
            action="group_member_added",
            actor=actor,
            target_name=account_name,
            group_name="Administrators",
            timestamp_offset=2,
            is_suspicious=True,
        )
        events.append(group_event)

        # Disable MFA (suspicious)
        mfa_event = self.generate(
            action="mfa_disabled",
            actor=actor,
            target_name=account_name,
            timestamp_offset=1,
        )
        events.append(mfa_event)

        # Set password (never expires in real attack, but we just log the change)
        password_event = self.generate(
            action="password_changed",
            actor=actor,
            target_name=account_name,
            timestamp_offset=0,
        )
        events.append(password_event)

        return events

    def generate_security_weakening(
        self,
        actor: "User",
        target_user: "User",
    ) -> list[dict[str, Any]]:
        """
        Generate events for weakening account security.

        Args:
            actor: User performing the action
            target_user: Target user whose security is being weakened

        Returns:
            List of IAM events
        """
        events = []

        # Disable MFA
        mfa_event = self.generate(
            action="mfa_disabled",
            actor=actor,
            target_user=target_user,
            timestamp_offset=2,
        )
        events.append(mfa_event)

        # Reset password
        password_event = self.generate(
            action="password_reset",
            actor=actor,
            target_user=target_user,
            timestamp_offset=1,
        )
        events.append(password_event)

        return events
