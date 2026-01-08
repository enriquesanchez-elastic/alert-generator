"""Azure audit log generator for creating ECS-compliant Azure events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import User


@register_event_type(
    name="azure-audit",
    category=GeneratorCategory.CLOUD,
    description="Azure AD and audit events for sign-in and directory monitoring",
    ecs_fields=[
        "cloud.provider",
        "azure.signinlogs.properties.status.error_code",
        "azure.auditlogs.operation_name",
        "user.name",
        "event.outcome",
    ],
    index_pattern="logs-azure.auditlogs-default",
    example_params={"event_type": "signin", "is_malicious": True},
)
class AzureAuditGenerator:
    """
    Generator for creating ECS-compliant Azure audit events.

    Supports both Azure AD sign-in logs and audit logs for detecting:
    - Suspicious sign-in activity
    - Risky user behavior
    - Directory changes
    - Application consent grants
    - Conditional access policy bypasses
    """

    # Azure regions
    AZURE_LOCATIONS = [
        "westus",
        "westus2",
        "eastus",
        "eastus2",
        "westeurope",
        "northeurope",
        "uksouth",
        "japaneast",
        "australiaeast",
        "southeastasia",
    ]

    # Sign-in error codes
    SIGNIN_ERROR_CODES = {
        "50126": "Invalid username or password",
        "50053": "Account is locked",
        "50057": "User account is disabled",
        "50074": "Strong authentication required",
        "50076": "MFA required",
        "50079": "User needs to register for MFA",
        "53003": "Access blocked by Conditional Access",
    }

    # Risk levels
    RISK_LEVELS = ["none", "low", "medium", "high"]

    # Conditional access statuses
    CA_STATUSES = ["success", "failure", "notApplied"]

    # Audit operations
    AUDIT_OPERATIONS = {
        "user_management": [
            "Add user",
            "Delete user",
            "Update user",
            "Reset user password",
            "Enable user",
            "Disable user",
        ],
        "group_management": [
            "Add group",
            "Delete group",
            "Add member to group",
            "Remove member from group",
        ],
        "role_management": [
            "Add member to role",
            "Remove member from role",
            "Add eligible member to role",
        ],
        "application": [
            "Add application",
            "Update application",
            "Consent to application",
            "Add service principal",
        ],
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize Azure audit generator."""
        self.randomizer = randomizer or RandomDataGenerator()

    def generate_signin(
        self,
        user: Optional["User"] = None,
        tenant_id: str | None = None,
        is_successful: bool = True,
        is_risky: bool = False,
        timestamp_offset: int = 0,
        source_ip: str | None = None,
        location: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate an Azure AD sign-in event.

        Args:
            user: User entity
            tenant_id: Azure tenant ID
            is_successful: Whether sign-in succeeded
            is_risky: Whether to flag as risky
            timestamp_offset: Minutes to offset timestamp
            source_ip: Source IP address
            location: Sign-in location

        Returns:
            ECS-compliant Azure sign-in event
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        if tenant_id is None:
            tenant_id = self.randomizer.generate_uuid()

        if user:
            user_principal_name = user.email or f"{user.name}@company.onmicrosoft.com"
            user_id = user.id
        else:
            user_principal_name = f"user{random.randint(1, 999)}@company.onmicrosoft.com"
            user_id = self.randomizer.generate_uuid()

        if source_ip is None:
            source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        if location is None:
            location = random.choice(self.AZURE_LOCATIONS)

        # Determine error code if failed
        error_code = None
        error_desc = None
        if not is_successful:
            error_code = random.choice(list(self.SIGNIN_ERROR_CODES.keys()))
            error_desc = self.SIGNIN_ERROR_CODES[error_code]

        # Determine risk level
        risk_level = (
            random.choice(["high", "medium"]) if is_risky else random.choice(["none", "low"])
        )

        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["authentication"],
                "type": ["start"],
                "action": "UserLoggedIn" if is_successful else "UserLoginFailed",
                "outcome": "success" if is_successful else "failure",
                "provider": "azure.signinlogs",
                "id": self.randomizer.generate_uuid(),
            },
            "cloud": {
                "provider": "azure",
                "account": {"id": tenant_id},
                "region": location,
            },
            "azure": {
                "signinlogs": {
                    "properties": {
                        "user_principal_name": user_principal_name,
                        "user_id": user_id,
                        "app_display_name": random.choice(
                            ["Azure Portal", "Microsoft Office", "Teams", "Outlook"]
                        ),
                        "ip_address": source_ip,
                        "location": {
                            "city": location.title(),
                            "country_or_region": "US",
                        },
                        "status": {
                            "error_code": error_code or 0,
                            "failure_reason": error_desc,
                        },
                        "device_detail": {
                            "operating_system": random.choice(
                                ["Windows 10", "Windows 11", "MacOS", "iOS", "Android"]
                            ),
                            "browser": random.choice(["Chrome", "Edge", "Firefox", "Safari"]),
                        },
                        "risk_level_aggregated": risk_level,
                        "risk_level_during_signin": risk_level,
                        "risk_state": "atRisk" if is_risky else "none",
                        "is_interactive": random.choice([True, False]),
                        "conditional_access_status": random.choice(self.CA_STATUSES),
                        "authentication_requirement": "singleFactorAuthentication",
                        "token_issuer_type": "AzureAD",
                    },
                },
            },
            "user": {
                "name": user_principal_name.split("@")[0],
                "email": user_principal_name,
                "id": user_id,
            },
            "source": {
                "ip": source_ip,
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "azure.signinlogs",
                "namespace": "default",
            },
        }

        if error_desc:
            event["event"]["reason"] = error_desc

        event["related"] = {
            "user": [user_principal_name],
            "ip": [source_ip],
        }

        return event

    def generate_audit(
        self,
        operation: str | None = None,
        actor: Optional["User"] = None,
        target_user: str | None = None,
        tenant_id: str | None = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
    ) -> dict[str, Any]:
        """
        Generate an Azure AD audit event.

        Args:
            operation: Audit operation name
            actor: User performing the action
            target_user: Target of the operation
            tenant_id: Azure tenant ID
            timestamp_offset: Minutes to offset timestamp
            is_malicious: Whether to flag as suspicious

        Returns:
            ECS-compliant Azure audit event
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        if tenant_id is None:
            tenant_id = self.randomizer.generate_uuid()

        if operation is None:
            if is_malicious:
                category = random.choice(["role_management", "application"])
            else:
                category = random.choice(list(self.AUDIT_OPERATIONS.keys()))
            operation = random.choice(self.AUDIT_OPERATIONS[category])

        if actor:
            actor_upn = actor.email or f"{actor.name}@company.onmicrosoft.com"
        else:
            actor_upn = f"admin{random.randint(1, 99)}@company.onmicrosoft.com"

        if target_user is None:
            target_user = f"user{random.randint(1, 999)}@company.onmicrosoft.com"

        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["iam"],
                "type": self._get_event_type(operation),
                "action": operation,
                "outcome": "success",
                "provider": "azure.auditlogs",
                "id": self.randomizer.generate_uuid(),
            },
            "cloud": {
                "provider": "azure",
                "account": {"id": tenant_id},
            },
            "azure": {
                "auditlogs": {
                    "properties": {
                        "activity_display_name": operation,
                        "activity_datetime": timestamp,
                        "category": (
                            "UserManagement" if "user" in operation.lower() else "RoleManagement"
                        ),
                        "initiated_by": {
                            "user": {
                                "user_principal_name": actor_upn,
                            },
                        },
                        "target_resources": [
                            {
                                "display_name": target_user.split("@")[0],
                                "user_principal_name": target_user,
                                "type": "User",
                            }
                        ],
                        "result": "success",
                        "result_reason": None,
                    },
                },
            },
            "user": {
                "name": actor_upn.split("@")[0],
                "email": actor_upn,
            },
            "user_target": {
                "name": target_user.split("@")[0],
                "email": target_user,
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "azure.auditlogs",
                "namespace": "default",
            },
        }

        event["related"] = {
            "user": [actor_upn, target_user],
        }

        return event

    def _get_event_type(self, operation: str) -> list[str]:
        """Map operation to ECS event type."""
        op_lower = operation.lower()
        if "add" in op_lower or "create" in op_lower:
            return ["creation"]
        elif "delete" in op_lower or "remove" in op_lower:
            return ["deletion"]
        elif "update" in op_lower or "reset" in op_lower:
            return ["change"]
        return ["info"]

    def generate_batch(
        self,
        count: int,
        event_type: str = "signin",
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Generate a batch of Azure events."""
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            if event_type == "signin":
                event = self.generate_signin(
                    is_successful=not is_malicious or random.random() < 0.3,
                    is_risky=is_malicious,
                    timestamp_offset=timestamp_offset,
                )
            else:
                event = self.generate_audit(
                    timestamp_offset=timestamp_offset,
                    is_malicious=is_malicious,
                )
            events.append(event)

        return events

    def generate_brute_force(
        self,
        target_user: "User",
        source_ip: str,
        attempts: int = 20,
    ) -> list[dict[str, Any]]:
        """Generate Azure AD brute force attack events."""
        events = []

        for i in range(attempts):
            is_last = i == attempts - 1
            event = self.generate_signin(
                user=target_user,
                is_successful=is_last,  # Last attempt succeeds
                is_risky=True,
                timestamp_offset=attempts - i,
                source_ip=source_ip,
            )
            events.append(event)

        return events
