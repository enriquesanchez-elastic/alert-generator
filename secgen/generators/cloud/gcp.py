"""GCP audit log generator for creating ECS-compliant GCP events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import User


@register_event_type(
    name="gcp-audit",
    category=GeneratorCategory.CLOUD,
    description="GCP audit events for IAM and resource monitoring",
    ecs_fields=[
        "cloud.provider",
        "cloud.project.id",
        "gcp.audit.method_name",
        "gcp.audit.service_name",
        "event.outcome",
    ],
    index_pattern="logs-gcp.audit-default",
    example_params={"is_malicious": True, "service": "iam"},
)
class GCPAuditGenerator:
    """
    Generator for creating ECS-compliant GCP audit events.

    GCP audit logs are critical for detecting:
    - IAM policy changes
    - Resource access patterns
    - Service account abuse
    - Data exfiltration from GCS/BigQuery
    - Compute instance manipulation
    """

    # GCP services
    GCP_SERVICES = [
        "iam.googleapis.com",
        "compute.googleapis.com",
        "storage.googleapis.com",
        "bigquery.googleapis.com",
        "cloudresourcemanager.googleapis.com",
        "cloudfunctions.googleapis.com",
        "container.googleapis.com",
        "logging.googleapis.com",
    ]

    # GCP regions
    GCP_REGIONS = [
        "us-central1",
        "us-east1",
        "us-west1",
        "europe-west1",
        "europe-west2",
        "asia-east1",
        "asia-northeast1",
        "australia-southeast1",
    ]

    # IAM methods
    IAM_METHODS = {
        "privilege_escalation": [
            "SetIamPolicy",
            "CreateServiceAccountKey",
            "CreateServiceAccount",
            "AddRoleMember",
        ],
        "reconnaissance": [
            "GetIamPolicy",
            "ListServiceAccounts",
            "ListRoles",
            "GetProject",
        ],
    }

    # Storage methods
    STORAGE_METHODS = [
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.create",
        "storage.objects.delete",
        "storage.buckets.get",
        "storage.buckets.setIamPolicy",
    ]

    # Compute methods
    COMPUTE_METHODS = [
        "compute.instances.insert",
        "compute.instances.delete",
        "compute.instances.setMetadata",
        "compute.firewalls.insert",
        "compute.firewalls.delete",
    ]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize GCP audit generator."""
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        method_name: str | None = None,
        service_name: str | None = None,
        user: Optional["User"] = None,
        project_id: str | None = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        source_ip: str | None = None,
        is_granted: bool = True,
    ) -> dict[str, Any]:
        """
        Generate a single GCP audit event.

        Args:
            method_name: GCP API method name
            service_name: GCP service name
            user: User entity
            project_id: GCP project ID
            timestamp_offset: Minutes to offset timestamp
            is_malicious: Whether to flag as suspicious
            source_ip: Source IP address
            is_granted: Whether access was granted

        Returns:
            ECS-compliant GCP audit event
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        if project_id is None:
            project_id = f"project-{random.randint(100000, 999999)}"

        if service_name is None:
            service_name = random.choice(self.GCP_SERVICES)

        if method_name is None:
            if is_malicious:
                category = random.choice(list(self.IAM_METHODS.keys()))
                method_name = random.choice(self.IAM_METHODS[category])
                service_name = "iam.googleapis.com"
            else:
                if "storage" in service_name:
                    method_name = random.choice(self.STORAGE_METHODS)
                elif "compute" in service_name:
                    method_name = random.choice(self.COMPUTE_METHODS)
                else:
                    method_name = f"{service_name.split('.')[0]}.get"

        if user:
            principal_email = user.email or f"{user.name}@company.com"
        else:
            principal_email = f"user{random.randint(1, 999)}@company.com"

        if source_ip is None:
            source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["iam"] if "iam" in service_name else ["configuration"],
                "type": self._get_event_type(method_name),
                "action": method_name,
                "outcome": "success" if is_granted else "failure",
                "provider": "gcp.audit",
                "id": self.randomizer.generate_uuid(),
            },
            "cloud": {
                "provider": "gcp",
                "project": {"id": project_id},
                "region": random.choice(self.GCP_REGIONS),
                "service": {"name": service_name},
            },
            "gcp": {
                "audit": {
                    "method_name": method_name,
                    "service_name": service_name,
                    "resource_name": f"projects/{project_id}",
                    "authentication_info": {
                        "principal_email": principal_email,
                    },
                    "authorization_info": [
                        {
                            "granted": is_granted,
                            "permission": method_name,
                            "resource": f"projects/{project_id}",
                        }
                    ],
                    "request_metadata": {
                        "caller_ip": source_ip,
                        "caller_supplied_user_agent": random.choice(
                            [
                                "gcloud/400.0.0",
                                "google-api-python-client/2.0.0",
                                "Terraform/1.5.0",
                                "Mozilla/5.0 (GCP Console)",
                            ]
                        ),
                    },
                    "status": {"code": 0 if is_granted else 7},
                },
            },
            "user": {
                "email": principal_email,
                "name": principal_email.split("@")[0],
            },
            "source": {
                "ip": source_ip,
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "gcp.audit",
                "namespace": "default",
            },
        }

        if not is_granted:
            event["event"]["reason"] = "Permission denied"

        event["related"] = {
            "user": [principal_email],
            "ip": [source_ip],
        }

        return event

    def _get_event_type(self, method_name: str) -> list[str]:
        """Map method name to ECS event type."""
        method_lower = method_name.lower()
        if "insert" in method_lower or "create" in method_lower or "add" in method_lower:
            return ["creation"]
        elif "delete" in method_lower or "remove" in method_lower:
            return ["deletion"]
        elif "set" in method_lower or "update" in method_lower:
            return ["change"]
        elif "get" in method_lower or "list" in method_lower:
            return ["access"]
        return ["info"]

    def generate_batch(
        self,
        count: int,
        project_id: str | None = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Generate a batch of GCP audit events."""
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                project_id=project_id,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            events.append(event)

        return events

    def generate_service_account_abuse(
        self,
        attacker: "User",
        project_id: str,
    ) -> list[dict[str, Any]]:
        """
        Generate service account key creation abuse.

        Args:
            attacker: Attacker user
            project_id: GCP project ID

        Returns:
            List of GCP audit events
        """
        events = []
        methods = [
            "ListServiceAccounts",
            "GetServiceAccount",
            "CreateServiceAccountKey",
            "SetIamPolicy",
        ]

        for i, method in enumerate(methods):
            event = self.generate(
                method_name=method,
                service_name="iam.googleapis.com",
                user=attacker,
                project_id=project_id,
                timestamp_offset=len(methods) - i,
                is_malicious=True,
            )
            events.append(event)

        return events

    def generate_data_exfiltration(
        self,
        attacker: "User",
        project_id: str,
        bucket_name: str,
        object_count: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Generate GCS data exfiltration events.

        Args:
            attacker: Attacker user
            project_id: GCP project ID
            bucket_name: Target GCS bucket
            object_count: Number of objects accessed

        Returns:
            List of GCP audit events
        """
        events = []

        # List bucket
        list_event = self.generate(
            method_name="storage.objects.list",
            service_name="storage.googleapis.com",
            user=attacker,
            project_id=project_id,
            timestamp_offset=object_count + 1,
            is_malicious=True,
        )
        events.append(list_event)

        # Get objects
        for i in range(object_count):
            event = self.generate(
                method_name="storage.objects.get",
                service_name="storage.googleapis.com",
                user=attacker,
                project_id=project_id,
                timestamp_offset=object_count - i,
                is_malicious=True,
            )
            events.append(event)

        return events
