"""AWS CloudTrail event generator for creating ECS-compliant AWS audit events."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import User


@register_event_type(
    name="aws-cloudtrail",
    category=GeneratorCategory.CLOUD,
    description="AWS CloudTrail audit events for IAM and resource monitoring",
    ecs_fields=[
        "cloud.provider",
        "cloud.account.id",
        "aws.cloudtrail.event_name",
        "aws.cloudtrail.event_source",
        "event.outcome",
    ],
    index_pattern="logs-aws.cloudtrail-default",
    example_params={"is_malicious": True, "action_category": "privilege_escalation"},
)
class AWSCloudTrailGenerator:
    """
    Generator for creating ECS-compliant AWS CloudTrail events.

    CloudTrail events are critical for detecting:
    - Unauthorized IAM changes
    - Privilege escalation
    - Data access patterns
    - Resource enumeration
    - Defense evasion (trail disabling)
    """

    # AWS event sources
    EVENT_SOURCES = [
        "iam.amazonaws.com",
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
        "sts.amazonaws.com",
        "lambda.amazonaws.com",
        "rds.amazonaws.com",
        "kms.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "organizations.amazonaws.com",
        "secretsmanager.amazonaws.com",
    ]

    # High-risk IAM actions
    IAM_ACTIONS = {
        "privilege_escalation": [
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "CreateRole",
            "UpdateAssumeRolePolicy",
            "AddUserToGroup",
        ],
        "reconnaissance": [
            "ListUsers",
            "ListRoles",
            "ListGroups",
            "ListPolicies",
            "GetUser",
            "GetRole",
            "GetPolicy",
            "ListAccessKeys",
        ],
        "defense_evasion": [
            "DeleteTrail",
            "StopLogging",
            "UpdateTrail",
            "DeleteFlowLogs",
            "DeleteEventBus",
        ],
    }

    # EC2 actions
    EC2_ACTIONS = [
        "RunInstances",
        "TerminateInstances",
        "ModifyInstanceAttribute",
        "CreateSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "CreateKeyPair",
        "DescribeInstances",
        "DescribeSecurityGroups",
    ]

    # S3 actions
    S3_ACTIONS = [
        "GetObject",
        "PutObject",
        "DeleteObject",
        "ListBucket",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
    ]

    # AWS regions
    AWS_REGIONS = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "eu-west-2",
        "eu-central-1",
        "ap-northeast-1",
        "ap-southeast-1",
        "ap-southeast-2",
    ]

    # User identity types
    IDENTITY_TYPES = ["IAMUser", "Root", "AssumedRole", "FederatedUser", "AWSService"]

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """
        Initialize AWS CloudTrail generator.

        Args:
            randomizer: Optional RandomDataGenerator instance
        """
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        event_name: str | None = None,
        event_source: str | None = None,
        user: Optional["User"] = None,
        account_id: str | None = None,
        region: str | None = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
        error_code: str | None = None,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a single AWS CloudTrail event.

        Args:
            event_name: AWS API action name
            event_source: AWS service source
            user: Optional User entity
            account_id: AWS account ID
            region: AWS region
            timestamp_offset: Minutes to offset timestamp
            is_malicious: If True, generate suspicious characteristics
            error_code: Error code for failed actions
            source_ip: Source IP address

        Returns:
            ECS-compliant CloudTrail event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Set defaults
        if event_source is None:
            event_source = random.choice(self.EVENT_SOURCES)

        if event_name is None:
            if is_malicious:
                category = random.choice(list(self.IAM_ACTIONS.keys()))
                event_name = random.choice(self.IAM_ACTIONS[category])
                event_source = "iam.amazonaws.com"
            else:
                event_name = random.choice(self.EC2_ACTIONS + self.S3_ACTIONS)

        if region is None:
            region = random.choice(self.AWS_REGIONS)

        if account_id is None:
            account_id = str(random.randint(100000000000, 999999999999))

        if source_ip is None:
            source_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Generate user identity
        if user:
            user_name = user.name
            identity_type = "IAMUser"
        else:
            user_name = f"user_{random.randint(1000, 9999)}"
            identity_type = random.choice(self.IDENTITY_TYPES)

        user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": (
                    ["iam", "configuration"] if "iam" in event_source else ["configuration"]
                ),
                "type": self._get_event_type(event_name),
                "action": event_name,
                "outcome": "failure" if error_code else "success",
                "provider": "aws.cloudtrail",
                "id": self.randomizer.generate_uuid(),
            },
            "cloud": {
                "provider": "aws",
                "account": {"id": account_id},
                "region": region,
                "service": {"name": event_source.split(".")[0]},
            },
            "aws": {
                "cloudtrail": {
                    "event_type": "AwsApiCall",
                    "event_source": event_source,
                    "event_version": "1.08",
                    "user_identity": {
                        "type": identity_type,
                        "arn": user_arn,
                        "access_key_id": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                    },
                    "request_id": self.randomizer.generate_uuid(),
                    "read_only": event_name.startswith(("Get", "List", "Describe")),
                },
            },
            "user": {
                "name": user_name,
                "id": user_arn,
            },
            "source": {
                "ip": source_ip,
            },
            "user_agent": {
                "original": random.choice(
                    [
                        "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
                        "Boto3/1.28.0 Python/3.9.0",
                        "console.amazonaws.com",
                        "signin.amazonaws.com",
                    ]
                ),
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "aws.cloudtrail",
                "namespace": "default",
            },
        }

        # Add error information if present
        if error_code:
            event["event"]["reason"] = error_code
            event["aws"]["cloudtrail"]["error_code"] = error_code
            event["aws"]["cloudtrail"]["error_message"] = f"User: {user_arn} is not authorized"

        # Add related fields
        event["related"] = {
            "user": [user_name],
            "ip": [source_ip],
        }

        return event

    def _get_event_type(self, event_name: str) -> list[str]:
        """Map event name to ECS event type."""
        if event_name.startswith("Create"):
            return ["creation"]
        elif event_name.startswith("Delete"):
            return ["deletion"]
        elif event_name.startswith(("Update", "Modify", "Put", "Attach", "Detach")):
            return ["change"]
        elif event_name.startswith(("Get", "List", "Describe")):
            return ["access"]
        return ["info"]

    def generate_batch(
        self,
        count: int,
        user: Optional["User"] = None,
        account_id: str | None = None,
        malicious_ratio: float = 0.1,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Generate a batch of CloudTrail events."""
        events = []

        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                user=user,
                account_id=account_id,
                timestamp_offset=timestamp_offset,
                is_malicious=is_malicious,
            )
            events.append(event)

        return events

    def generate_privilege_escalation(
        self,
        attacker: "User",
        account_id: str,
        source_ip: str,
    ) -> list[dict[str, Any]]:
        """
        Generate privilege escalation attack sequence.

        Args:
            attacker: Attacker user
            account_id: AWS account ID
            source_ip: Attacker IP

        Returns:
            List of CloudTrail events representing privilege escalation
        """
        events = []
        actions = [
            ("ListUsers", False),
            ("ListRoles", False),
            ("CreateUser", True),
            ("AttachUserPolicy", True),
            ("CreateAccessKey", True),
        ]

        for i, (action, is_write) in enumerate(actions):
            event = self.generate(
                event_name=action,
                event_source="iam.amazonaws.com",
                user=attacker,
                account_id=account_id,
                timestamp_offset=len(actions) - i,
                is_malicious=True,
                source_ip=source_ip,
            )
            events.append(event)

        return events

    def generate_defense_evasion(
        self,
        attacker: "User",
        account_id: str,
    ) -> list[dict[str, Any]]:
        """
        Generate defense evasion events (disabling logging).

        Args:
            attacker: Attacker user
            account_id: AWS account ID

        Returns:
            List of CloudTrail events
        """
        events = []
        actions = ["StopLogging", "DeleteTrail", "UpdateTrail"]

        for i, action in enumerate(actions):
            event = self.generate(
                event_name=action,
                event_source="cloudtrail.amazonaws.com",
                user=attacker,
                account_id=account_id,
                timestamp_offset=len(actions) - i,
                is_malicious=True,
            )
            events.append(event)

        return events

    def generate_data_exfiltration(
        self,
        attacker: "User",
        account_id: str,
        bucket_name: str,
        object_count: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Generate S3 data exfiltration events.

        Args:
            attacker: Attacker user
            account_id: AWS account ID
            bucket_name: Target S3 bucket
            object_count: Number of objects accessed

        Returns:
            List of CloudTrail events
        """
        events = []

        # First enumerate the bucket
        list_event = self.generate(
            event_name="ListBucket",
            event_source="s3.amazonaws.com",
            user=attacker,
            account_id=account_id,
            timestamp_offset=object_count + 1,
            is_malicious=True,
        )
        events.append(list_event)

        # Then download objects
        for i in range(object_count):
            event = self.generate(
                event_name="GetObject",
                event_source="s3.amazonaws.com",
                user=attacker,
                account_id=account_id,
                timestamp_offset=object_count - i,
                is_malicious=True,
            )
            events.append(event)

        return events
