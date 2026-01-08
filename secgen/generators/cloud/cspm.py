"""CSPM (Cloud Security Posture Management) generator for compliance findings."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    pass

CloudProvider = Literal["aws", "azure", "gcp"]
ComplianceFramework = Literal["CIS AWS", "CIS Azure", "CIS GCP", "PCI-DSS", "SOC2", "HIPAA"]


@register_event_type(
    name="cspm",
    category=GeneratorCategory.CLOUD,
    description="Cloud Security Posture Management findings for compliance dashboards",
    ecs_fields=[
        "rule.id",
        "rule.name",
        "rule.description",
        "cloud.provider",
        "cloud.account.id",
        "event.outcome",
    ],
    index_pattern="logs-cloud_security_posture.findings-default",
    example_params={"cloud_provider": "aws", "framework": "CIS AWS"},
)
class CSPMGenerator:
    """
    Generator for creating CSPM compliance findings.

    CSPM findings are critical for:
    - Cloud security posture dashboards
    - Compliance reporting (CIS, PCI-DSS, SOC2)
    - Risk assessment
    - Configuration drift detection
    """

    # CIS AWS Foundations Benchmark rules
    CIS_AWS_RULES = [
        {
            "id": "cis-aws-1.1",
            "name": "Avoid the use of the root account",
            "description": "The root account has unrestricted access to all resources",
            "severity": "high",
            "section": "1. Identity and Access Management",
        },
        {
            "id": "cis-aws-1.4",
            "name": "Ensure no root account access key exists",
            "description": "Root account access keys should not exist",
            "severity": "critical",
            "section": "1. Identity and Access Management",
        },
        {
            "id": "cis-aws-1.5",
            "name": "Ensure MFA is enabled for the root account",
            "description": "Multi-factor authentication adds an extra layer of protection",
            "severity": "critical",
            "section": "1. Identity and Access Management",
        },
        {
            "id": "cis-aws-2.1",
            "name": "Ensure CloudTrail is enabled in all regions",
            "description": "CloudTrail logs AWS API calls for auditing",
            "severity": "high",
            "section": "2. Logging",
        },
        {
            "id": "cis-aws-2.6",
            "name": "Ensure S3 bucket access logging is enabled",
            "description": "S3 access logging helps identify unauthorized access",
            "severity": "medium",
            "section": "2. Logging",
        },
        {
            "id": "cis-aws-3.1",
            "name": "Ensure VPC flow logging is enabled",
            "description": "VPC flow logs capture network traffic metadata",
            "severity": "medium",
            "section": "3. Monitoring",
        },
        {
            "id": "cis-aws-4.1",
            "name": "Ensure no security groups allow 0.0.0.0/0 to port 22",
            "description": "SSH should not be open to the internet",
            "severity": "high",
            "section": "4. Networking",
        },
        {
            "id": "cis-aws-4.2",
            "name": "Ensure no security groups allow 0.0.0.0/0 to port 3389",
            "description": "RDP should not be open to the internet",
            "severity": "high",
            "section": "4. Networking",
        },
    ]

    # CIS Azure rules
    CIS_AZURE_RULES = [
        {
            "id": "cis-azure-1.1",
            "name": "Ensure MFA is enabled for all privileged users",
            "description": "Multi-factor authentication for privileged Azure AD users",
            "severity": "critical",
            "section": "1. Identity and Access Management",
        },
        {
            "id": "cis-azure-2.1",
            "name": "Ensure that Azure Defender is set to On for Servers",
            "description": "Azure Defender provides threat protection",
            "severity": "high",
            "section": "2. Security Center",
        },
        {
            "id": "cis-azure-3.1",
            "name": "Ensure storage account secure transfer is enabled",
            "description": "Enforce HTTPS for storage account access",
            "severity": "medium",
            "section": "3. Storage Accounts",
        },
        {
            "id": "cis-azure-4.1",
            "name": "Ensure SQL server TDE is enabled",
            "description": "Transparent Data Encryption protects data at rest",
            "severity": "high",
            "section": "4. Database Services",
        },
        {
            "id": "cis-azure-5.1",
            "name": "Ensure Network Security Group flow logs are enabled",
            "description": "NSG flow logs capture network traffic information",
            "severity": "medium",
            "section": "5. Networking",
        },
    ]

    # Cloud account templates
    CLOUD_ACCOUNTS = {
        "aws": [
            {"id": "123456789012", "name": "production"},
            {"id": "234567890123", "name": "staging"},
            {"id": "345678901234", "name": "development"},
        ],
        "azure": [
            {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "Production Subscription"},
            {"id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "name": "Dev Subscription"},
        ],
        "gcp": [
            {"id": "prod-project-123", "name": "production-project"},
            {"id": "dev-project-456", "name": "development-project"},
        ],
    }

    # Resource types by cloud provider
    RESOURCE_TYPES = {
        "aws": ["ec2:instance", "s3:bucket", "iam:user", "rds:db-instance", "vpc:security-group"],
        "azure": [
            "microsoft.compute/virtualmachines",
            "microsoft.storage/storageaccounts",
            "microsoft.sql/servers",
        ],
        "gcp": [
            "compute.googleapis.com/Instance",
            "storage.googleapis.com/Bucket",
            "iam.googleapis.com/ServiceAccount",
        ],
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize CSPM generator."""
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        cloud_provider: CloudProvider = "aws",
        framework: ComplianceFramework | None = None,
        passed: bool | None = None,
        timestamp_offset: int = 0,
    ) -> dict[str, Any]:
        """
        Generate a single CSPM compliance finding.

        Args:
            cloud_provider: Cloud provider (aws, azure, gcp)
            framework: Compliance framework
            passed: Whether the check passed (None for random)
            timestamp_offset: Minutes to offset timestamp

        Returns:
            ECS-compliant CSPM finding dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Select rules based on provider
        if cloud_provider == "aws":
            rules = self.CIS_AWS_RULES
        elif cloud_provider == "azure":
            rules = self.CIS_AZURE_RULES
        else:
            rules = self.CIS_AWS_RULES  # Default to AWS

        rule = random.choice(rules)

        # Determine pass/fail
        if passed is None:
            # 70% pass rate by default
            passed = random.random() < 0.7

        # Select account
        accounts = self.CLOUD_ACCOUNTS.get(cloud_provider, self.CLOUD_ACCOUNTS["aws"])
        account = random.choice(accounts)

        # Select resource type
        resource_types = self.RESOURCE_TYPES.get(cloud_provider, self.RESOURCE_TYPES["aws"])
        resource_type = random.choice(resource_types)
        resource_id = f"{resource_type.split(':')[-1]}-{self.randomizer.generate_uuid()[:8]}"

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "state",
                "category": ["configuration"],
                "type": ["info"],
                "action": "compliance-check",
                "outcome": "success" if passed else "failure",
                "id": self.randomizer.generate_uuid(),
            },
            "rule": {
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "reference": f"https://www.cisecurity.org/benchmark/{cloud_provider}",
                "ruleset": framework or f"CIS {cloud_provider.upper()} Foundations Benchmark",
                "version": "1.4.0",
            },
            "cloud": {
                "provider": cloud_provider,
                "account": {
                    "id": account["id"],
                    "name": account["name"],
                },
            },
            "resource": {
                "type": resource_type,
                "id": resource_id,
                "name": f"{account['name']}-{resource_id}",
            },
            "result": {
                "evaluation": "passed" if passed else "failed",
                "evidence": {
                    "check_performed": rule["name"],
                    "expected": "Compliant",
                    "actual": "Compliant" if passed else "Non-compliant",
                },
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "cloud_security_posture.findings",
                "namespace": "default",
            },
        }

        # Add severity for failed checks
        if not passed:
            event["event"]["severity"] = {"name": rule["severity"]}

        return event

    def generate_batch(
        self,
        count: int,
        cloud_provider: CloudProvider = "aws",
        pass_rate: float = 0.7,
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of CSPM findings.

        Args:
            count: Number of findings to generate
            cloud_provider: Cloud provider
            pass_rate: Ratio of passing checks
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of CSPM finding dictionaries
        """
        events = []

        for i in range(count):
            passed = random.random() < pass_rate
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                cloud_provider=cloud_provider,
                passed=passed,
                timestamp_offset=timestamp_offset,
            )
            events.append(event)

        return events

    def generate_compliance_report(
        self,
        cloud_provider: CloudProvider = "aws",
        target_pass_rate: float = 0.75,
    ) -> list[dict[str, Any]]:
        """
        Generate a complete compliance report for a cloud account.

        Args:
            cloud_provider: Cloud provider
            target_pass_rate: Target compliance pass rate

        Returns:
            List of CSPM findings representing a compliance report
        """
        events = []

        # Use all rules for the provider
        if cloud_provider == "aws":
            rules = self.CIS_AWS_RULES
        elif cloud_provider == "azure":
            rules = self.CIS_AZURE_RULES
        else:
            rules = self.CIS_AWS_RULES

        for i, rule in enumerate(rules):
            passed = random.random() < target_pass_rate

            event = self.generate(
                cloud_provider=cloud_provider,
                passed=passed,
                timestamp_offset=i,
            )
            # Override with specific rule
            event["rule"]["id"] = rule["id"]
            event["rule"]["name"] = rule["name"]
            event["rule"]["description"] = rule["description"]

            events.append(event)

        return events


