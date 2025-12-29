"""Cloud event generators for AWS, Azure, and GCP audit logs."""

from secgen.generators.cloud.aws import AWSCloudTrailGenerator
from secgen.generators.cloud.azure import AzureAuditGenerator
from secgen.generators.cloud.gcp import GCPAuditGenerator

__all__ = [
    "AWSCloudTrailGenerator",
    "AzureAuditGenerator",
    "GCPAuditGenerator",
]
