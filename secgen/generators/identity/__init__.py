"""Identity event generators for authentication and IAM events."""

from secgen.generators.identity.auth import AuthenticationEventGenerator
from secgen.generators.identity.iam import IAMEventGenerator

__all__ = [
    "AuthenticationEventGenerator",
    "IAMEventGenerator",
]
