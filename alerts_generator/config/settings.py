"""Application settings with environment variable support."""

import os
from typing import Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback for Pydantic v1
    from pydantic import BaseSettings

from pydantic import Field, field_validator


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    All settings can be overridden via environment variables or .env file.
    """

    # Elasticsearch connection
    elastic_url: str = Field(
        default="localhost:9200",
        env="ELASTIC_URL",
        description="Elasticsearch URL (host:port)",
    )
    elastic_username: str = Field(
        default="elastic",
        env="ELASTIC_USERNAME",
        description="Elasticsearch username",
    )
    elastic_password: str = Field(
        default="changeme",
        env="ELASTIC_PASSWORD",
        description="Elasticsearch password",
    )

    # Index configuration
    alerts_index: str = Field(
        default=".alerts-security.alerts-default",
        env="ALERTS_INDEX",
        description="Kibana alerts index",
    )

    # Rule configuration
    elastic_security_rule_id: str = Field(
        default="9a1a2dae-0b5f-4c3d-8305-a268d404c306",
        env="ELASTIC_SECURITY_RULE_ID",
        description="Elastic Security rule ID",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        env="LOG_LEVEL",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    log_json: bool = Field(
        default=False,
        env="LOG_JSON",
        description="Enable JSON formatted logging",
    )

    @field_validator("elastic_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate Elasticsearch URL format."""
        if not v or "://" in v:
            # If protocol is included, strip it
            v = v.replace("https://", "").replace("http://", "")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()

    def _is_elastic_cloud_url(self, url: str) -> bool:
        """Check if URL is an Elastic Cloud domain."""
        # Elastic Cloud URLs typically contain .es. or end with .elastic-cloud.com
        return ".es." in url or url.endswith(".elastic-cloud.com")

    @property
    def elastic_url_with_protocol(self) -> str:
        """Get Elasticsearch URL with protocol."""
        # Check environment variable first, then fall back to instance value
        url = os.getenv("ELASTIC_URL", self.elastic_url)

        # If URL already has a protocol, return as-is
        if "://" in url:
            return url

        # Determine protocol based on URL type
        # Elastic Cloud requires HTTPS, localhost/private IPs can use HTTP
        if self._is_elastic_cloud_url(url) or not url.startswith(
            ("localhost", "127.0.0.1", "10.", "172.", "192.168.")
        ):
            return f"https://{url}"
        else:
            return f"http://{url}"

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


# Global settings instance (can be overridden)
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get application settings instance.

    Returns:
        Settings instance (singleton pattern)
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
