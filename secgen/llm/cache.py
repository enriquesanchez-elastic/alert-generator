"""Artifact caching for LLM-generated content."""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ArtifactCache:
    """
    Cache manager for LLM-generated artifacts.

    Artifacts are stored locally to avoid redundant API calls.
    Each artifact type has its own subdirectory:
    - commands/     Command libraries
    - scenarios/    Scenario variations
    - profiles/     Entity behavior profiles
    - campaigns/    Campaign narratives
    """

    SUBDIRS = ["commands", "scenarios", "profiles", "campaigns"]

    def __init__(self, base_dir: str, enabled: bool = True) -> None:
        """
        Initialize artifact cache.

        Args:
            base_dir: Base directory for artifact storage
            enabled: Whether caching is enabled
        """
        self.base_dir = Path(os.path.expanduser(base_dir))
        self.enabled = enabled

        if self.enabled:
            self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create cache directory structure if it doesn't exist."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        for subdir in self.SUBDIRS:
            (self.base_dir / subdir).mkdir(exist_ok=True)
        logger.debug(f"Artifact cache directory: {self.base_dir}")

    def _get_cache_key(self, artifact_type: str, params: dict[str, Any]) -> str:
        """
        Generate a cache key from artifact type and parameters.

        Args:
            artifact_type: Type of artifact (commands, scenarios, etc.)
            params: Parameters that uniquely identify the artifact

        Returns:
            SHA256 hash as cache key
        """
        # Sort params for consistent hashing
        param_str = json.dumps(params, sort_keys=True)
        content = f"{artifact_type}:{param_str}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get_path(self, artifact_type: str, name: str, extension: str = "json") -> Path:
        """
        Get the full path for an artifact file.

        Args:
            artifact_type: Type of artifact (commands, scenarios, etc.)
            name: Artifact name (used as filename)
            extension: File extension (json or yaml)

        Returns:
            Full path to artifact file
        """
        if artifact_type not in self.SUBDIRS:
            raise ValueError(
                f"Invalid artifact type: {artifact_type}. Must be one of {self.SUBDIRS}"
            )
        return self.base_dir / artifact_type / f"{name}.{extension}"

    def exists(self, artifact_type: str, name: str, extension: str = "json") -> bool:
        """
        Check if an artifact exists in the cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name
            extension: File extension

        Returns:
            True if artifact exists
        """
        if not self.enabled:
            return False
        return self.get_path(artifact_type, name, extension).exists()

    def load_json(self, artifact_type: str, name: str) -> dict[str, Any] | None:
        """
        Load a JSON artifact from cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name

        Returns:
            Parsed JSON data, or None if not found
        """
        if not self.enabled:
            return None

        path = self.get_path(artifact_type, name, "json")
        if not path.exists():
            return None

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            logger.debug(f"Loaded artifact from cache: {path}")
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load cached artifact {path}: {e}")
            return None

    def load_yaml(self, artifact_type: str, name: str) -> dict[str, Any] | None:
        """
        Load a YAML artifact from cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name

        Returns:
            Parsed YAML data, or None if not found
        """
        if not self.enabled:
            return None

        if not YAML_AVAILABLE:
            logger.warning("PyYAML not available, cannot load YAML artifacts")
            return None

        path = self.get_path(artifact_type, name, "yaml")
        if not path.exists():
            return None

        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            logger.debug(f"Loaded artifact from cache: {path}")
            return data
        except (yaml.YAMLError, OSError) as e:
            logger.warning(f"Failed to load cached artifact {path}: {e}")
            return None

    def save_json(
        self,
        artifact_type: str,
        name: str,
        data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """
        Save a JSON artifact to cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name
            data: Data to save
            metadata: Optional metadata to include

        Returns:
            Path to saved artifact
        """
        path = self.get_path(artifact_type, name, "json")

        # Add metadata
        artifact = {
            "_metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "artifact_type": artifact_type,
                "name": name,
                **(metadata or {}),
            },
            **data,
        }

        with path.open("w", encoding="utf-8") as f:
            json.dump(artifact, f, indent=2, default=str)

        logger.info(f"Saved artifact to cache: {path}")
        return path

    def save_yaml(
        self,
        artifact_type: str,
        name: str,
        data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """
        Save a YAML artifact to cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name
            data: Data to save
            metadata: Optional metadata to include

        Returns:
            Path to saved artifact
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML not available. Install with: pip install pyyaml")

        path = self.get_path(artifact_type, name, "yaml")

        # Add metadata as comment header
        header = f"# Generated: {datetime.now(timezone.utc).isoformat()}\n"
        header += f"# Type: {artifact_type}\n"
        header += f"# Name: {name}\n"
        if metadata:
            for key, value in metadata.items():
                header += f"# {key}: {value}\n"
        header += "\n"

        with path.open("w", encoding="utf-8") as f:
            f.write(header)
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Saved artifact to cache: {path}")
        return path

    def list_artifacts(self, artifact_type: str) -> list[dict[str, Any]]:
        """
        List all artifacts of a given type.

        Args:
            artifact_type: Type of artifact to list

        Returns:
            List of artifact info dictionaries
        """
        if artifact_type not in self.SUBDIRS:
            raise ValueError(f"Invalid artifact type: {artifact_type}")

        artifacts = []
        subdir = self.base_dir / artifact_type

        if not subdir.exists():
            return artifacts

        for path in subdir.iterdir():
            if path.is_file() and path.suffix in [".json", ".yaml"]:
                stat = path.stat()
                artifacts.append(
                    {
                        "name": path.stem,
                        "path": str(path),
                        "extension": path.suffix[1:],
                        "size_bytes": stat.st_size,
                        "modified_at": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )

        return sorted(artifacts, key=lambda x: x["modified_at"], reverse=True)

    def delete(self, artifact_type: str, name: str, extension: str = "json") -> bool:
        """
        Delete an artifact from cache.

        Args:
            artifact_type: Type of artifact
            name: Artifact name
            extension: File extension

        Returns:
            True if artifact was deleted, False if not found
        """
        path = self.get_path(artifact_type, name, extension)
        if path.exists():
            path.unlink()
            logger.info(f"Deleted artifact: {path}")
            return True
        return False

    def clear(self, artifact_type: str | None = None) -> int:
        """
        Clear artifacts from cache.

        Args:
            artifact_type: Type to clear, or None for all types

        Returns:
            Number of artifacts deleted
        """
        count = 0
        types_to_clear = [artifact_type] if artifact_type else self.SUBDIRS

        for atype in types_to_clear:
            if atype not in self.SUBDIRS:
                continue
            subdir = self.base_dir / atype
            if subdir.exists():
                for path in subdir.iterdir():
                    if path.is_file():
                        path.unlink()
                        count += 1

        logger.info(f"Cleared {count} artifacts from cache")
        return count

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        stats = {
            "base_dir": str(self.base_dir),
            "enabled": self.enabled,
            "total_artifacts": 0,
            "total_size_bytes": 0,
            "by_type": {},
        }

        for artifact_type in self.SUBDIRS:
            artifacts = self.list_artifacts(artifact_type)
            type_size = sum(a["size_bytes"] for a in artifacts)
            stats["by_type"][artifact_type] = {
                "count": len(artifacts),
                "size_bytes": type_size,
            }
            stats["total_artifacts"] += len(artifacts)
            stats["total_size_bytes"] += type_size

        return stats


def get_artifact_cache(settings: Any) -> ArtifactCache:
    """
    Create an artifact cache from settings.

    Args:
        settings: Settings object with llm_artifacts_path and llm_cache_enabled

    Returns:
        Configured ArtifactCache instance
    """
    return ArtifactCache(
        base_dir=settings.llm_artifacts_path,
        enabled=settings.llm_cache_enabled,
    )
