"""Base class for LLM artifact generators."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from secgen.llm.cache import ArtifactCache
from secgen.llm.client import GeminiClient

logger = logging.getLogger(__name__)


class BaseArtifactGenerator(ABC):
    """
    Base class for LLM-based artifact generators.

    Provides common functionality for:
    - Cache checking before generation
    - Saving generated artifacts
    - Error handling and logging
    """

    # Override in subclasses
    ARTIFACT_TYPE: str = "base"

    def __init__(
        self,
        client: GeminiClient,
        cache: ArtifactCache,
    ) -> None:
        """
        Initialize artifact generator.

        Args:
            client: Gemini client for LLM calls
            cache: Artifact cache for storage
        """
        self.client = client
        self.cache = cache

    @abstractmethod
    def generate(self, **kwargs: Any) -> dict[str, Any]:
        """
        Generate artifact data.

        Args:
            **kwargs: Generator-specific parameters

        Returns:
            Generated artifact data
        """
        pass

    @abstractmethod
    def get_artifact_name(self, **kwargs: Any) -> str:
        """
        Get the artifact name for caching.

        Args:
            **kwargs: Same parameters as generate()

        Returns:
            Artifact name string
        """
        pass

    def generate_or_load(
        self,
        force_regenerate: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate artifact or load from cache if available.

        Args:
            force_regenerate: If True, regenerate even if cached
            **kwargs: Generator-specific parameters

        Returns:
            Artifact data (from cache or freshly generated)
        """
        artifact_name = self.get_artifact_name(**kwargs)

        # Check cache first
        if not force_regenerate:
            cached = self._load_from_cache(artifact_name)
            if cached is not None:
                logger.info(f"Loaded {self.ARTIFACT_TYPE} artifact from cache: {artifact_name}")
                return cached

        # Generate new artifact
        logger.info(f"Generating new {self.ARTIFACT_TYPE} artifact: {artifact_name}")
        data = self.generate(**kwargs)

        # Save to cache
        self._save_to_cache(artifact_name, data, kwargs)

        return data

    def _load_from_cache(self, artifact_name: str) -> dict[str, Any] | None:
        """
        Load artifact from cache.

        Args:
            artifact_name: Name of artifact to load

        Returns:
            Cached data or None if not found
        """
        # Try JSON first, then YAML
        data = self.cache.load_json(self.ARTIFACT_TYPE, artifact_name)
        if data is not None:
            return data

        data = self.cache.load_yaml(self.ARTIFACT_TYPE, artifact_name)
        return data

    def _save_to_cache(
        self,
        artifact_name: str,
        data: dict[str, Any],
        params: dict[str, Any],
    ) -> None:
        """
        Save artifact to cache.

        Args:
            artifact_name: Name for the artifact
            data: Artifact data to save
            params: Generation parameters (for metadata)
        """
        # Determine format based on artifact type
        if self.ARTIFACT_TYPE in ["scenarios", "profiles", "campaigns"]:
            self.cache.save_yaml(
                self.ARTIFACT_TYPE,
                artifact_name,
                data,
                metadata={"params": str(params)},
            )
        else:
            self.cache.save_json(
                self.ARTIFACT_TYPE,
                artifact_name,
                data,
                metadata={"params": str(params)},
            )

    def list_cached(self) -> list[dict[str, Any]]:
        """
        List all cached artifacts of this type.

        Returns:
            List of artifact info dictionaries
        """
        return self.cache.list_artifacts(self.ARTIFACT_TYPE)

    def delete_cached(self, artifact_name: str) -> bool:
        """
        Delete a cached artifact.

        Args:
            artifact_name: Name of artifact to delete

        Returns:
            True if deleted, False if not found
        """
        # Try both extensions
        deleted = self.cache.delete(self.ARTIFACT_TYPE, artifact_name, "json")
        if not deleted:
            deleted = self.cache.delete(self.ARTIFACT_TYPE, artifact_name, "yaml")
        return deleted

