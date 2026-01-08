"""Tests for artifact cache."""

import json
import tempfile
from pathlib import Path

import pytest

from secgen.llm.cache import ArtifactCache


class TestArtifactCache:
    """Tests for ArtifactCache."""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def cache(self, temp_cache_dir):
        """Create a cache instance with temp directory."""
        return ArtifactCache(base_dir=temp_cache_dir, enabled=True)

    def test_init_creates_directories(self, temp_cache_dir):
        """Test that cache initialization creates subdirectories."""
        cache = ArtifactCache(base_dir=temp_cache_dir, enabled=True)

        for subdir in cache.SUBDIRS:
            assert (Path(temp_cache_dir) / subdir).exists()

    def test_disabled_cache_returns_none(self, temp_cache_dir):
        """Test that disabled cache returns None on load."""
        # First create a cache that saves something
        enabled_cache = ArtifactCache(base_dir=temp_cache_dir, enabled=True)
        enabled_cache.save_json("commands", "test", {"data": "value"})

        # Now create disabled cache - it should not be able to load
        disabled_cache = ArtifactCache(base_dir=temp_cache_dir, enabled=False)
        assert disabled_cache.load_json("commands", "test") is None
        assert not disabled_cache.exists("commands", "test")

    def test_save_and_load_json(self, cache):
        """Test saving and loading JSON artifacts."""
        data = {"commands": {"test": ["cmd1", "cmd2"]}}

        cache.save_json("commands", "test_artifact", data)

        loaded = cache.load_json("commands", "test_artifact")
        assert loaded is not None
        assert loaded["commands"] == data["commands"]
        assert "_metadata" in loaded

    def test_save_and_load_yaml(self, cache):
        """Test saving and loading YAML artifacts."""
        pytest.importorskip("yaml")

        data = {"personas": [{"role": "Admin", "department": "IT"}]}

        cache.save_yaml("profiles", "test_profile", data)

        loaded = cache.load_yaml("profiles", "test_profile")
        assert loaded is not None
        assert loaded["personas"] == data["personas"]

    def test_exists(self, cache):
        """Test exists method."""
        assert not cache.exists("commands", "nonexistent")

        cache.save_json("commands", "exists_test", {"data": "test"})
        assert cache.exists("commands", "exists_test")

    def test_get_path(self, cache, temp_cache_dir):
        """Test get_path method."""
        path = cache.get_path("commands", "test", "json")
        expected = Path(temp_cache_dir) / "commands" / "test.json"
        assert path == expected

    def test_get_path_invalid_type(self, cache):
        """Test get_path with invalid artifact type."""
        with pytest.raises(ValueError, match="Invalid artifact type"):
            cache.get_path("invalid_type", "test", "json")

    def test_list_artifacts(self, cache):
        """Test listing artifacts."""
        # Initially empty
        assert cache.list_artifacts("commands") == []

        # Add some artifacts
        cache.save_json("commands", "artifact1", {"data": 1})
        cache.save_json("commands", "artifact2", {"data": 2})

        artifacts = cache.list_artifacts("commands")
        assert len(artifacts) == 2

        names = [a["name"] for a in artifacts]
        assert "artifact1" in names
        assert "artifact2" in names

    def test_delete(self, cache):
        """Test deleting artifacts."""
        cache.save_json("commands", "to_delete", {"data": "test"})
        assert cache.exists("commands", "to_delete")

        result = cache.delete("commands", "to_delete")
        assert result is True
        assert not cache.exists("commands", "to_delete")

        # Deleting non-existent returns False
        result = cache.delete("commands", "to_delete")
        assert result is False

    def test_clear_single_type(self, cache):
        """Test clearing artifacts of a single type."""
        cache.save_json("commands", "cmd1", {"data": 1})
        cache.save_json("commands", "cmd2", {"data": 2})
        cache.save_json("profiles", "prof1", {"data": 3})

        count = cache.clear("commands")
        assert count == 2

        assert cache.list_artifacts("commands") == []
        assert len(cache.list_artifacts("profiles")) == 1

    def test_clear_all(self, cache):
        """Test clearing all artifacts."""
        cache.save_json("commands", "cmd1", {"data": 1})
        cache.save_json("profiles", "prof1", {"data": 2})

        count = cache.clear()
        assert count == 2

        for atype in cache.SUBDIRS:
            assert cache.list_artifacts(atype) == []

    def test_get_stats(self, cache):
        """Test getting cache statistics."""
        cache.save_json("commands", "cmd1", {"data": "test" * 100})
        cache.save_json("profiles", "prof1", {"data": "test"})

        stats = cache.get_stats()

        assert stats["enabled"] is True
        assert stats["total_artifacts"] == 2
        assert stats["total_size_bytes"] > 0
        assert stats["by_type"]["commands"]["count"] == 1
        assert stats["by_type"]["profiles"]["count"] == 1

    def test_metadata_included(self, cache):
        """Test that metadata is included in saved artifacts."""
        cache.save_json(
            "commands",
            "with_meta",
            {"data": "test"},
            metadata={"custom_key": "custom_value"},
        )

        loaded = cache.load_json("commands", "with_meta")
        assert loaded is not None
        assert "_metadata" in loaded
        assert "created_at" in loaded["_metadata"]
        assert loaded["_metadata"]["custom_key"] == "custom_value"

