"""Tests for ElasticsearchIndexer."""

from unittest.mock import MagicMock, patch

import requests

from alerts_generator.indexers.elasticsearch import ElasticsearchIndexer


def test_index_alert_successful_indexing(settings):
    """Test that index_alert() handles successful indexing."""
    indexer = ElasticsearchIndexer(settings)

    alert = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test"},
    }

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {"_id": "test-id", "result": "created"}

    with patch("requests.post", return_value=mock_response):
        result = indexer.index_alert(alert)

        assert result is not None
        assert result["_id"] == "test-id"
        assert result["result"] == "created"


def test_index_alert_handles_http_errors(settings):
    """Test that index_alert() handles HTTP errors."""
    indexer = ElasticsearchIndexer(settings)

    alert = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test"},
    }

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"

    with patch("requests.post", return_value=mock_response):
        result = indexer.index_alert(alert)

        assert result is None


def test_index_events_bulk_indexing(settings):
    """Test that index_events() handles bulk indexing."""
    indexer = ElasticsearchIndexer(settings)

    events = [
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": {"id": "event1"},
        }
    ]
    endpoint_alert = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "event": {"kind": "alert"},
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "items": [{"create": {"_id": "id1", "status": 201}}],
        "errors": False,
    }

    with patch("requests.post", return_value=mock_response):
        result = indexer.index_events(events, endpoint_alert)

        assert result is not None
        assert result["errors"] is False


def test_index_events_handles_bulk_errors(settings):
    """Test that index_events() handles bulk errors."""
    indexer = ElasticsearchIndexer(settings)

    events = [
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": {"id": "event1"},
        }
    ]
    endpoint_alert = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "event": {"kind": "alert"},
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "items": [{"create": {"error": {"type": "error"}}}],
        "errors": True,
    }

    with patch("requests.post", return_value=mock_response):
        result = indexer.index_events(events, endpoint_alert)

        # Should still return result even with errors
        assert result is not None


def test_delete_all_deletes_from_all_indices(settings):
    """Test that delete_all() deletes from all indices."""
    indexer = ElasticsearchIndexer(settings)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"deleted": 10}

    with patch("requests.post", return_value=mock_response):
        result = indexer.delete_all()

        assert result["alerts_index"]["success"] is True
        assert result["alerts_index"]["deleted_count"] == 10
        # Should call multiple times for different indices
        assert mock_response.status_code == 200


def test_delete_all_handles_missing_indices(settings):
    """Test that delete_all() handles missing indices gracefully."""
    indexer = ElasticsearchIndexer(settings)

    # First call returns 404, subsequent calls return 200
    mock_responses = [
        MagicMock(status_code=404, json=lambda: {}),
        MagicMock(status_code=200, json=lambda: {"deleted": 5}),
        MagicMock(status_code=200, json=lambda: {"deleted": 3}),
    ]

    with patch("requests.post", side_effect=mock_responses):
        result = indexer.delete_all()

        # Should handle 404 gracefully
        assert "alerts_index" in result
        assert "process_events" in result
        assert "endpoint_alerts" in result


def test_delete_all_error_handling_for_connection_issues(settings):
    """Test that delete_all() handles connection issues."""
    indexer = ElasticsearchIndexer(settings)

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError()):
        result = indexer.delete_all()

        # Should return results structure even on error
        assert "alerts_index" in result
        assert "process_events" in result
        assert "endpoint_alerts" in result


def test_index_alert_handles_timeout(settings):
    """Test that index_alert() handles timeout."""
    indexer = ElasticsearchIndexer(settings)

    alert = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "agent": {"id": "test"},
    }

    with patch("requests.post", side_effect=requests.exceptions.Timeout()):
        result = indexer.index_alert(alert)

        assert result is None
