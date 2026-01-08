"""Response formatting utilities for MCP tools.

This module provides consistent JSON formatting for all MCP tool responses.
All responses follow a standard structure with success flag, data, and optional metadata.
"""

import json
from typing import Any


def format_success_response(data: dict[str, Any], **metadata: Any) -> str:
    """Format a successful tool response.

    Args:
        data: Response data dictionary
        **metadata: Additional metadata to include in response

    Returns:
        JSON string with success response
    """
    response = {
        "success": True,
        **data,
    }

    if metadata:
        response["metadata"] = metadata

    return json.dumps(response, indent=2, default=str)


def format_error_response(
    error: str,
    tool: str,
    suggestion: str | None = None,
    **context: Any,
) -> str:
    """Format an error response.

    Args:
        error: Error message
        tool: Tool name that generated the error
        suggestion: Optional suggestion for recovery
        **context: Additional context about the error

    Returns:
        JSON string with error response
    """
    response: dict[str, Any] = {
        "success": False,
        "error": error,
        "tool": tool,
    }

    if suggestion:
        response["suggestion"] = suggestion

    if context:
        response["context"] = context

    return json.dumps(response, indent=2)


def format_event_types_list(event_types: list[dict[str, Any]]) -> str:
    """Format list of event types.

    Args:
        event_types: List of event type metadata dictionaries

    Returns:
        JSON string with formatted event types
    """
    return format_success_response(
        {
            "count": len(event_types),
            "event_types": event_types,
        }
    )


def format_attack_patterns_list(attack_patterns: list[dict[str, Any]]) -> str:
    """Format list of attack patterns.

    Args:
        attack_patterns: List of attack pattern metadata dictionaries

    Returns:
        JSON string with formatted attack patterns
    """
    return format_success_response(
        {
            "count": len(attack_patterns),
            "attack_patterns": attack_patterns,
        }
    )


def format_event_type_description(metadata: dict[str, Any]) -> str:
    """Format detailed event type description.

    Args:
        metadata: Event type metadata dictionary

    Returns:
        JSON string with detailed description
    """
    return format_success_response(metadata)


def format_attack_pattern_description(metadata: dict[str, Any]) -> str:
    """Format detailed attack pattern description.

    Args:
        metadata: Attack pattern metadata dictionary

    Returns:
        JSON string with detailed description
    """
    return format_success_response(metadata)


def format_generation_summary(
    event_type: str,
    count: int,
    events_summary: dict[str, Any],
    world_summary: dict[str, Any] | None = None,
) -> str:
    """Format event generation summary.

    Args:
        event_type: Type of events generated
        count: Number of events generated
        events_summary: Summary of generated events
        world_summary: Optional World state summary

    Returns:
        JSON string with generation summary
    """
    data: dict[str, Any] = {
        "event_type": event_type,
        "events_generated": count,
        "summary": events_summary,
    }

    if world_summary:
        data["world_state"] = world_summary

    return format_success_response(data)


def format_attack_execution_summary(
    pattern: str,
    iterations: int,
    total_events: int,
    events_by_type: dict[str, int],
    ttps: list[str],
    detection_recommendations: list[str],
    world_summary: dict[str, Any] | None = None,
) -> str:
    """Format attack pattern execution summary.

    Args:
        pattern: Attack pattern name
        iterations: Number of iterations executed
        total_events: Total events generated
        events_by_type: Events grouped by type
        ttps: MITRE ATT&CK TTPs
        detection_recommendations: Detection rule recommendations
        world_summary: Optional World state summary

    Returns:
        JSON string with attack execution summary
    """
    data: dict[str, Any] = {
        "attack_pattern": pattern,
        "iterations": iterations,
        "total_events": total_events,
        "events_by_type": events_by_type,
        "mitre_attck": {
            "ttps": ttps,
            "references": [
                f"https://attack.mitre.org/techniques/{ttp.split('.')[0]}/" for ttp in ttps
            ],
        },
        "detection": {
            "recommendations": detection_recommendations,
        },
    }

    if world_summary:
        data["world_state"] = world_summary

    return format_success_response(data)


def format_world_summary(
    source: str,
    summary: dict[str, Any],
    file_path: str | None = None,
) -> str:
    """Format World state summary.

    Args:
        source: World source ("ephemeral", "file", "none")
        summary: World summary dictionary
        file_path: Optional file path if loaded from file

    Returns:
        JSON string with World summary
    """
    data: dict[str, Any] = {
        "source": source,
        **summary,
    }

    if file_path:
        data["file_path"] = file_path

    return format_success_response(data)


def format_capabilities_response(
    version: str,
    event_types_count: int,
    attack_patterns_count: int,
    categories: list[str],
    features: list[str],
) -> str:
    """Format capabilities response.

    Args:
        version: secgen version
        event_types_count: Number of event types
        attack_patterns_count: Number of attack patterns
        categories: List of generator categories
        features: List of testable Elastic features

    Returns:
        JSON string with capabilities
    """
    return format_success_response(
        {
            "version": version,
            "capabilities": {
                "event_types": event_types_count,
                "attack_patterns": attack_patterns_count,
                "categories": categories,
                "testable_features": features,
            },
            "safety": {
                "dry_run_default": True,
                "indexing_requires_confirmation": True,
            },
        }
    )


def format_validation_result(
    connected: bool,
    cluster_info: dict[str, Any] | None = None,
    error: str | None = None,
) -> str:
    """Format Elasticsearch validation result.

    Args:
        connected: Whether connection succeeded
        cluster_info: Optional cluster information
        error: Optional error message

    Returns:
        JSON string with validation result
    """
    data: dict[str, Any] = {
        "connected": connected,
    }

    if cluster_info:
        data["cluster"] = cluster_info

    if error:
        data["error"] = error

    return format_success_response(data)


def format_indexing_result(
    indexed: bool,
    event_count: int,
    indices: list[str],
    error: str | None = None,
) -> str:
    """Format indexing result.

    Args:
        indexed: Whether indexing succeeded
        event_count: Number of events indexed
        indices: List of indices written to
        error: Optional error message

    Returns:
        JSON string with indexing result
    """
    data: dict[str, Any] = {
        "indexed": indexed,
        "events_count": event_count,
        "indices": indices,
    }

    if error:
        data["error"] = error

    return format_success_response(data)
