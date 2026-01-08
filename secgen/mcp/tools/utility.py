"""Utility tools for MCP server.

This module implements utility tools:
- validate_elasticsearch: Check ES connection
- get_capabilities: Get server capabilities
- index_events: Enable indexing to Elasticsearch
"""

import logging
from typing import Any

import requests

from secgen.config.settings import Settings
from secgen.mcp import formatters
from secgen.mcp.state import MCPState
from secgen.registry import GeneratorCategory, get_registry
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)

# Version for MCP server
MCP_VERSION = "2.1.0"

# Features available for testing
TESTABLE_FEATURES = [
    "network-map",
    "timeline",
    "analyzer",
    "entity-analytics",
    "detection-rule",
    "vulnerability-management",
    "cloud-posture",
]


async def handle_tool(
    name: str,
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Route utility tool calls to appropriate handlers.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with tool response
    """
    if name == "validate_elasticsearch":
        return await _handle_validate_elasticsearch(arguments, state, settings)
    elif name == "get_capabilities":
        return await _handle_get_capabilities(arguments, state)
    elif name == "index_events":
        return await _handle_index_events(arguments, state)
    else:
        return formatters.format_error_response(
            error=f"Unknown utility tool: {name}",
            tool=name,
        )


async def _handle_validate_elasticsearch(
    arguments: dict[str, Any],
    state: MCPState,
    settings: Settings,
) -> str:
    """Handle validate_elasticsearch tool.

    Args:
        arguments: Tool arguments (none required)
        state: MCP session state
        settings: Application settings

    Returns:
        JSON string with validation result
    """
    try:
        base_url = settings.elastic_url_with_protocol

        # Try to get cluster info (read-only operation)
        response = requests.get(
            base_url,
            auth=(settings.elastic_username, settings.elastic_password),
            timeout=10,
            verify=True,
        )

        if response.status_code == 200:
            cluster_info = response.json()

            logger.info(
                f"Connected to Elasticsearch cluster: {cluster_info.get('cluster_name', 'unknown')}"
            )

            return formatters.format_validation_result(
                connected=True,
                cluster_info={
                    "cluster_name": cluster_info.get("cluster_name"),
                    "cluster_uuid": cluster_info.get("cluster_uuid"),
                    "version": cluster_info.get("version", {}).get("number"),
                    "tagline": cluster_info.get("tagline"),
                },
            )
        else:
            logger.warning(f"Elasticsearch connection failed: {response.status_code}")

            return formatters.format_validation_result(
                connected=False,
                error=f"HTTP {response.status_code}: {response.text[:200]}",
            )

    except requests.exceptions.ConnectionError as e:
        logger.error(f"Cannot connect to Elasticsearch: {e}")
        return formatters.format_validation_result(
            connected=False,
            error=f"Connection failed: Cannot reach {settings.elastic_url_with_protocol}",
        )

    except requests.exceptions.Timeout:
        logger.error("Elasticsearch connection timed out")
        return formatters.format_validation_result(
            connected=False,
            error="Connection timed out after 10 seconds",
        )

    except Exception as e:
        logger.error(f"Error validating Elasticsearch: {e}", exc_info=True)
        return formatters.format_validation_result(
            connected=False,
            error=str(e),
        )


async def _handle_get_capabilities(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle get_capabilities tool.

    Args:
        arguments: Tool arguments (none required)
        state: MCP session state

    Returns:
        JSON string with server capabilities
    """
    try:
        # Ensure registry is bootstrapped
        ensure_bootstrapped()
        registry = get_registry()

        # Count event types and attack patterns
        event_types = registry.list_event_types()
        attack_patterns = registry.list_attack_patterns()

        # Get categories
        categories = sorted(set(c.value for c in GeneratorCategory))

        logger.info("Retrieved server capabilities")

        return formatters.format_capabilities_response(
            version=MCP_VERSION,
            event_types_count=len(event_types),
            attack_patterns_count=len(attack_patterns),
            categories=categories,
            features=TESTABLE_FEATURES,
        )

    except Exception as e:
        logger.error(f"Error getting capabilities: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="get_capabilities",
        )


async def _handle_index_events(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle index_events tool.

    This is a safety gate that enables indexing of generated events.
    Requires explicit confirmation flags to prevent accidental writes.

    Args:
        arguments: Tool arguments with enable_indexing and confirm flags
        state: MCP session state

    Returns:
        JSON string with indexing configuration result
    """
    try:
        enable_indexing = arguments.get("enable_indexing", False)
        confirm = arguments.get("confirm", False)

        # Safety check: both flags must be explicitly true
        if not enable_indexing or not confirm:
            return formatters.format_error_response(
                error="Indexing requires explicit confirmation",
                tool="index_events",
                suggestion=(
                    "Set both enable_indexing=true AND confirm=true to enable indexing. "
                    "This is a safety feature to prevent accidental writes to Elasticsearch."
                ),
            )

        # Enable indexing
        state.enable_indexing = True
        state.dry_run = False

        logger.warning("Elasticsearch indexing ENABLED by user confirmation")

        return formatters.format_success_response(
            {
                "indexing_enabled": True,
                "dry_run": False,
                "warning": (
                    "Indexing is now enabled. Generated events will be written to Elasticsearch. "
                    "Use generate_events or execute_attack to create and index events."
                ),
                "session_stats": {
                    "events_pending": len(state.events_generated),
                    "total_generated": state.total_events_count,
                },
            }
        )

    except Exception as e:
        logger.error(f"Error configuring indexing: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="index_events",
        )
