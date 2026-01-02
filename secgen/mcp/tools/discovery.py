"""Discovery tools for MCP server.

This module implements tools for discovering available event types and attack patterns:
- list_event_types: List event generators with optional category filtering
- list_attack_patterns: List attack patterns with optional TTP filtering
- describe_event_type: Get detailed metadata for an event type
- describe_attack_pattern: Get detailed metadata for an attack pattern
"""

import logging
from typing import Any

from secgen.mcp import formatters
from secgen.mcp.state import MCPState
from secgen.registry import GeneratorCategory, get_registry

logger = logging.getLogger(__name__)


async def handle_tool(
    name: str,
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Route discovery tool calls to appropriate handlers.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: MCP session state

    Returns:
        JSON string with tool response
    """
    if name == "list_event_types":
        return await _handle_list_event_types(arguments, state)
    elif name == "list_attack_patterns":
        return await _handle_list_attack_patterns(arguments, state)
    elif name == "describe_event_type":
        return await _handle_describe_event_type(arguments, state)
    elif name == "describe_attack_pattern":
        return await _handle_describe_attack_pattern(arguments, state)
    else:
        return formatters.format_error_response(
            error=f"Unknown discovery tool: {name}",
            tool=name,
        )


async def _handle_list_event_types(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle list_event_types tool.

    Args:
        arguments: Tool arguments with optional 'category' filter
        state: MCP session state

    Returns:
        JSON string with list of event types
    """
    try:
        registry = get_registry()

        # Parse category filter
        category_filter = None
        if "category" in arguments and arguments["category"]:
            try:
                category_filter = GeneratorCategory(arguments["category"])
            except ValueError:
                return formatters.format_error_response(
                    error=f"Invalid category: {arguments['category']}",
                    tool="list_event_types",
                    suggestion=(
                        "Valid categories: " + ", ".join(c.value for c in GeneratorCategory)
                    ),
                )

        # Get event types
        event_types = registry.list_event_types(category=category_filter)

        # Format response
        event_types_data = [
            {
                "name": et.name,
                "category": et.category.value,
                "description": et.description,
                "index_pattern": et.index_pattern,
                "example_params": et.example_params,
            }
            for et in event_types
        ]

        logger.info(f"Listed {len(event_types_data)} event types")
        return formatters.format_event_types_list(event_types_data)

    except Exception as e:
        logger.error(f"Error listing event types: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="list_event_types",
        )


async def _handle_list_attack_patterns(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle list_attack_patterns tool.

    Args:
        arguments: Tool arguments with optional 'category' and 'ttp' filters
        state: MCP session state

    Returns:
        JSON string with list of attack patterns
    """
    try:
        registry = get_registry()

        # Parse category filter
        category_filter = None
        if "category" in arguments and arguments["category"]:
            try:
                category_filter = GeneratorCategory(arguments["category"])
            except ValueError:
                return formatters.format_error_response(
                    error=f"Invalid category: {arguments['category']}",
                    tool="list_attack_patterns",
                    suggestion=(
                        "Valid categories: " + ", ".join(c.value for c in GeneratorCategory)
                    ),
                )

        # Parse TTP filter
        ttp_filter = arguments.get("ttp")

        # Get attack patterns
        attack_patterns = registry.list_attack_patterns(
            category=category_filter,
            ttp=ttp_filter,
        )

        # Format response
        attack_patterns_data = [
            {
                "name": ap.name,
                "category": ap.category.value,
                "description": ap.description,
                "ttps": ap.ttps,
                "event_types": ap.event_types,
            }
            for ap in attack_patterns
        ]

        logger.info(f"Listed {len(attack_patterns_data)} attack patterns")
        return formatters.format_attack_patterns_list(attack_patterns_data)

    except Exception as e:
        logger.error(f"Error listing attack patterns: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="list_attack_patterns",
        )


async def _handle_describe_event_type(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle describe_event_type tool.

    Args:
        arguments: Tool arguments with 'name' (required)
        state: MCP session state

    Returns:
        JSON string with event type metadata
    """
    try:
        registry = get_registry()

        # Get event type name
        name = arguments.get("name")
        if not name:
            return formatters.format_error_response(
                error="Missing required argument: name",
                tool="describe_event_type",
                suggestion="Provide event type name (e.g., 'dns', 'file', 'process')",
            )

        # Get metadata
        metadata = registry.get_event_type(name)
        if not metadata:
            # Suggest similar names
            all_types = registry.list_event_types()
            available_names = [et.name for et in all_types]

            return formatters.format_error_response(
                error=f"Event type '{name}' not found",
                tool="describe_event_type",
                suggestion=(
                    f"Available event types: {', '.join(available_names[:10])}"
                    + ("..." if len(available_names) > 10 else "")
                ),
            )

        # Format response
        event_type_data = {
            "name": metadata.name,
            "category": metadata.category.value,
            "description": metadata.description,
            "ecs_fields": metadata.ecs_fields,
            "index_pattern": metadata.index_pattern,
            "example_params": metadata.example_params,
            "generator_class": metadata.generator_class.__name__,
        }

        logger.info(f"Described event type: {name}")
        return formatters.format_event_type_description(event_type_data)

    except Exception as e:
        logger.error(f"Error describing event type: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="describe_event_type",
        )


async def _handle_describe_attack_pattern(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle describe_attack_pattern tool.

    Args:
        arguments: Tool arguments with 'name' (required)
        state: MCP session state

    Returns:
        JSON string with attack pattern metadata
    """
    try:
        registry = get_registry()

        # Get attack pattern name
        name = arguments.get("name")
        if not name:
            return formatters.format_error_response(
                error="Missing required argument: name",
                tool="describe_attack_pattern",
                suggestion="Provide attack pattern name (e.g., 'brute-force', 'c2-beacon')",
            )

        # Get metadata
        metadata = registry.get_attack_pattern(name)
        if not metadata:
            # Suggest similar names
            all_patterns = registry.list_attack_patterns()
            available_names = [ap.name for ap in all_patterns]

            return formatters.format_error_response(
                error=f"Attack pattern '{name}' not found",
                tool="describe_attack_pattern",
                suggestion=(
                    f"Available attack patterns: {', '.join(available_names[:10])}"
                    + ("..." if len(available_names) > 10 else "")
                ),
            )

        # Format response
        attack_pattern_data = {
            "name": metadata.name,
            "category": metadata.category.value,
            "description": metadata.description,
            "ttps": metadata.ttps,
            "mitre_attck_references": [
                f"https://attack.mitre.org/techniques/{ttp.split('.')[0]}/" for ttp in metadata.ttps
            ],
            "required_params": metadata.required_params,
            "optional_params": metadata.optional_params,
            "event_types": metadata.event_types,
            "detection_recommendations": metadata.detection_recommendations,
            "generator_class": metadata.generator_class.__name__,
            "method_name": metadata.method_name,
        }

        logger.info(f"Described attack pattern: {name}")
        return formatters.format_attack_pattern_description(attack_pattern_data)

    except Exception as e:
        logger.error(f"Error describing attack pattern: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="describe_attack_pattern",
        )
