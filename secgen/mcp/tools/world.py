"""World state tools for MCP server.

This module implements tools for managing World state:
- create_world: Create/reset World state
- get_world_info: Get World summary
- save_world: Save World to file
- load_world: Load World from file
"""

import logging
import os
from pathlib import Path
from typing import Any

from secgen.mcp import formatters
from secgen.mcp.state import MCPState

logger = logging.getLogger(__name__)


def _validate_file_path(file_path: str) -> tuple[bool, str]:
    """Validate file path for security.

    Prevents path traversal attacks and ensures path is reasonable.

    Args:
        file_path: Path to validate

    Returns:
        Tuple of (is_valid, error_message or resolved_path)
    """
    try:
        # Resolve to absolute path
        resolved = Path(file_path).resolve()

        # Check for path traversal attempts
        if ".." in file_path:
            return False, "Path traversal detected: '..' not allowed in file path"

        # Ensure it's a JSON file
        if not str(resolved).endswith(".json"):
            return False, "File must have .json extension"

        # Check the path is not trying to write to sensitive locations
        sensitive_paths = ["/etc", "/usr", "/bin", "/sbin", "/var", "/root"]
        for sensitive in sensitive_paths:
            if str(resolved).startswith(sensitive):
                return False, f"Cannot write to system path: {sensitive}"

        return True, str(resolved)

    except Exception as e:
        return False, f"Invalid file path: {e}"


async def handle_tool(
    name: str,
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Route World state tool calls to appropriate handlers.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: MCP session state

    Returns:
        JSON string with tool response
    """
    if name == "create_world":
        return await _handle_create_world(arguments, state)
    elif name == "get_world_info":
        return await _handle_get_world_info(arguments, state)
    elif name == "save_world":
        return await _handle_save_world(arguments, state)
    elif name == "load_world":
        return await _handle_load_world(arguments, state)
    else:
        return formatters.format_error_response(
            error=f"Unknown World state tool: {name}",
            tool=name,
        )


async def _handle_create_world(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle create_world tool.

    Args:
        arguments: Tool arguments with optional num_hosts, num_users, reset
        state: MCP session state

    Returns:
        JSON string with World creation result
    """
    try:
        num_hosts = arguments.get("num_hosts", 10)
        num_users = arguments.get("num_users", 20)
        reset = arguments.get("reset", False)

        # Validate parameters
        if num_hosts < 1 or num_hosts > 1000:
            return formatters.format_error_response(
                error=f"num_hosts must be between 1 and 1000, got {num_hosts}",
                tool="create_world",
            )

        if num_users < 1 or num_users > 5000:
            return formatters.format_error_response(
                error=f"num_users must be between 1 and 5000, got {num_users}",
                tool="create_world",
            )

        # Check if World already exists and reset not requested
        if state.world is not None and not reset:
            return formatters.format_error_response(
                error="World already exists. Use reset=true to create a new one.",
                tool="create_world",
                suggestion="Set reset=true to replace existing World state",
            )

        # Create World
        world = state.get_or_create_world(
            num_hosts=num_hosts,
            num_users=num_users,
            reset=reset,
        )

        # Get summary
        summary = world.summary()

        logger.info(f"Created World with {num_hosts} hosts and {num_users} users")

        return formatters.format_world_summary(
            source=state.world_source,
            summary=summary,
        )

    except Exception as e:
        logger.error(f"Error creating World: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="create_world",
        )


async def _handle_get_world_info(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle get_world_info tool.

    Args:
        arguments: Tool arguments (none required)
        state: MCP session state

    Returns:
        JSON string with World information
    """
    try:
        if state.world is None:
            return formatters.format_error_response(
                error="No World state exists",
                tool="get_world_info",
                suggestion="Use create_world or load_world to create World state first",
            )

        # Get full session summary including World
        session_summary = state.get_session_summary()

        logger.info("Retrieved World info")

        return formatters.format_success_response(session_summary)

    except Exception as e:
        logger.error(f"Error getting World info: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="get_world_info",
        )


async def _handle_save_world(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle save_world tool.

    Args:
        arguments: Tool arguments with file_path (required)
        state: MCP session state

    Returns:
        JSON string with save result
    """
    try:
        file_path = arguments.get("file_path")

        if not file_path:
            return formatters.format_error_response(
                error="Missing required argument: file_path",
                tool="save_world",
                suggestion="Provide a file path (e.g., 'world.json')",
            )

        # Validate file path
        is_valid, result = _validate_file_path(file_path)
        if not is_valid:
            return formatters.format_error_response(
                error=result,
                tool="save_world",
                suggestion="Use a simple filename like 'world.json' or a safe path",
            )

        validated_path = result

        # Check World exists
        if state.world is None:
            return formatters.format_error_response(
                error="No World state to save",
                tool="save_world",
                suggestion="Use create_world first to create World state",
            )

        # Save World
        state.save_world_to_file(validated_path)

        logger.info(f"Saved World to: {validated_path}")

        return formatters.format_success_response(
            {
                "saved": True,
                "file_path": validated_path,
                "world_summary": state.world.summary(),
            }
        )

    except Exception as e:
        logger.error(f"Error saving World: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="save_world",
        )


async def _handle_load_world(
    arguments: dict[str, Any],
    state: MCPState,
) -> str:
    """Handle load_world tool.

    Args:
        arguments: Tool arguments with file_path (required)
        state: MCP session state

    Returns:
        JSON string with load result
    """
    try:
        file_path = arguments.get("file_path")

        if not file_path:
            return formatters.format_error_response(
                error="Missing required argument: file_path",
                tool="load_world",
                suggestion="Provide a file path (e.g., 'world.json')",
            )

        # Validate file path
        is_valid, result = _validate_file_path(file_path)
        if not is_valid:
            return formatters.format_error_response(
                error=result,
                tool="load_world",
                suggestion="Use a valid JSON file path",
            )

        validated_path = result

        # Check file exists
        if not os.path.exists(validated_path):
            return formatters.format_error_response(
                error=f"File not found: {validated_path}",
                tool="load_world",
                suggestion="Check the file path and ensure the file exists",
            )

        # Load World
        world = state.load_world_from_file(validated_path)

        logger.info(f"Loaded World from: {validated_path}")

        return formatters.format_world_summary(
            source=state.world_source,
            summary=world.summary(),
            file_path=validated_path,
        )

    except Exception as e:
        logger.error(f"Error loading World: {e}", exc_info=True)
        return formatters.format_error_response(
            error=str(e),
            tool="load_world",
        )
