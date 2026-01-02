"""MCP server implementation for secgen.

This module provides the main MCP server that exposes secgen's event generators
and attack patterns to Claude Desktop and other MCP clients via stdio transport.
"""

import asyncio
import logging
import sys
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from secgen.config.settings import get_settings
from secgen.mcp import schemas
from secgen.mcp.formatters import format_error_response
from secgen.mcp.state import MCPState
from secgen.registry_bootstrap import ensure_bootstrapped

logger = logging.getLogger(__name__)


class SecGenMCPServer:
    """MCP server for security data generation.

    This server exposes 15 tools organized into categories:
    - Discovery (4): list/describe event types and attack patterns
    - Generation (3): generate events, execute attacks, create campaigns
    - World State (4): create/get/save/load World
    - Testing (1): test Elastic Security features
    - Utility (3): validate ES, get capabilities, index events
    """

    def __init__(self) -> None:
        """Initialize MCP server."""
        self.server = Server("secgen-mcp")
        self.state = MCPState()
        self.settings = get_settings()

        # Bootstrap registry (loads all generators)
        ensure_bootstrapped()

        # Register tool handlers
        self._register_tools()

        logger.info("SecGen MCP server initialized")

    def _register_tools(self) -> None:
        """Register all MCP tools."""

        # =================================================================
        # LIST TOOLS
        # =================================================================

        @self.server.list_tools()
        async def list_tools() -> list[types.Tool]:
            """List all available MCP tools."""
            return [
                # Discovery Tools (4)
                types.Tool(
                    name="list_event_types",
                    description=(
                        "List all available event type generators with optional category filtering. "
                        "Returns event type names, descriptions, categories, and index patterns."
                    ),
                    inputSchema=schemas.LIST_EVENT_TYPES_SCHEMA,
                ),
                types.Tool(
                    name="list_attack_patterns",
                    description=(
                        "List all available attack patterns with optional filtering by category or "
                        "MITRE ATT&CK TTP. Returns attack pattern names, descriptions, TTPs, and "
                        "detection recommendations."
                    ),
                    inputSchema=schemas.LIST_ATTACK_PATTERNS_SCHEMA,
                ),
                types.Tool(
                    name="describe_event_type",
                    description=(
                        "Get detailed metadata for a specific event type including ECS fields, "
                        "index pattern, example parameters, and generator information."
                    ),
                    inputSchema=schemas.DESCRIBE_EVENT_TYPE_SCHEMA,
                ),
                types.Tool(
                    name="describe_attack_pattern",
                    description=(
                        "Get detailed metadata for a specific attack pattern including MITRE TTPs, "
                        "required parameters, event types generated, and detection recommendations."
                    ),
                    inputSchema=schemas.DESCRIBE_ATTACK_PATTERN_SCHEMA,
                ),
                # Generation Tools (3)
                types.Tool(
                    name="generate_events",
                    description=(
                        "Generate events of a specific type with optional parameters. Uses World "
                        "state for entity correlation by default. Events are generated in dry-run "
                        "mode (not indexed) unless explicitly enabled."
                    ),
                    inputSchema=schemas.GENERATE_EVENTS_SCHEMA,
                ),
                types.Tool(
                    name="execute_attack",
                    description=(
                        "Execute an attack pattern which generates multiple correlated events "
                        "representing a realistic attack sequence. Uses World state for entity "
                        "correlation."
                    ),
                    inputSchema=schemas.EXECUTE_ATTACK_SCHEMA,
                ),
                types.Tool(
                    name="generate_campaign",
                    description=(
                        "Generate a coordinated attack campaign targeting multiple hosts with "
                        "realistic time distribution and phase progression (initial access, "
                        "execution, lateral movement, exfiltration)."
                    ),
                    inputSchema=schemas.GENERATE_CAMPAIGN_SCHEMA,
                ),
                # World State Tools (4)
                types.Tool(
                    name="create_world",
                    description=(
                        "Create or reset World state with hosts and users for entity correlation. "
                        "World state persists across tool calls within the same session."
                    ),
                    inputSchema=schemas.CREATE_WORLD_SCHEMA,
                ),
                types.Tool(
                    name="get_world_info",
                    description=(
                        "Get summary of current World state including host counts by OS, user counts "
                        "by type, and entity statistics."
                    ),
                    inputSchema=schemas.GET_WORLD_INFO_SCHEMA,
                ),
                types.Tool(
                    name="save_world",
                    description=(
                        "Save current World state to a JSON file for persistence across sessions."
                    ),
                    inputSchema=schemas.SAVE_WORLD_SCHEMA,
                ),
                types.Tool(
                    name="load_world",
                    description=("Load World state from a previously saved JSON file."),
                    inputSchema=schemas.LOAD_WORLD_SCHEMA,
                ),
                # Testing Tools (1)
                types.Tool(
                    name="test_elastic_feature",
                    description=(
                        "Generate data specifically designed to test Elastic Security features like "
                        "network-map, timeline, analyzer, entity-analytics, detection-rule, "
                        "vulnerability-management, or cloud-posture."
                    ),
                    inputSchema=schemas.TEST_ELASTIC_FEATURE_SCHEMA,
                ),
                # Utility Tools (3)
                types.Tool(
                    name="validate_elasticsearch",
                    description=(
                        "Validate Elasticsearch connection and get cluster information (read-only check)."
                    ),
                    inputSchema=schemas.VALIDATE_ELASTICSEARCH_SCHEMA,
                ),
                types.Tool(
                    name="get_capabilities",
                    description=(
                        "Get MCP server capabilities including supported event types, attack patterns, "
                        "categories, and features."
                    ),
                    inputSchema=schemas.GET_CAPABILITIES_SCHEMA,
                ),
                types.Tool(
                    name="index_events",
                    description=(
                        "Enable indexing of generated events to Elasticsearch. Requires explicit "
                        "confirmation flags (enable_indexing=true AND confirm=true). Safety gate "
                        "to prevent accidental writes."
                    ),
                    inputSchema=schemas.INDEX_EVENTS_SCHEMA,
                ),
            ]

        # =================================================================
        # CALL TOOL
        # =================================================================

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            """Route tool calls to appropriate handlers."""
            try:
                logger.info(f"Tool called: {name} with arguments: {arguments}")

                # Route to appropriate tool category
                if name in ["list_event_types", "list_attack_patterns"]:
                    result = await self._handle_list_tools(name, arguments)
                elif name in ["describe_event_type", "describe_attack_pattern"]:
                    result = await self._handle_describe_tools(name, arguments)
                elif name in ["generate_events", "execute_attack", "generate_campaign"]:
                    result = await self._handle_generation_tools(name, arguments)
                elif name in ["create_world", "get_world_info", "save_world", "load_world"]:
                    result = await self._handle_world_tools(name, arguments)
                elif name == "test_elastic_feature":
                    result = await self._handle_testing_tool(name, arguments)
                elif name in ["validate_elasticsearch", "get_capabilities", "index_events"]:
                    result = await self._handle_utility_tools(name, arguments)
                else:
                    result = format_error_response(
                        error=f"Unknown tool: {name}",
                        tool=name,
                        suggestion="Use list_tools to see available tools",
                    )

                return [types.TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Tool execution error: {e}", exc_info=True)
                error_msg = format_error_response(
                    error=str(e),
                    tool=name,
                    suggestion="Check tool arguments and try again",
                )
                return [types.TextContent(type="text", text=error_msg)]

    # =====================================================================
    # TOOL HANDLERS (Stubs - to be implemented)
    # =====================================================================

    async def _handle_list_tools(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle list tools (list_event_types, list_attack_patterns)."""
        # Import here to avoid circular imports
        from secgen.mcp.tools import discovery

        return await discovery.handle_tool(name, arguments, self.state)

    async def _handle_describe_tools(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle describe tools (describe_event_type, describe_attack_pattern)."""
        from secgen.mcp.tools import discovery

        return await discovery.handle_tool(name, arguments, self.state)

    async def _handle_generation_tools(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle generation tools (generate_events, execute_attack, generate_campaign)."""
        from secgen.mcp.tools import generation

        return await generation.handle_tool(name, arguments, self.state, self.settings)

    async def _handle_world_tools(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle World state tools."""
        from secgen.mcp.tools import world

        return await world.handle_tool(name, arguments, self.state)

    async def _handle_testing_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle testing tool (test_elastic_feature)."""
        from secgen.mcp.tools import testing

        return await testing.handle_tool(name, arguments, self.state, self.settings)

    async def _handle_utility_tools(self, name: str, arguments: dict[str, Any]) -> str:
        """Handle utility tools."""
        from secgen.mcp.tools import utility

        return await utility.handle_tool(name, arguments, self.state, self.settings)

    # =====================================================================
    # SERVER LIFECYCLE
    # =====================================================================

    async def run(self) -> None:
        """Run the MCP server with stdio transport."""
        logger.info("Starting SecGen MCP server (stdio mode)")

        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="secgen-mcp",
                    server_version="2.1.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


def _configure_logging_to_stderr() -> None:
    """Configure ALL logging to go to stderr.

    MCP protocol requires stdout to be reserved exclusively for JSON-RPC messages.
    Any logging to stdout will corrupt the JSON-RPC stream and cause parse errors.
    """
    # Create stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )

    # Configure root logger - this affects all loggers that don't have handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    # Remove any existing handlers (which might write to stdout)
    root_logger.handlers.clear()
    root_logger.addHandler(stderr_handler)

    # Explicitly configure the MCP library's logger to use stderr
    # The MCP library creates its own logger that might bypass root config
    mcp_logger = logging.getLogger("mcp")
    mcp_logger.handlers.clear()
    mcp_logger.addHandler(stderr_handler)
    mcp_logger.propagate = False  # Don't double-log to root

    # Also configure our own logger
    secgen_logger = logging.getLogger("secgen")
    secgen_logger.handlers.clear()
    secgen_logger.addHandler(stderr_handler)
    secgen_logger.propagate = False


async def main() -> None:
    """Main entry point for MCP server."""
    # CRITICAL: Configure logging BEFORE any MCP operations
    # stdout must be clean for JSON-RPC protocol
    _configure_logging_to_stderr()

    # Create and run server
    server = SecGenMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
