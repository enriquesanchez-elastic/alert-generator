"""Model Context Protocol (MCP) server for secgen.

This module provides an MCP server that exposes secgen's event generators
and attack patterns to Claude Desktop and other MCP clients.

The MCP server provides 15 tools organized into categories:
- Discovery (4): list/describe event types and attack patterns
- Generation (3): generate events, execute attacks, create campaigns
- World State (4): create/get/save/load World for entity correlation
- Testing (1): test Elastic Security features
- Utility (3): validate ES, get capabilities, index events

Usage:
    # Start MCP server via CLI
    $ secgen mcp

    # Or programmatically
    from secgen.mcp.server import SecGenMCPServer
    import asyncio

    server = SecGenMCPServer()
    asyncio.run(server.run())
"""

from secgen.mcp.server import SecGenMCPServer
from secgen.mcp.state import MCPState

__version__ = "2.1.0"

__all__ = ["SecGenMCPServer", "MCPState"]
