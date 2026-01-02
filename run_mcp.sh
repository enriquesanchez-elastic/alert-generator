#!/bin/bash
# MCP Server launcher for secgen
#
# This script starts the secgen MCP server for use with Claude Desktop
# or other MCP-compatible clients.
#
# Usage:
#   ./run_mcp.sh              # Start with default settings
#   ./run_mcp.sh --log-level DEBUG  # Start with debug logging
#
# Environment variables (optional):
#   ELASTIC_URL       - Elasticsearch URL (default: localhost:9200)
#   ELASTIC_USERNAME  - Elasticsearch username (default: elastic)
#   ELASTIC_PASSWORD  - Elasticsearch password (default: changeme)

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate virtual environment if it exists
if [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    source "$SCRIPT_DIR/.venv/bin/activate"
elif [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Run the MCP server
exec python -m secgen mcp "$@"


