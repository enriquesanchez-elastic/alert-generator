# MCP Server Integration Guide

This guide explains how to use the secgen Model Context Protocol (MCP) server with Claude Desktop and other MCP clients.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Configuration](#configuration)
- [Available Tools](#available-tools)
- [Example Workflows](#example-workflows)
- [Architecture](#architecture)
- [Development Status](#development-status)
- [Troubleshooting](#troubleshooting)

## Overview

The secgen MCP server enables Claude Desktop and other MCP clients to discover and use secgen's 15+ event generators and attack patterns through natural language. Instead of remembering complex CLI commands, users can simply describe what they need in conversation with Claude.

### Key Features

- **15 MCP Tools**: Organized into 5 categories (discovery, generation, world state, testing, utility)
- **Dry-Run by Default**: Safe exploration without accidental writes to Elasticsearch
- **Entity Correlation**: Session-based World state for consistent host.id and user.name across events
- **MITRE ATT&CK Integration**: All attack patterns mapped to TTPs with detection recommendations
- **ECS Compliance**: All generated events follow Elastic Common Schema
- **Safety Gates**: Indexing requires explicit confirmation flags to prevent accidental writes

## Installation

### Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- [Claude Desktop](https://claude.ai/download) (for Claude integration)

### Install secgen with MCP Support

```bash
# Clone repository
git clone https://github.com/enriquesanchez-elastic/secgen
cd secgen

# Install with uv (recommended)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .

# Or with pip
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

MCP dependencies (`mcp>=1.0.0` and `pytest-asyncio>=0.23.0`) are included automatically.

### Verify Installation

```bash
# Test MCP module imports
python -c "from secgen.mcp import SecGenMCPServer; print('MCP server ready!')"

# Start MCP server using the convenience script (recommended)
./run_mcp.sh

# Or using the CLI directly
secgen mcp

# With debug logging
./run_mcp.sh --log-level DEBUG
```

## Configuration

### Claude Desktop Configuration

Add the secgen MCP server to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "secgen": {
      "command": "secgen",
      "args": ["mcp"],
      "env": {
        "ELASTIC_URL": "localhost:9200",
        "ELASTIC_USERNAME": "elastic",
        "ELASTIC_PASSWORD": "changeme"
      }
    }
  }
}
```

### Using the Shell Script (Alternative)

Use the included `run_mcp.sh` script which handles virtual environment activation:

```json
{
  "mcpServers": {
    "secgen": {
      "command": "/path/to/alert-generator/run_mcp.sh",
      "args": [],
      "env": {
        "ELASTIC_URL": "localhost:9200",
        "ELASTIC_USERNAME": "elastic",
        "ELASTIC_PASSWORD": "changeme"
      }
    }
  }
}
```

### Using Full Path (Alternative)

If `secgen` is not in your PATH and you prefer not to use the script:

```json
{
  "mcpServers": {
    "secgen": {
      "command": "/full/path/to/.venv/bin/python",
      "args": ["-m", "secgen.mcp.server"],
      "env": {
        "ELASTIC_URL": "localhost:9200",
        "ELASTIC_USERNAME": "elastic",
        "ELASTIC_PASSWORD": "changeme"
      }
    }
  }
}
```

### Environment Variables

The MCP server respects these environment variables (configured in `claude_desktop_config.json` or `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTIC_URL` | `localhost:9200` | Elasticsearch URL (host:port) |
| `ELASTIC_USERNAME` | `elastic` | Elasticsearch username |
| `ELASTIC_PASSWORD` | `changeme` | Elasticsearch password |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Restart Claude Desktop

After updating the configuration, restart Claude Desktop to load the MCP server.

## Available Tools

The MCP server provides **15 tools** organized into 5 categories:

### Discovery Tools (✅ Fully Implemented)

| Tool | Description | Parameters |
|------|-------------|------------|
| `list_event_types` | List all available event generators | `category` (optional): Filter by category |
| `list_attack_patterns` | List attack patterns with MITRE TTPs | `category`, `ttp` (optional): Filter by category or TTP |
| `describe_event_type` | Get detailed metadata for an event type | `name` (required): Event type name |
| `describe_attack_pattern` | Get detailed metadata for an attack pattern | `name` (required): Attack pattern name |

**Categories**: `endpoint`, `network`, `identity`, `cloud`, `threat_intel`, `security`, `analytics`

### Generation Tools (✅ Fully Implemented)

| Tool | Description | Parameters |
|------|-------------|------------|
| `generate_events` | Generate events by type | `event_type` (required), `count`, `use_world`, `params` |
| `execute_attack` | Execute attack pattern (multi-event) | `pattern` (required), `count`, `use_world` |
| `generate_campaign` | Generate correlated attack campaign | `num_hosts`, `num_alerts`, `attack_speed`, `time_spread` |

### World State Tools (✅ Fully Implemented)

| Tool | Description | Parameters |
|------|-------------|------------|
| `create_world` | Create/reset World state | `num_hosts`, `num_users`, `reset` |
| `get_world_info` | Get World summary | None |
| `save_world` | Save World to file | `file_path` (required) |
| `load_world` | Load World from file | `file_path` (required) |

### Testing Tools (✅ Fully Implemented)

| Tool | Description | Parameters |
|------|-------------|------------|
| `test_elastic_feature` | Generate feature-specific test data | `feature` (required), `count` (optional) |

**Features**: `network-map`, `timeline`, `analyzer`, `entity-analytics`, `detection-rule`, `vulnerability-management`, `cloud-posture`

### Utility Tools (✅ Fully Implemented)

| Tool | Description | Parameters |
|------|-------------|------------|
| `validate_elasticsearch` | Check ES connection (read-only) | None |
| `get_capabilities` | Get server capabilities | None |
| `index_events` | Enable indexing (safety gate) | `enable_indexing`, `confirm` (both required=true) |

## Example Workflows

### Workflow 1: Explore Available Generators

**Scenario**: You want to understand what secgen can generate before creating test data.

```
You: "What kind of security events can secgen generate?"

Claude: [Calls list_event_types]
"secgen can generate 15+ event types across these categories:

• Endpoint: process, file, registry, endpoint-network events
• Network: DNS queries, HTTP traffic, TLS connections, network flows  
• Identity: authentication events, IAM audit logs
• Cloud: AWS CloudTrail, Azure audit, GCP audit logs
• Security: vulnerability scans, CSPM findings
• Analytics: risk scores, entity analytics

Which category would you like to explore?"

You: "Tell me more about the DNS event generator"

Claude: [Calls describe_event_type with name="dns"]
"The DNS event generator creates ECS-compliant DNS query logs:

• Index pattern: logs-dns.query-default
• ECS fields: dns.question.name, dns.question.type, dns.answers, 
  dns.response_code, source.ip, destination.ip
• Parameters: is_malicious (bool) - generates suspicious queries
  like DGA domains when true

This is perfect for testing DNS-based detections like tunneling,
DGA activity, or suspicious domain queries."
```

### Workflow 2: Find Attack Patterns by MITRE TTP

**Scenario**: You're building detection rules for credential-based attacks and need test data.

```
You: "Show me attack patterns for credential access techniques"

Claude: [Calls list_attack_patterns with ttp="T1110"]
"I found these credential-related attack patterns:

• brute-force (T1110.001, T1110.003)
  Simulates password guessing with multiple failed logins followed by success
  
• credential-stuffing (T1110.004)
  Uses known username/password pairs across multiple accounts

Each generates realistic authentication event sequences with proper
timing and entity correlation."

You: "Execute 5 iterations of the brute-force attack"

Claude: [Calls execute_attack with pattern="brute-force", count=5]
"Executed 5 brute-force attack iterations:

✓ Generated 75 authentication events total
  - 70 failed login attempts (event.outcome: failure)
  - 5 successful logins (event.outcome: success)

Events are correlated:
  - Same source.ip per attack iteration
  - Same target user.name sequence
  - Realistic timing (attempts spread over seconds)

MITRE ATT&CK: T1110.001 (Password Guessing), T1110.003 (Password Spraying)

Detection recommendations:
  - Alert on >5 failed logins from same source.ip in 5 minutes
  - Correlate failed logins followed by success from same source"
```

### Workflow 3: Generate Test Data for Detection Rules

**Scenario**: You're testing DNS tunneling detection rules and need realistic data.

```
You: "I need to test my DNS tunneling detection. Generate some data."

Claude: [Calls execute_attack with pattern="dns-tunneling", count=3]
"Generated DNS tunneling attack simulation:

✓ 450 DNS events across 3 attack iterations

Attack characteristics:
  - High-entropy subdomain queries (base64-encoded data)
  - Queries to same parent domain (tunnel.exfil.net)
  - TXT record queries (common for data exfiltration)
  - High query frequency per host

Sample event:
  dns.question.name: aGVsbG8td29ybGQ.tunnel.exfil.net
  dns.question.type: TXT
  source.ip: 10.0.1.45

MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)

Your detection rule should trigger on:
  - Unusually long subdomain names (>50 chars)
  - High volume of TXT queries to single domain
  - High entropy in subdomain strings"

You: "Now generate some normal DNS traffic to reduce false positives"

Claude: [Calls generate_events with event_type="dns", count=500, 
        params={"is_malicious": false}]
"Generated 500 benign DNS events:

• Common domains: google.com, microsoft.com, cloudflare.com
• Standard query types: A, AAAA, CNAME
• Normal subdomain patterns: www, mail, cdn

This gives you a realistic baseline to tune your detection thresholds."
```

### Workflow 4: Test Elastic Security Features

**Scenario**: You want to verify the Network Map visualization works correctly.

```
You: "I need to test Elastic's Network Map feature. Can you help?"

Claude: [Calls test_elastic_feature with feature="network-map"]
"Generated test data for Network Map visualization:

✓ 200 network events created
  - 50 internal-to-internal flows
  - 100 internal-to-external flows  
  - 50 external-to-internal flows

Events include:
  - source.ip, destination.ip (for node placement)
  - source.geo, destination.geo (for geographic mapping)
  - network.bytes, network.packets (for edge thickness)
  - network.community_id (for flow correlation)

View in Kibana: Security > Network > Network Map

Verification steps:
  1. Open Network Map in Elastic Security
  2. Verify nodes appear for unique IPs
  3. Check edges show traffic between hosts
  4. Confirm geographic placement is correct"
```

### Workflow 5: Build a Complete Test Environment

**Scenario**: You're preparing a demo environment for Elastic Security training.

```
You: "I'm doing an Elastic Security training tomorrow. I need a realistic 
environment with 20 hosts, 50 users, and various attack scenarios."

Claude: [Calls create_world with num_hosts=20, num_users=50]
"Created test environment:

Hosts (20 total):
  - Windows: 12 (workstations and servers)
  - Linux: 6 (servers)
  - macOS: 2 (developer workstations)

Users (50 total):
  - Standard users: 35
  - Administrators: 10
  - Service accounts: 5

All entities have consistent IDs for correlation across events."

You: "Generate a multi-stage attack campaign targeting this environment"

Claude: [Calls generate_campaign with num_hosts=5, num_alerts=30,
        attack_speed="medium", time_spread="hours"]
"Generated attack campaign spanning 4 hours:

Campaign ID: APT-2024-12-29-a3f2

Attack phases:
  1. Initial Access (T1566): Phishing emails to 3 users
  2. Execution (T1059): PowerShell scripts on compromised hosts
  3. Lateral Movement (T1021): RDP connections to 5 hosts
  4. Exfiltration (T1048): Data staged and exfiltrated

Timeline:
  - 09:00: Initial phishing attempt
  - 09:30: First payload execution
  - 10:15: Privilege escalation
  - 11:00: Lateral movement begins
  - 12:30: Data exfiltration detected

30 alerts generated across the campaign, all correlated by:
  - host.id (tracks which machines were compromised)
  - user.name (tracks which accounts were used)
  - process.entity_id (tracks process trees)

Perfect for demonstrating Timeline, Analyzer, and Entity Analytics!"

You: "Save this environment so I can reload it during the training"

Claude: [Calls save_world with file_path="training-demo.json"]
"World state saved to training-demo.json

To reload during training:
  - Ask me to 'load the training environment from training-demo.json'
  - Or use CLI: secgen world load training-demo.json"
```

### Workflow 6: Index Events to Elasticsearch

**Scenario**: You're ready to write test data to your Elastic cluster.

```
You: "I want to index these events to my Elasticsearch cluster"

Claude: [Calls validate_elasticsearch]
"Elasticsearch connection validated:

✓ Connected to: localhost:9200
✓ Cluster: my-cluster (health: green)
✓ Version: 8.12.0

Ready to index events."

You: "Enable indexing and generate 50 process events"

Claude: [Calls index_events with enable_indexing=true, confirm=true]
"⚠️ Elasticsearch indexing ENABLED for this session.

Generated events will now be written to Elasticsearch.
Indices: logs-endpoint.events.process-default and others.

Proceed with caution - this will modify your cluster data."

Claude: [Calls generate_events with event_type="process", count=50]
"Generated and indexed 50 process events:

✓ Indexed to: logs-endpoint.events.process-default
✓ All events have consistent host.id and user.name

View in Kibana: Discover > Select 'logs-*' index pattern"
```

## Real-World Use Cases

### Use Case 1: SOC Analyst Training

Create realistic attack scenarios for training new SOC analysts:

```
You: "Create a training scenario with 3 different attack types 
for our new SOC analysts to investigate"

Claude: I'll create three distinct attack scenarios for training:

[Executes brute-force, c2-beacon, and data-exfiltration attacks]

"Created 3 investigation scenarios:

Scenario 1 - Credential Attack:
  - 50 failed logins followed by success
  - Source: External IP 203.0.113.45
  - Target: user 'admin.jones'
  
Scenario 2 - Command & Control:
  - Beacon pattern every 60 seconds
  - C2 domain: update.suspicious-cdn.com
  - Affected host: WORKSTATION-PC12
  
Scenario 3 - Data Exfiltration:
  - Large file transfers to external IP
  - Source: FILE-SERVER-01
  - 500MB transferred over 2 hours

Each scenario has unique correlation IDs for Timeline investigation."
```

### Use Case 2: Detection Engineering

Test and tune detection rules before production deployment:

```
You: "I wrote a detection rule for PowerShell encoded commands. 
Generate test data to validate it."

Claude: [Generates process events with encoded PowerShell]

"Generated 25 events matching your detection criteria:

• Process: powershell.exe
• Arguments: -enc [base64 strings]
• Various base64 payloads (download cradles, reverse shells)

Also generated 100 benign PowerShell events to test for false positives:
• Common admin scripts
• Standard system maintenance commands

Your rule should trigger on the 25 malicious events and NOT 
on the 100 benign ones. Check your precision/recall!"
```

### Use Case 3: SIEM Migration Validation

Verify data flows correctly when migrating to Elastic:

```
You: "We're migrating to Elastic. Generate sample data for 
all our key log sources to verify ingestion."

Claude: [Generates events across all categories]

"Generated validation dataset:

✓ Windows Events: 200 (process, file, registry)
✓ Network Logs: 150 (DNS, HTTP, TLS, flows)
✓ Auth Logs: 100 (Windows, Linux, cloud SSO)
✓ Cloud Audit: 75 (AWS CloudTrail, Azure)
✓ Security Tools: 50 (vulnerability scans)

All events are ECS-compliant and should map correctly to 
Elastic's detection rules and dashboards.

Recommended verification:
1. Check each index has expected document count
2. Verify field mappings match ECS
3. Confirm dashboards show data
4. Test sample detection rules fire correctly"
```

### Use Case 4: Capacity Planning

Estimate storage and performance requirements:

```
You: "We expect 10,000 events per day. Generate a sample 
to estimate storage requirements."

Claude: [Generates 10,000 events across types]

"Generated 10,000 events (~1 day sample):

Distribution:
  - Process events: 4,000 (40%)
  - Network events: 3,000 (30%)
  - File events: 2,000 (20%)
  - Auth events: 1,000 (10%)

Estimated sizes:
  - Raw JSON: ~15 MB
  - Elasticsearch indexed: ~25 MB (with replicas)
  - Monthly storage: ~750 MB

Note: Actual sizes depend on field cardinality and 
your retention policies."
```

## Architecture

### MCP Server Components

```
secgen/mcp/
├── server.py              # Main MCP server (stdio transport)
├── state.py               # Session state management
├── schemas.py             # JSON schemas for tool arguments
├── formatters.py          # Response formatting utilities
└── tools/
    ├── discovery.py       # ✅ Discovery tools (fully implemented)
    ├── generation.py      # ✅ Generation tools (fully implemented)
    ├── world.py           # ✅ World state tools (fully implemented)
    ├── testing.py         # ✅ Testing tools (fully implemented)
    └── utility.py         # ✅ Utility tools (fully implemented)
```

### Session State Management

The MCP server maintains session state across tool calls:

- **World State**: Ephemeral World created on first use, persists for session duration
- **Event Tracking**: All generated events tracked with statistics
- **Configuration**: dry_run=true by default (safety feature)

```python
@dataclass
class MCPState:
    world: Optional[World] = None          # Entity correlation
    world_source: str = "none"             # "none", "ephemeral", "file"
    dry_run: bool = True                   # Safe default
    events_generated: list = []            # Track all events
    total_events_count: int = 0            # Event counter
    events_by_type: dict = {}              # Statistics
```

### Integration with Existing Code

The MCP server reuses existing secgen components to avoid code duplication:

1. **Registry System**: Discovery tools query `registry.py` for event types and attack patterns
2. **Core Operations**: Generation tools use `generators/core_operations.py` for shared logic
3. **World State**: Uses `core/world.py` for entity correlation
4. **Indexers**: Uses `indexers/elasticsearch.py` for optional indexing

### Design Decisions

| Decision | Rationale |
|----------|-----------|
| **stdio transport only** | Simplest for Claude Desktop, can add SSE/HTTP later |
| **Dry-run by default** | Safe exploration without accidental Elasticsearch writes |
| **Session-based World** | Entity correlation persists across tool calls |
| **Reuse existing handlers** | Single source of truth for business logic |
| **Async architecture** | Compatible with MCP SDK requirements |

## Development Status

### ✅ All Phases Complete

- [x] **Phase 1: Foundation**
  - Dependencies added to `pyproject.toml`
  - Module structure created
  - State management (`state.py`)
  - JSON schemas (`schemas.py`)
  - Response formatters (`formatters.py`)
  - Test suite for state management

- [x] **Phase 2: Core Server**
  - Main MCP server (`server.py`)
  - stdio transport setup
  - Tool registration (all 15 tools)
  - Tool routing logic
  - CLI integration (`secgen mcp` subcommand)

- [x] **Phase 3: Discovery Tools**
  - `list_event_types` - ✅ Working
  - `list_attack_patterns` - ✅ Working
  - `describe_event_type` - ✅ Working
  - `describe_attack_pattern` - ✅ Working

- [x] **Phase 4: Generation Tools**
  - `generate_events` - ✅ Working
  - `execute_attack` - ✅ Working
  - `generate_campaign` - ✅ Working

- [x] **Phase 5: World State Tools**
  - `create_world` - ✅ Working
  - `get_world_info` - ✅ Working
  - `save_world` - ✅ Working
  - `load_world` - ✅ Working

- [x] **Phase 6: Testing Tools**
  - `test_elastic_feature` - ✅ Working

- [x] **Phase 7: Utility Tools**
  - `validate_elasticsearch` - ✅ Working
  - `get_capabilities` - ✅ Working
  - `index_events` - ✅ Working

- [x] **Phase 8: Integration Tests**
  - Comprehensive test suite for all tools
  - Tests for state management
  - Tests for formatters

- [x] **Phase 9: Polish & Release**
  - Code quality checks
  - Documentation updated
  - Version 2.1.0

## Troubleshooting

### MCP Server Not Appearing in Claude Desktop

1. **Check configuration file path**:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. **Verify JSON syntax**:
   ```bash
   # On macOS/Linux
   python -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

3. **Use the run_mcp.sh script** (recommended):
   ```json
   {
     "mcpServers": {
       "secgen": {
         "command": "/full/path/to/alert-generator/run_mcp.sh"
       }
     }
   }
   ```

4. **Restart Claude Desktop** after configuration changes

### JSON Parse Errors in Claude Desktop Logs

If you see errors like `Unexpected non-whitespace character after JSON at position 4`:

This means logging output is being mixed with JSON-RPC messages on stdout. The MCP server should redirect all logging to stderr.

**Solution**: Ensure you're using the latest version of `secgen/mcp/server.py` which includes `_configure_logging_to_stderr()`.

Check logs at:
- macOS: `~/Library/Logs/Claude/mcp-server-secgen.log`
- Windows: `%APPDATA%\Claude\logs\mcp-server-secgen.log`

### ModuleNotFoundError: No module named 'mcp'

```bash
# Install MCP dependencies
uv pip install mcp pytest-asyncio

# Or reinstall secgen
uv pip install -e .
```

### AttributeError: module 'mcp.types' has no attribute 'NotificationOptions'

This error occurs with certain MCP library versions. The fix is to import `NotificationOptions` from `mcp.server` instead of `mcp.types`:

```python
# Correct import
from mcp.server import NotificationOptions, Server
```

Ensure you're using the latest `secgen/mcp/server.py`.

### Connection to Elasticsearch Failed

The MCP server uses environment variables from `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secgen": {
      "command": "/path/to/run_mcp.sh",
      "env": {
        "ELASTIC_URL": "localhost:9200",
        "ELASTIC_USERNAME": "elastic",
        "ELASTIC_PASSWORD": "changeme"
      }
    }
  }
}
```

Test connection manually:
```bash
curl -u elastic:changeme http://localhost:9200
```

**Note**: Elasticsearch connection is only needed if you enable indexing. The MCP server works in dry-run mode without Elasticsearch.

### Enable Debug Logging

```bash
# Start server manually with debug logging
./run_mcp.sh --log-level DEBUG

# Or using CLI
secgen mcp --log-level DEBUG

# Or add to Claude Desktop config
{
  "mcpServers": {
    "secgen": {
      "command": "/path/to/run_mcp.sh",
      "args": ["--log-level", "DEBUG"]
    }
  }
}
```

### Test MCP Server Manually

Test the server outside of Claude Desktop:

```bash
# Test basic startup
./run_mcp.sh 2>&1 | head -5

# Test with JSON-RPC message
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":0}' | \
  python -m secgen mcp 2>/dev/null | head -1

# Expected output (clean JSON, no log messages):
# {"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18",...}}
```

## Contributing

To contribute to MCP server development:

1. **Add new tools**: Follow the pattern in `secgen/mcp/tools/` for new capabilities
2. **Add tests**: Create tests in `tests/test_mcp/` for any new functionality
3. **Update documentation**: Keep this guide in sync with new features
4. **Follow existing patterns**: Use `core_operations.py` for shared logic, maintain async architecture

### Adding a New MCP Tool

1. Define the JSON schema in `secgen/mcp/schemas.py`
2. Add the tool registration in `secgen/mcp/server.py` (`_register_tools()`)
3. Implement the handler in the appropriate `secgen/mcp/tools/*.py` file
4. Add formatting functions in `secgen/mcp/formatters.py` if needed
5. Write tests in `tests/test_mcp/`

See [CONTRIBUTING.md](../CONTRIBUTING.md) for general contribution guidelines.

## Resources

- **MCP Specification**: https://modelcontextprotocol.io/
- **MCP Python SDK**: https://github.com/modelcontextprotocol/python-sdk
- **Claude Desktop**: https://claude.ai/download
- **secgen Documentation**: https://github.com/enriquesanchez-elastic/secgen

## License

MIT License - See [LICENSE](../LICENSE) for details.
