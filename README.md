# Security Data Generator for Elastic

A comprehensive, modular tool for generating realistic, ECS-compliant security data for testing Elastic Security Solution. Supports correlated attack campaigns, multi-event-type generation, World state management for entity correlation, and extensive coverage of security data sources.

## Features

- **Multi-Event-Type Generation**: Process, file, registry, network, DNS, authentication, cloud, and threat intelligence events
- **Beat Event Generators**: Auditbeat, Packetbeat, and Filebeat format events for realistic agent simulation
- **World State Management**: Persistent entity correlation across all event types (host.id, user.name, process.entity_id)
- **Attack Campaigns**: Correlated multi-phase attacks with shared threat actor infrastructure
- **MITRE ATT&CK Integration**: Full threat mapping with tactics, techniques, and subtechniques
- **Attack Discovery**: Generate attack discovery documents with correlated findings
- **Security Cases**: Full Elastic Cases API-compatible case management documents
- **Detection Rules**: Pre-built rule templates with MITRE mappings
- **Cloud Security**: AWS CloudTrail, Azure AD, and GCP audit log generation
- **Network Security**: DNS, HTTP, TLS with JA3 fingerprints, and geo-enriched network flows
- **Threat Intelligence**: Coordinated IOC generation for indicator matching rules
- **ECS Compliance**: Full Elastic Common Schema compliance for all event types

> 📖 **NEW!** For documentation on Beat generators, Attack Discovery, Cases, and MITRE integration, see [docs/FEATURES.md](docs/FEATURES.md)

## Installation

### Using uv (Recommended)

[uv](https://docs.astral.sh/uv/) is a fast Python package installer and resolver.

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/enriquesanchez-elastic/secgen
cd secgen
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

### Development Installation with uv

```bash
uv pip install -e ".[dev]"
```

### Using pip

```bash
git clone https://github.com/enriquesanchez-elastic/secgen
cd secgen
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

### Development Installation with pip

```bash
pip install -e ".[dev]"
```

### Dependencies

The project requires Python 3.10+ and these packages (installed automatically):
- `requests` - HTTP client for Elasticsearch
- `pydantic` / `pydantic-settings` - Configuration management
- `pyyaml` - YAML scenario file support
- `python-dotenv` - Environment variable support

## Quick Start

### Discovery Commands

```bash
# List all available event types
python -m secgen list event-types

# List attack patterns with MITRE ATT&CK TTP filtering
python -m secgen list attack-patterns --ttp T1110

# Describe an event type in detail
python -m secgen describe event-type dns

# Describe an attack pattern
python -m secgen describe attack brute-force
```

### Generate Events by Type

> **Note**: Add `--index` to send events to Elasticsearch. Without it, events are generated and displayed but not indexed.

```bash
# Generate DNS events (dry run - displays summary only)
python -m secgen generate dns --count 50

# Generate with malicious parameter and index to Elasticsearch
python -m secgen generate dns --count 50 --param is_malicious=true --index

# Generate vulnerability scan findings
python -m secgen generate vulnerability --count 100 --param severity=critical --index

# Generate risk scores for Entity Analytics
python -m secgen generate risk-score --use-world --count 30 --index
```

### Execute Attack Patterns

```bash
# Execute brute-force attack pattern
python -m secgen attack brute-force --count 3 --index

# Execute C2 beaconing
python -m secgen attack c2-beacon --world-file qa-world.json --index

# Execute DGA activity
python -m secgen attack dga-activity --index
```

### Beat Event Generation 

```bash
# Generate Auditbeat events
python -m secgen generate auditbeat --count 50 --param dataset=auditd --index
python -m secgen generate auditbeat --count 20 --param dataset=system.login --param is_malicious=true --index

# Generate Packetbeat events
python -m secgen generate packetbeat --count 100 --param dataset=dns --index
python -m secgen generate packetbeat --count 50 --param dataset=http --param is_malicious=true --index

# Generate Filebeat events
python -m secgen generate filebeat --count 200 --param dataset=system.syslog --index
python -m secgen generate filebeat --count 50 --param dataset=system.auth --param is_malicious=true --index
```

### Attack Discovery & Cases (NEW!)

```bash
# Generate Attack Discovery
python -m secgen generate attack-discovery --pattern brute-force --alerts 10 --index

# Generate Security Cases
python -m secgen generate case --template brute-force-investigation --index

# Generate full correlated attack chain (events → alerts → discovery → case)
python -m secgen correlated-attack brute-force --events 100 --index
python -m secgen correlated-attack c2-beacon --events 50 --index
python -m secgen correlated-attack ransomware --events 200 --no-case --index
```

### Feature Testing

```bash
# Test Network Map visualization
python -m secgen test network-map --index

# Test Timeline correlation
python -m secgen test timeline --index

# Test Entity Analytics
python -m secgen test entity-analytics --index
```

### Presets (One-Command Workflows)

```bash
# Demo cluster with diverse data
python -m secgen preset demo-cluster

# Entity Analytics showcase
python -m secgen preset entity-analytics-showcase

# Attack simulation for detection testing
python -m secgen preset attack-simulation
```

### Legacy Mode (Backward Compatible)

> **Note**: Add `--index-all` (legacy) or `--index` to send events to Elasticsearch.

```bash
# Legacy mode - generate 20 alerts and index
python -m secgen --count 20 --index-all

# Generate with entity correlation (World state)
python -m secgen --count 20 --use-world --index-all

# Create and manage World state
python -m secgen world create --hosts 50 --users 100 --save world.json

# Generate with persistent World state
python -m secgen generate --count 30 --world-file world.json --campaign --index

# Generate sample multi-event scenario
python -m secgen sample-scenario --output my_scenario.yaml

# Performance testing (indexes by default, use --dry-run to skip)
python -m secgen perf-test --events 10000 --types file network dns
```

## MCP Server for Claude Desktop

**NEW!** secgen now includes a Model Context Protocol (MCP) server that enables Claude Desktop and other MCP clients to discover and use secgen's event generators through natural language.

### Quick Start with Claude Desktop

1. **Install secgen with MCP support**:
   ```bash
   uv pip install -e .  # MCP dependencies included automatically
   ```

2. **Configure Claude Desktop**:

   Add to your `claude_desktop_config.json` (use the full path to `run_mcp.sh`):
   
   **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
   **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   
   ```json
   {
     "mcpServers": {
       "secgen": {
         "command": "/full/path/to/alert-generator/run_mcp.sh",
         "env": {
           "ELASTIC_URL": "localhost:9200",
           "ELASTIC_USERNAME": "elastic",
           "ELASTIC_PASSWORD": "changeme"
         }
       }
     }
   }
   ```
   
   The `run_mcp.sh` script handles virtual environment activation automatically.

3. **Use with Claude**:
   ```
   User: "List all available event types for network security"
   Claude: [Uses list_event_types tool with category filter]

   User: "I need to test DNS tunneling detection in Elastic"
   Claude: [Uses list_attack_patterns, describe_attack_pattern, then execute_attack]

   User: "Create a test environment with 20 Windows hosts"
   Claude: [Uses create_world tool]
   ```

### MCP Tools Available

The MCP server provides **15 tools** organized into 5 categories:

**Discovery (4 tools)** ✅:
- `list_event_types` - List event generators with category filtering
- `list_attack_patterns` - List attack patterns with MITRE ATT&CK filtering
- `describe_event_type` - Get detailed metadata for an event type
- `describe_attack_pattern` - Get detailed metadata with TTPs and detection recommendations

**Generation (3 tools)** ✅:
- `generate_events` - Generate events by type with parameters
- `execute_attack` - Execute attack patterns (multi-event sequences)
- `generate_campaign` - Generate correlated attack campaigns

**World State (4 tools)** ✅:
- `create_world` - Create/reset World state for entity correlation
- `get_world_info` - Get World summary
- `save_world` - Save World to file
- `load_world` - Load World from file

**Testing (1 tool)** ✅:
- `test_elastic_feature` - Generate data for Elastic features (network-map, timeline, etc.)

**Utility (3 tools)** ✅:
- `validate_elasticsearch` - Check ES connection
- `get_capabilities` - Get server capabilities
- `index_events` - Enable indexing (requires explicit confirmation)

### MCP Server Features

- **Dry-run by default**: Safe exploration without accidental writes to Elasticsearch
- **Entity correlation**: Session-based World state for consistent host.id and user.name
- **MITRE ATT&CK integration**: All attack patterns mapped to TTPs
- **ECS compliance**: All events follow Elastic Common Schema
- **Safety gates**: Indexing requires explicit confirmation flags

### Example Conversations with Claude

**Detection rule testing**:
```
You: "I wrote a detection rule for DNS tunneling. Can you generate 
     test data to validate it?"

Claude: I'll generate DNS tunneling attack data and some baseline 
        normal DNS traffic.
        
        [Executes dns-tunneling attack pattern]
        [Generates 500 benign DNS events]
        
        Generated 450 malicious DNS events with:
        • High-entropy subdomain queries
        • TXT record lookups to tunnel.exfil.net
        
        Plus 500 normal DNS events for baseline.
        Your rule should fire on the malicious events.
```

**SOC analyst training**:
```
You: "Create a training scenario with 3 different attacks for 
     our new SOC analysts to investigate"

Claude: [Creates World with hosts/users]
        [Executes brute-force, c2-beacon, and data-exfiltration]
        
        Created 3 investigation scenarios:
        1. Credential attack: 50 failed logins from 203.0.113.45
        2. C2 beacon: Every 60s to suspicious-cdn.com
        3. Data exfiltration: 500MB transferred over 2 hours
        
        Each scenario has unique correlation IDs for Timeline.
```

**Feature demonstration**:
```
You: "I need to demo Elastic's Network Map for a customer"

Claude: [Calls test_elastic_feature with feature="network-map"]
        
        Generated 200 network flow events with:
        • Internal and external traffic
        • Geographic data for map placement
        • Community IDs for flow correlation
        
        Open Security > Network > Network Map to see the visualization.
```

### MCP Server Architecture

```
secgen/mcp/
├── server.py              # Main MCP server (stdio transport)
├── state.py               # Session state management
├── schemas.py             # JSON schemas for tool arguments
├── formatters.py          # Response formatting utilities
└── tools/
    ├── discovery.py       # Discovery tools (✅ fully implemented)
    ├── generation.py      # Generation tools (✅ fully implemented)
    ├── world.py           # World state tools (✅ fully implemented)
    ├── testing.py         # Feature testing tools (✅ fully implemented)
    └── utility.py         # Utility tools (✅ fully implemented)
```

> 📖 **For detailed MCP documentation**, see [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)

### Start MCP Server Manually

```bash
# Using the convenience script (recommended)
./run_mcp.sh

# With debug logging
./run_mcp.sh --log-level DEBUG

# Or using the module directly
secgen mcp
python -m secgen mcp --log-level DEBUG
```

## CLI Commands

### Legacy Mode (Backward Compatible)

> **Note**: Add `--index-all` to send events to Elasticsearch.

```bash
# Basic alert generation
python -m secgen --count 20 --index-all

# Campaign mode with entity correlation
python -m secgen --count 50 --campaign --campaign-hosts 10 --use-world --index-all

# Time distribution with business hours
python -m secgen --count 100 --time-spread days --working-hours --index-all

# Delete all generated data
python -m secgen --delete-all
```

### World Command

Manage persistent World state for entity correlation.

```bash
# Create a new World with hosts and users
python -m secgen world create --hosts 50 --users 100 --save world.json

# Load and display World information
python -m secgen world info --load world.json

# Load existing World
python -m secgen world load --load world.json
```

**World State includes:**
- Hosts with persistent host.id, IPs, MACs, OS info
- Users with roles, groups, and host assignments
- Process trees for each host
- Network topology (subnets, DNS servers, domain controllers)
- Threat actors for campaign generation

### Generate Command (Advanced)

Advanced generation with World state correlation.

> **Note**: Add `--index` to send events to Elasticsearch. Without it, events are generated and displayed but not indexed.

```bash
# Generate with ephemeral World state
python -m secgen generate --count 30 --use-world --index

# Generate with persistent World state
python -m secgen generate --count 50 --world-file world.json --campaign --index

# Save World state after generation
python -m secgen generate --count 30 --use-world --save-world world_after.json --index

# Full options
python -m secgen generate \
  --count 100 \
  --scenario custom_scenarios.yaml \
  --world-file world.json \
  --campaign \
  --hosts 20 \
  --speed slow \
  --time-spread days \
  --working-hours \
  --index \
  --output events.json
```

### Performance Test Command

Benchmark event generation performance.

```bash
# Test all generator types
python -m secgen perf-test --events 10000

# Test specific event types
python -m secgen perf-test --events 5000 --types file network dns auth

# Dry run (don't index)
python -m secgen perf-test --events 10000 --dry-run
```

### Sample Scenario Command

Generate sample multi-event scenario YAML.

```bash
# Print to stdout
python -m secgen sample-scenario

# Save to file
python -m secgen sample-scenario --output apt_scenario.yaml
```

## Event Types & Generators

### Endpoint Events

| Generator | Index Pattern | Use Cases |
|-----------|--------------|-----------|
| Process | `logs-endpoint.events.process-*` | Process execution, command lines, process trees |
| File | `logs-endpoint.events.file-*` | File creation, modification, deletion, malware drops |
| Registry | `logs-endpoint.events.registry-*` | Windows persistence, security disabling |
| Network | `logs-endpoint.events.network-*` | Process-linked network connections, C2 beaconing |

### Network Events

| Generator | Index Pattern | Use Cases |
|-----------|--------------|-----------|
| DNS | `logs-dns.query-*` | DNS queries, DGA detection, DNS tunneling |
| Network Flow | `logs-network_traffic.flow-*` | Geo-enriched flows, Network Map visualization |
| HTTP | `logs-network_traffic.http-*` | Web traffic, web shells, HTTP exfiltration |
| TLS | `logs-network_traffic.tls-*` | JA3/JA3S fingerprints, certificate analysis |

### Identity Events

| Generator | Index Pattern | Use Cases |
|-----------|--------------|-----------|
| Authentication | `logs-system.auth-*` | Login success/failure, brute force, impossible travel |
| IAM | `logs-system.security-*` | User/group/role management, privilege escalation |

### Cloud Events

| Generator | Index Pattern | Use Cases |
|-----------|--------------|-----------|
| AWS CloudTrail | `logs-aws.cloudtrail-*` | IAM changes, S3 access, defense evasion |
| Azure Sign-in | `logs-azure.signinlogs-*` | Azure AD authentication, risky sign-ins |
| Azure Audit | `logs-azure.auditlogs-*` | Directory changes, role assignments |
| GCP Audit | `logs-gcp.audit-*` | GCP API calls, service account abuse |

### Threat Intelligence

| Generator | Index Pattern | Use Cases |
|-----------|--------------|-----------|
| Threat Indicators | `logs-ti_util.logs-*` | IOC matching, coordinated indicator injection |

## Multi-Event Scenario Format

Create complex attack scenarios with multiple event types:

```yaml
scenarios:
  - name: "APT29 Initial Access Campaign"
    description: "Spear-phishing leading to payload execution and C2 establishment"
    severity: "critical"
    threat_actor: "APT29"
    ttps:
      - "T1566.001"  # Spear-phishing Attachment
      - "T1059.001"  # PowerShell
      - "T1071.001"  # Web Protocols

    environment:
      os_family: "windows"
      host_template: "workstation"
      user_template: "standard"

    phases:
      - name: "initial_access"
        description: "User opens malicious document"
        duration_minutes: 2
        correlation:
          same_host: true
          same_user: true
          process_tree: true
        events:
          - type: "authentication"
            template: "successful_login"
          - type: "process"
            params:
              name: "OUTLOOK.EXE"
              executable: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
              args: ["/recycle"]
              working_dir: "C:\\Users\\victim\\Documents"
              user: "victim"
          - type: "file"
            template: "malware_drop"

      - name: "execution"
        description: "Malicious macro executes PowerShell"
        events:
          - type: "process"
            template: "powershell_encoded"
          - type: "file"
            template: "malware_drop"

      - name: "persistence"
        description: "Establish registry persistence"
        events:
          - type: "registry"
            template: "run_key_persistence"

      - name: "c2_communication"
        description: "Establish C2 channel"
        events:
          - type: "dns"
            params:
              query_name: "cozy-c2.evil.com"
              is_malicious: true
          - type: "network"
            template: "c2_beacon"
          - type: "tls"
            params:
              server_name: "cozy-c2.evil.com"
              is_malicious: true

    generate_indicators: true
```

### Available Event Templates

```yaml
# Process templates
- bash_session
- powershell_encoded

# File templates  
- malware_drop
- data_staging

# Network templates
- c2_beacon
- data_exfiltration

# Authentication templates
- successful_login
- failed_login
- brute_force

# Registry templates (Windows)
- run_key_persistence

# DNS templates
- dga_activity
- dns_tunneling
```

## Entity Correlation with World State

The World state enables proper correlation across all event types using consistent entity identifiers:

### Correlation Keys

| Key | Description | Use Case |
|-----|-------------|----------|
| `host.id` | Persistent host identifier | Timeline, Analyzer, Entity Analytics |
| `user.name` | Username | Entity Analytics risk scoring |
| `process.entity_id` | Process identifier | Process tree visualization |
| `network.community_id` | Network flow ID | Cross-tool correlation |

### Example: Correlated Attack Chain

```python
from secgen.core.world import World
from secgen.generators.endpoint import FileEventGenerator, EndpointNetworkEventGenerator
from secgen.generators.network import DNSEventGenerator

# Create world with entities
world = World()
world.populate(num_hosts=10, num_users=20)

# Get correlated entities
host = world.get_random_host()
user = world.get_random_user()
world.assign_user_to_host(user, host)

# Spawn process in world
process = world.spawn_process(
    host_id=host.id,
    name="powershell.exe",
    executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    args=["-enc", "..."],
    working_directory="C:\\Users\\victim",
    user=user,
)

# Generate correlated events - all share same host.id, user.name
file_gen = FileEventGenerator()
file_event = file_gen.generate_malware_drop(host, user, process, "payload.exe")

dns_gen = DNSEventGenerator()
dns_event = dns_gen.generate(host=host, query_name="evil-c2.com", is_malicious=True)

network_gen = EndpointNetworkEventGenerator()
network_event = network_gen.generate_c2_beacon(host, user, process, "evil-c2.com", "198.51.100.10")

# All events have same host.id enabling Timeline correlation
assert file_event["host"]["id"] == dns_event["host"]["id"] == network_event["host"]["id"]
```

## Attack Patterns

### Brute Force Attack

```python
from secgen.generators.identity import AuthenticationEventGenerator

auth_gen = AuthenticationEventGenerator()
events = auth_gen.generate_brute_force(
    target_user=user,
    host=host,
    source_ip="203.0.113.50",
    attempts=50,
    success_at_end=True,
    duration_minutes=10,
)
```

### Impossible Travel

```python
events = auth_gen.generate_impossible_travel(
    user=user,
    first_location={"country_name": "United States", ...},
    second_location={"country_name": "Russia", ...},
    time_gap_minutes=30,
)
```

### DGA Activity

```python
from secgen.generators.network import DNSEventGenerator

dns_gen = DNSEventGenerator()
events = dns_gen.generate_dga_activity(
    host=host,
    domain_count=50,
    nxdomain_ratio=0.9,
)
```

### DNS Tunneling

```python
events = dns_gen.generate_dns_tunneling(
    host=host,
    tunnel_domain="exfil.evil.com",
    query_count=20,
    data_size_bytes=10000,
)
```

### C2 Beaconing

```python
from secgen.generators.endpoint import EndpointNetworkEventGenerator

network_gen = EndpointNetworkEventGenerator()
events = network_gen.generate_c2_beacon(
    host=host,
    user=user,
    process=process,
    c2_domain="beacon.evil.com",
    c2_ip="198.51.100.10",
    beacon_count=10,
    interval_seconds=60,
)
```

### Data Exfiltration

```python
events = network_gen.generate_data_exfiltration(
    host=host,
    user=user,
    process=process,
    exfil_domain="exfil.evil.com",
    exfil_ip="198.51.100.20",
    data_size_mb=100.0,
)
```

### AWS Privilege Escalation

```python
from secgen.generators.cloud import AWSCloudTrailGenerator

aws_gen = AWSCloudTrailGenerator()
events = aws_gen.generate_privilege_escalation(
    attacker=user,
    account_id="123456789012",
    source_ip="203.0.113.50",
)
```

### Coordinated Threat Indicators

```python
from secgen.generators.threat_intel import ThreatIndicatorGenerator

threat_gen = ThreatIndicatorGenerator()
indicators = threat_gen.generate_coordinated_iocs(
    c2_domain="evil-c2.com",
    c2_ip="198.51.100.10",
    malware_hashes=["abc123...", "def456..."],
    threat_actor="APT29",
    campaign_name="Operation Dark Eagle",
)
```

## Complete Examples

### Generate Full Attack Campaign with All Event Types

```bash
# Create persistent World state
python -m secgen world create --hosts 50 --users 100 --save campaign_world.json

# Generate correlated campaign and index to Elasticsearch
python -m secgen generate \
  --count 100 \
  --world-file campaign_world.json \
  --campaign \
  --hosts 10 \
  --speed slow \
  --time-spread days \
  --working-hours \
  --index

# View generated data in Kibana Security
```

### Test Specific Detection Rules

```bash
# DGA detection rules
python -m secgen perf-test --events 100 --types dns

# Brute force detection
python -m secgen perf-test --events 200 --types auth

# Cloud security rules
python -m secgen perf-test --events 100 --types aws azure gcp
```

### Generate Data for Network Map

```bash
# Network flows with geo-enrichment
python -m secgen generate --count 500 --use-world --index
```

## Architecture

> 📖 **For detailed documentation on how data generation works**, see [docs/DATA_GENERATION.md](docs/DATA_GENERATION.md)

```
secgen/
├── core/
│   ├── __init__.py
│   └── world.py              # World state management
├── models/
│   ├── entities/             # Host, User, ProcessTree models
│   │   ├── host.py
│   │   ├── user.py
│   │   └── process_tree.py
│   ├── scenario.py           # Legacy + Multi-event scenarios
│   ├── campaign.py
│   └── alert.py
├── generators/
│   ├── endpoint/             # Endpoint event generators
│   │   ├── file.py
│   │   ├── registry.py
│   │   └── network.py
│   ├── network/              # Network event generators
│   │   ├── dns.py
│   │   ├── flow.py
│   │   ├── http.py
│   │   └── tls.py
│   ├── identity/             # Identity event generators
│   │   ├── auth.py
│   │   └── iam.py
│   ├── cloud/                # Cloud audit log generators
│   │   ├── aws.py
│   │   ├── azure.py
│   │   └── gcp.py
│   ├── threat_intel/         # Threat intelligence
│   │   └── indicators.py
│   ├── alert.py              # Detection alert generator
│   ├── process.py            # Process event generator
│   ├── campaign.py           # Campaign generator
│   └── randomizers.py        # Random data utilities
├── indexers/
│   ├── base.py
│   └── elasticsearch.py      # Multi-index bulk operations
├── time_distribution/
│   └── strategies.py         # Time distribution strategies
├── config/
│   ├── loader.py             # YAML scenario loading
│   └── settings.py           # Pydantic settings
├── core.py                   # Alert orchestration
└── cli.py                    # CLI with subcommands
```

## Indices Used

| Index Pattern | Event Type |
|---------------|------------|
| `.alerts-security.alerts-default` | Detection rule alerts |
| `logs-endpoint.events.process-*` | Process events |
| `logs-endpoint.events.file-*` | File events |
| `logs-endpoint.events.registry-*` | Registry events |
| `logs-endpoint.events.network-*` | Endpoint network events |
| `logs-endpoint.alerts-*` | Endpoint alerts |
| `logs-dns.query-*` | DNS events |
| `logs-network_traffic.flow-*` | Network flows |
| `logs-network_traffic.http-*` | HTTP events |
| `logs-network_traffic.tls-*` | TLS events |
| `logs-system.auth-*` | Authentication events |
| `logs-aws.cloudtrail-*` | AWS CloudTrail |
| `logs-azure.signinlogs-*` | Azure sign-in logs |
| `logs-azure.auditlogs-*` | Azure audit logs |
| `logs-gcp.audit-*` | GCP audit logs |
| `logs-ti_util.logs-*` | Threat indicators |
| `auditbeat-*` | Auditbeat events (auditd, login, process, FIM) |
| `packetbeat-*` | Packetbeat events (DNS, HTTP, TLS, flow) |
| `filebeat-*` | Filebeat events (syslog, auth, nginx, apache) |
| `.ai-attack-discovery-default` | Attack Discovery documents |
| `logs-case-default` | Security Case documents |

## Data Management

### Delete All Generated Data

```bash
python -m secgen --delete-all
```

This clears all indices listed above.

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--count N` | Number of alerts/events (default: 10) |
| `--dry-run` | Generate without indexing |
| `--output FILE` | Save to JSON file |
| `--scenarios-file FILE` | Load scenarios from YAML |

### Campaign Options

| Option | Description |
|--------|-------------|
| `--campaign` | Enable campaign mode |
| `--campaign-hosts N` | Number of hosts (default: 5) |
| `--attack-speed SPEED` | fast, medium, slow (default: medium) |

### Time Distribution

| Option | Description |
|--------|-------------|
| `--time-spread UNIT` | minutes, hours, days, weeks (default: minutes) |
| `--working-hours` | Weight to business hours (8am-6pm) |

### World State Options

| Option | Description |
|--------|-------------|
| `--use-world` | Enable World state correlation |
| `--world-file FILE` | Load World from file |
| `--save-world FILE` | Save World after generation |
| `--hosts N` | Number of hosts for ephemeral World |
| `--users N` | Number of users for ephemeral World |

## Best Practices

1. **Use World State**: Always use `--use-world` for proper entity correlation
2. **Persistent World**: Save World state for consistent testing across sessions
3. **Campaign Mode**: Use campaigns to test correlation features
4. **Time Distribution**: Use `--working-hours` for realistic patterns
5. **Start Small**: Test with `--count 5 --dry-run` first
6. **Custom Scenarios**: Create multi-event scenarios matching your threat model
7. **Performance Testing**: Use `perf-test` to benchmark before large runs

## Troubleshooting

### PyYAML not available

```
⚠️  PyYAML not available - using hardcoded scenarios only
```

Solution: `pip install pyyaml`

### Pydantic not available

```
ModuleNotFoundError: No module named 'pydantic'
```

Solution: `pip install pydantic pydantic-settings`

### Failed to index

```
❌ Failed to index alert: 401
```

Solution: Check ELASTIC_URL, USERNAME, PASSWORD environment variables

### World file not found

```
❌ World file not found: world.json
```

Solution: Create World first with `python -m secgen world create --save world.json`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - See LICENSE file for details.
