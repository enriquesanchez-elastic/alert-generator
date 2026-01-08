# SecGen Command Reference

This document provides a complete reference for all SecGen CLI commands.

## Discovery Commands

### `list` - List Available Generators

List event types, attack patterns, and feature tests.

```bash
# List all event types
secgen list event-types

# List event types filtered by category
secgen list event-types --filter endpoint

# List all attack patterns
secgen list attack-patterns

# List attack patterns by MITRE ATT&CK TTP
secgen list attack-patterns --ttp T1110

# List all generators by category
secgen list generators

# List feature tests
secgen list feature-tests
```

**Output includes:**
- Event type name and description
- Category (endpoint, network, identity, cloud, etc.)
- Total count of registered generators

### `describe` - Detailed Information

Get detailed information about event types or attack patterns.

```bash
# Describe an event type
secgen describe event-type dns

# Describe an attack pattern
secgen describe attack brute-force
```

**Event type output includes:**
- ECS fields generated
- Index pattern
- Example parameters
- Usage examples

**Attack pattern output includes:**
- MITRE ATT&CK TTPs
- Required and optional parameters
- Detection recommendations
- MITRE ATT&CK references

---

## Event Generation

### `generate <event-type>` - Generate Events by Type

Generate events of a specific type.

> **Note**: Add `--index` to send events to Elasticsearch. Without it, events are generated and displayed but not indexed.

```bash
# Basic generation (dry run - displays summary only)
secgen generate dns --count 50

# Generate with parameters and index to Elasticsearch
secgen generate dns --count 50 --param is_malicious=true --index

# Use World state for entity correlation
secgen generate dns --count 50 --use-world --index

# Use existing World state file
secgen generate dns --count 50 --world-file qa-world.json --index

# Index to Elasticsearch
secgen generate dns --count 50 --index

# Save to JSON file
secgen generate dns --count 50 --output events.json

# Dry run (no indexing)
secgen generate dns --count 50 --dry-run

# JSON output format
secgen generate dns --count 50 --json
```

**Available event types:**

| Event Type | Category | Description |
|------------|----------|-------------|
| `process` | endpoint | Process execution events for Analyzer |
| `file` | endpoint | File system events |
| `registry` | endpoint | Windows registry events |
| `endpoint-network` | endpoint | Network events with process context |
| `dns` | network | DNS query events |
| `http` | network | HTTP transaction events |
| `tls` | network | TLS/SSL events with JA3 |
| `network-flow` | network | Network flows for Network Map |
| `authentication` | identity | Login/authentication events |
| `iam` | identity | IAM change events |
| `aws-cloudtrail` | cloud | AWS CloudTrail audit logs |
| `azure-audit` | cloud | Azure AD/audit logs |
| `gcp-audit` | cloud | GCP audit logs |
| `threat-indicator` | threat_intel | Threat indicators/IOCs |
| `vulnerability` | security | Vulnerability scan findings |
| `cspm` | cloud | CSPM compliance findings |
| `risk-score` | analytics | Entity risk scores |

**Options:**

| Option | Description |
|--------|-------------|
| `--count N` | Number of events to generate (default: 10) |
| `--param key=value` | Parameter for generator (can repeat) |
| `--use-world` | Create ephemeral World state |
| `--world-file PATH` | Load World from file |
| `--index` | Index to Elasticsearch |
| `--dry-run` | Don't index, just generate |
| `--output PATH` | Save events to JSON file |
| `--json` | Output in JSON format |

---

## Attack Pattern Commands

### `attack <pattern>` - Execute Attack Patterns

Execute registered attack patterns with MITRE ATT&CK context.

```bash
# Execute brute-force attack
secgen attack brute-force --index

# Multiple iterations
secgen attack brute-force --count 3 --index

# With World state
secgen attack c2-beacon --world-file qa-world.json --index

# Save output
secgen attack dga-activity --output attack-events.json
```

**Available attack patterns:**

| Pattern | Category | TTPs | Description |
|---------|----------|------|-------------|
| `brute-force` | identity | T1110.001, T1110.003 | Password brute force |
| `credential-stuffing` | identity | T1110.004 | Credential stuffing attack |
| `impossible-travel` | identity | T1078 | Geographically impossible login |
| `mfa-bypass` | identity | T1556.006 | MFA bypass attempt |
| `dga-activity` | network | T1568.002 | DGA domain queries |
| `dns-tunneling` | network | T1071.004 | DNS exfiltration |
| `c2-beacon` | endpoint | T1071.001 | C2 beaconing |
| `c2-dns` | network | T1071.004 | DNS-based C2 |
| `data-exfiltration` | endpoint | T1041 | Data exfiltration |
| `lateral-movement` | endpoint | T1021 | Lateral movement |
| `malware-drop` | endpoint | T1105 | Malware file drop |
| `data-staging` | endpoint | T1074.001 | Pre-exfil staging |
| `registry-persistence` | endpoint | T1547.001 | Registry persistence |
| `security-disable` | endpoint | T1562.001 | Security tool disable |

**Options:**

| Option | Description |
|--------|-------------|
| `--count N` | Number of iterations (default: 1) |
| `--world-file PATH` | Load World from file |
| `--use-world` | Create ephemeral World state |
| `--index` | Index to Elasticsearch |
| `--dry-run` | Don't index |
| `--output PATH` | Save to JSON file |
| `--json` | JSON output format |

---

## Feature Testing

### `test <feature>` - Test Elastic Security Features

Generate data specifically designed to test Elastic Security features.

```bash
# Test Network Map
secgen test network-map --index

# Test Timeline
secgen test timeline --index

# Test Process Analyzer
secgen test analyzer --index

# Test Entity Analytics
secgen test entity-analytics --index

# Override default count
secgen test network-map --count 500 --index
```

**Available feature tests:**

| Feature | Description | Event Types |
|---------|-------------|-------------|
| `network-map` | Network Map visualization | network-flow, endpoint-network |
| `timeline` | Timeline investigation | process, file, registry, network, dns |
| `analyzer` | Process Analyzer tree | process, alert |
| `entity-analytics` | Entity risk scoring | risk-score, authentication, alert |
| `detection-rule` | Detection rule testing | process, file, registry, network, dns |
| `vulnerability-management` | Vulnerability dashboard | vulnerability |
| `cloud-posture` | CSPM compliance | cspm |

**Output includes:**
- Verification steps for Kibana
- Useful KQL queries
- Correlation IDs for filtering

---

## Preset System

### `preset <name>` - Run Preset Configurations

Execute predefined data generation workflows.

```bash
# Demo cluster preset
secgen preset demo-cluster

# Entity Analytics showcase
secgen preset entity-analytics-showcase

# Load testing
secgen preset load-test

# Attack simulation
secgen preset attack-simulation

# Custom YAML preset
secgen preset ./my-preset.yaml

# Don't index
secgen preset demo-cluster --no-index

# Save all events
secgen preset demo-cluster --output all-events.json
```

**Built-in presets:**

| Preset | Description | Events |
|--------|-------------|--------|
| `demo-cluster` | Comprehensive demo data | ~1,500 |
| `entity-analytics-showcase` | Entity risk demonstration | ~500 |
| `load-test` | High-volume performance test | ~18,000 |
| `attack-simulation` | Multi-stage attack chain | ~50 |
| `network-visibility` | Network Map focus | ~1,500 |
| `cloud-security` | Cloud audit and CSPM | ~750 |

**Options:**

| Option | Description |
|--------|-------------|
| `--no-index` | Don't index to Elasticsearch |
| `--output PATH` | Save all events to JSON |
| `--json` | JSON output format |

---

## World State Management

### `world` - Manage Persistent Entity State

```bash
# Create World state
secgen world create --hosts 50 --users 100 --save world.json

# Load and view World info
secgen world info --load world.json
```

---

## Legacy Commands

### Legacy Alert Generation

> **Note**: Add `--index-all` to send events to Elasticsearch.

```bash
# Basic generation
python -m secgen --count 20 --index-all

# With World state
python -m secgen --count 20 --use-world --index-all

# Campaign mode
python -m secgen generate --count 30 --campaign --index

# Performance test (indexes by default, use --dry-run to skip)
python -m secgen perf-test --events 10000

# Sample scenario
python -m secgen sample-scenario --output scenario.yaml
```

---

## Environment Variables

### Elasticsearch Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTIC_URL` | Elasticsearch URL | `localhost:9200` |
| `ELASTIC_USERNAME` | Elasticsearch username | `elastic` |
| `ELASTIC_PASSWORD` | Elasticsearch password | - |
| `KIBANA_URL` | Kibana URL for links | `http://localhost:5601` |
| `KIBANA_BASE_PATH` | Kibana base path (if any) | - |
| `KIBANA_SPACE` | Kibana space ID | `default` |
| `ALERTS_INDEX` | Alerts index pattern | `.alerts-security.alerts-default` |

### Logging Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `LOG_JSON` | Enable JSON formatted logging | `false` |

### AI/LLM Configuration (Optional)

These settings enable AI-enhanced generation features. See [AI_ENHANCED_GENERATION.md](AI_ENHANCED_GENERATION.md) for details.

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key (required for AI features) | - |
| `GEMINI_MODEL` | Gemini model to use | `gemini-3-pro-preview` |
| `LLM_ARTIFACTS_DIR` | Directory for cached AI artifacts | `~/.secgen/llm_artifacts` |
| `LLM_CACHE_ENABLED` | Enable artifact caching | `true` |

---

## LLM Commands

Generate AI-powered artifacts using Google Gemini. Requires `GEMINI_API_KEY` to be set.

### `llm commands` - Generate Command Libraries

```bash
# Generate execution commands
secgen llm commands --tactic execution --count 30 --actor APT29 --os windows

# List available tactics
secgen llm commands --list-tactics
```

| Option | Default | Description |
|--------|---------|-------------|
| `--tactic` | `execution` | MITRE ATT&CK tactic |
| `--count` | `30` | Number of commands |
| `--actor` | `generic_apt` | Threat actor style |
| `--os` | `windows` | Target OS |
| `--force` | - | Force regeneration |

### `llm scenarios` - Generate Scenario Variations

```bash
# Generate ransomware variations
secgen llm scenarios --base "Ransomware" --variations 5
```

| Option | Default | Description |
|--------|---------|-------------|
| `--base` | `Ransomware` | Base scenario name |
| `--variations` | `5` | Number of variations |
| `--os` | `windows` | Target OS |

### `llm profiles` - Generate Entity Profiles

```bash
# Generate healthcare profiles
secgen llm profiles --industry healthcare --roles 15

# List industries
secgen llm profiles --list-industries
```

| Option | Default | Description |
|--------|---------|-------------|
| `--industry` | `technology` | Industry vertical |
| `--roles` | `10` | Number of roles |
| `--org-size` | `medium` | Organization size |

### `llm campaign` - Generate Campaign Narratives

```bash
# Generate APT campaign
secgen llm campaign --actor APT29 --target technology --days 14

# List threat actors
secgen llm campaign --list-actors
```

| Option | Default | Description |
|--------|---------|-------------|
| `--actor` | `APT29` | Threat actor |
| `--target` | `technology` | Target sector |
| `--days` | `14` | Campaign duration |
| `--objective` | `data_theft` | Campaign objective |

### `llm cache` - Manage Artifact Cache

```bash
# View cache statistics
secgen llm cache stats

# List cached artifacts
secgen llm cache list
secgen llm cache list --type commands

# Clear cache
secgen llm cache clear
secgen llm cache clear --type commands
```

> 📖 **For complete AI documentation**, see [AI_ENHANCED_GENERATION.md](AI_ENHANCED_GENERATION.md)




