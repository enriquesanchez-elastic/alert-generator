# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive, modular tool for generating realistic, ECS-compliant security data for testing Elastic Security Solution. It generates correlated attack campaigns, multi-event-type generation, and maintains World state for entity correlation across process, file, registry, network, DNS, authentication, cloud, and threat intelligence events.

**Key concept**: The "World" state is central to this project - it maintains persistent entities (hosts, users, process trees, network topology, threat actors) that enable proper correlation across all generated events using consistent identifiers like `host.id`, `user.name`, and `process.entity_id`.

## Development Commands

### Installation
```bash
# Using uv (recommended)
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Using pip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secgen --cov-report=html

# Run specific test module
pytest tests/test_generators/test_alert.py

# Test single function
pytest tests/test_core.py::test_function_name -v
```

### Code Quality
```bash
# Format code (required before commits)
black secgen/

# Lint code
ruff check secgen/ --fix

# Type checking
mypy secgen/
```

### Running the Tool

**Discovery Commands:**
```bash
# List all available event types
python -m secgen list event-types

# List attack patterns with MITRE ATT&CK filtering
python -m secgen list attack-patterns --ttp T1110

# Describe event type or attack pattern
python -m secgen describe event-type dns
python -m secgen describe attack brute-force
```

**Generate Events:**
```bash
# Generate specific event types (via registry)
python -m secgen generate dns --count 50 --index
python -m secgen generate file --count 100 --param is_malicious=true

# Execute attack patterns (via registry)
python -m secgen attack brute-force --count 3 --index
python -m secgen attack c2-beacon --world-file world.json --index
```

**Test Elastic Features:**
```bash
# Test specific features
python -m secgen test network-map --index
python -m secgen test timeline --index
python -m secgen test entity-analytics --index
```

**Presets (One-Command Workflows):**
```bash
# List available presets
python -m secgen preset --list

# Run preset
python -m secgen preset demo-cluster
python -m secgen preset entity-analytics-showcase
```

**Legacy Mode:**
```bash
# Basic alert generation
python -m secgen --count 20

# Generate with World state for entity correlation
python -m secgen generate --count 30 --use-world

# Create persistent World state
python -m secgen world create --hosts 50 --users 100 --save world.json

# Generate with persistent World
python -m secgen generate --count 50 --world-file world.json --campaign

# Performance benchmarking
python -m secgen perf-test --events 10000 --types file network dns

# Generate sample multi-event scenario
python -m secgen sample-scenario --output scenario.yaml
```

## Architecture

### Core Design Principles

1. **World State Pattern**: All generators should accept and use World entities (Host, User) for proper correlation
2. **ECS Compliance**: All events must follow Elastic Common Schema field mappings
3. **Modular Generators**: Each event type has its own generator in the appropriate subdirectory
4. **Entity Correlation**: Use `host.id`, `user.name`, `process.entity_id` as correlation keys across events
5. **Registry System**: Decorators (`@register_event_type`, `@register_attack_pattern`) enable CLI discovery and automatic documentation

### Directory Structure

```
secgen/
├── core/
│   └── world.py              # World state management - central to entity correlation
├── models/
│   ├── entities/             # Entity models (Host, User, ProcessTree)
│   ├── scenario.py           # Scenario definitions (legacy + multi-event)
│   ├── campaign.py           # Campaign model for correlated attacks
│   └── alert.py              # Alert model
├── generators/
│   ├── endpoint/             # Endpoint telemetry (file, registry, network)
│   ├── network/              # Network events (DNS, HTTP, TLS, flow)
│   ├── identity/             # Identity events (auth, IAM)
│   ├── cloud/                # Cloud audit logs (AWS, Azure, GCP)
│   ├── threat_intel/         # Threat indicators
│   ├── security/             # Security scan events (vulnerability, etc.)
│   ├── analytics/            # Analytics events (risk scores, etc.)
│   ├── alert.py              # Detection alert generator
│   ├── process.py            # Process event generator
│   ├── campaign.py           # Campaign generator
│   └── randomizers.py        # Random data utilities
├── handlers/                 # CLI command handlers
│   ├── list_handler.py       # List event types/attack patterns
│   ├── describe_handler.py   # Describe generators
│   ├── generate_handler.py   # Generate events by type
│   ├── attack_handler.py     # Execute attack patterns
│   ├── test_handler.py       # Feature tests (network-map, timeline, etc.)
│   └── preset_handler.py     # Preset configurations
├── indexers/
│   ├── base.py               # Base indexer interface
│   └── elasticsearch.py      # Multi-index bulk operations
├── time_distribution/
│   └── strategies.py         # Time distribution strategies
├── config/
│   ├── loader.py             # YAML scenario loading
│   └── settings.py           # Pydantic settings with env var support
├── llm/                      # LLM-powered generation (optional)
│   ├── client.py             # Gemini API client
│   ├── cache.py              # Artifact caching system
│   ├── prompts.py            # LLM prompt templates
│   └── generators/           # Command library, scenario variations, profiles, campaigns
├── registry.py               # Generator registration system
├── registry_bootstrap.py     # Bootstrap all generators into registry
├── orchestrator.py           # Core orchestration - glues generators together
└── cli.py                    # CLI with subcommands (list, describe, generate, attack, test, preset, etc.)
```

### Key Components

**World (`core/world.py`)**:
- Central state manager for entity correlation
- Maintains hosts, users, process trees, network topology, and threat actors
- Provides methods: `get_or_create_host()`, `get_or_create_user()`, `spawn_process()`, `assign_user_to_host()`
- Can be saved/loaded as JSON for persistent state across sessions

**AlertOrchestrator (`orchestrator.py`)**:
- Coordinates alert generation across multiple generators
- Manages campaign mode and time distribution
- Handles World state integration
- Routes events to appropriate indexers

**Entity Models (`models/entities/`)**:
- `Host`: Represents physical/virtual hosts with OS info, IPs, MACs, geo data
- `User`: Represents users with roles, groups, host assignments
- `ProcessTree`: Maintains process hierarchy per host with proper parent-child relationships

**Generators** (`generators/*/`):
- Each generator follows the pattern: `__init__(randomizer)` and `generate(host, user, **params)` methods
- Generators return ECS-compliant dictionaries
- Attack pattern methods (e.g., `generate_brute_force()`, `generate_c2_beacon()`) return lists of correlated events

**LLM Components** (`llm/` - optional):
- Enhances generation with AI-powered content when `GEMINI_API_KEY` is set
- `CommandLibraryGenerator`: Realistic command lines and PowerShell scripts
- `ScenarioVariationGenerator`: Dynamic scenario variations
- `EntityProfileGenerator`: Detailed user/host profiles
- `CampaignNarrativeGenerator`: Attack campaign narratives
- Uses caching to minimize API calls

**Registry System** (`registry.py` and `registry_bootstrap.py`):
- Decorator-based registration for event types and attack patterns
- Enables CLI discovery via `list` and `describe` commands
- Automatically documents generators with metadata (ECS fields, TTPs, parameters)
- `@register_event_type`: Registers generator classes (e.g., `DNSEventGenerator`)
- `@register_attack_pattern`: Registers attack pattern methods (e.g., `generate_brute_force`)
- `finalize_attack_patterns()`: Called in bootstrap to link methods to their classes
- Supports filtering by category (endpoint, network, identity, cloud, etc.) and MITRE ATT&CK TTPs

## Development Patterns

### Adding a New Event Generator

1. Create the generator in the appropriate subdirectory:
   - `generators/endpoint/` - for endpoint telemetry
   - `generators/network/` - for network events
   - `generators/identity/` - for identity events
   - `generators/cloud/` - for cloud audit logs
   - `generators/security/` - for security scan events
   - `generators/analytics/` - for analytics events

2. Follow this template with decorators for CLI discovery:

```python
"""Generator for X events."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, TYPE_CHECKING

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import (
    GeneratorCategory,
    register_attack_pattern,
    register_event_type,
)

if TYPE_CHECKING:
    from secgen.models.entities.host import Host
    from secgen.models.entities.user import User


@register_event_type(
    name="x-event",
    category=GeneratorCategory.ENDPOINT,  # or NETWORK, IDENTITY, CLOUD, etc.
    description="X events for detecting Y activity",
    ecs_fields=[
        "field1",
        "field2",
        "host.id",
        "user.name",
    ],
    index_pattern="logs-x.events-default",
    example_params={"is_malicious": True},
)
class XEventGenerator:
    """Generator for X events."""

    def __init__(self, randomizer: Optional[RandomDataGenerator] = None) -> None:
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        timestamp_offset: int = 0,
        is_malicious: bool = False,
    ) -> Dict[str, Any]:
        """Generate a single X event."""
        timestamp = datetime.now(timezone.utc).isoformat()

        event = {
            "@timestamp": timestamp,
            "event": {
                "kind": "event",
                "category": ["category"],
                "type": ["info"],
                "dataset": "x.events",
            },
            # Add ECS-compliant fields
        }

        # IMPORTANT: Always include entity correlation fields if provided
        if host:
            event["host"] = {
                "id": host.id,
                "name": host.name,
                "ip": host.ip,
                "os": host.os.to_dict(),
            }
        if user:
            event["user"] = {
                "name": user.name,
                "id": user.id,
                "domain": user.domain,
            }

        return event

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        malicious_ratio: float = 0.2,
    ) -> list[Dict[str, Any]]:
        """Generate multiple X events."""
        events = []
        for i in range(count):
            is_malicious = random.random() < malicious_ratio
            event = self.generate(
                host=host,
                user=user,
                timestamp_offset=count - i,
                is_malicious=is_malicious,
            )
            events.append(event)
        return events

    @register_attack_pattern(
        name="x-attack",
        description="Attack pattern description",
        ttps=["T1234"],
        category=GeneratorCategory.ENDPOINT,
        required_params=["host", "user"],
        optional_params=["count"],
        event_types=["x-event"],
        detection_recommendations=[
            "Detection rule recommendation 1",
            "Detection rule recommendation 2",
        ],
    )
    def generate_attack_pattern(
        self,
        host: "Host",
        user: "User",
        count: int = 10,
    ) -> list[Dict[str, Any]]:
        """Generate attack pattern events."""
        # Generate correlated events
        return []
```

3. Add to registry bootstrap in `secgen/registry_bootstrap.py`:

```python
from secgen.generators.x import XEventGenerator  # noqa: F401
# ...
finalize_attack_patterns(XEventGenerator)
```

3. Export in `generators/<subdir>/__init__.py`
4. Add index pattern handling in `indexers/elasticsearch.py` if needed
5. Add tests in `tests/test_generators/`

### Working with World State

When generating correlated events:

```python
from secgen.core.world import World

# Create or load World
world = World()
world.populate(num_hosts=10, num_users=20)

# Get entities
host = world.get_random_host(os_family="windows")
user = world.get_random_user(user_type="standard")
world.assign_user_to_host(user, host)

# Spawn process
process = world.spawn_process(
    host_id=host.id,
    name="powershell.exe",
    executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    args=["-enc", "base64..."],
    working_directory="C:\\Users\\victim",
    user=user,
)

# Generate events using these entities - all will share host.id, user.name
# This enables Timeline, Analyzer, and Entity Analytics correlation
```

### Adding Attack Patterns

Attack patterns generate multiple correlated events. Add them as methods in generators:

```python
def generate_attack_pattern(
    self,
    host: "Host",
    user: "User",
    **params,
) -> List[Dict[str, Any]]:
    """Generate events for specific attack pattern."""
    events = []
    # Generate correlated events sharing host.id, user.name
    return events
```

See examples: `generate_brute_force()` in `identity/auth.py`, `generate_c2_beacon()` in `endpoint/network.py`, `generate_dga_activity()` in `network/dns.py`

### Multi-Event Scenarios

Multi-event scenarios are YAML-defined attack chains with multiple phases:

```yaml
scenarios:
  - name: "Attack Scenario Name"
    severity: "critical"
    threat_actor: "APT29"
    ttps: ["T1566.001", "T1059.001"]

    environment:
      os_family: "windows"
      host_template: "workstation"

    phases:
      - name: "initial_access"
        duration_minutes: 5
        correlation:
          same_host: true
          same_user: true
          process_tree: true
        events:
          - type: "process"
            params:
              name: "powershell.exe"
          - type: "file"
            template: "malware_drop"
          - type: "network"
            template: "c2_beacon"

    generate_indicators: true
```

Available event types: `process`, `file`, `registry`, `network`, `authentication`, `dns`, `http`, `tls`, `aws_cloudtrail`, `azure_signin`, `azure_audit`, `gcp_audit`

### Configuration

Settings are loaded from environment variables or `.env` file via `config/settings.py`:

```bash
ELASTIC_URL=localhost:9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=changeme
LOG_LEVEL=INFO
GEMINI_API_KEY=optional_for_llm_features
```

Access settings:
```python
from secgen.config.settings import get_settings
settings = get_settings()
url = settings.elastic_url_with_protocol  # Adds http:// or https:// automatically
```

### Indexing to Elasticsearch

The `ElasticsearchIndexer` handles multi-index bulk operations:

```python
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.config.settings import get_settings

settings = get_settings()
indexer = ElasticsearchIndexer(settings)

# Index different event types - router automatically determines correct index
indexer.index_events(events, endpoint_alert)  # Routes by event.dataset
indexer.index_alert(alert)  # Goes to .alerts-security.alerts-default
```

Index patterns are mapped in `ElasticsearchIndexer._get_index_for_event()` based on `event.dataset` field.

## ECS Compliance Requirements

All generated events MUST follow Elastic Common Schema:

- Include proper `event.kind`, `event.category`, `event.type`, `event.dataset`
- Use standard field mappings (`host.id`, `user.name`, `process.entity_id`, etc.)
- Include correlation keys for entity linkage:
  - `host.id` - Links events to same host (enables Timeline)
  - `user.name` - Links events to same user (enables Entity Analytics)
  - `process.entity_id` - Links events in process tree (enables Analyzer)
  - `network.community_id` - Links network flows
- Timestamps in ISO 8601 format
- Reference: https://www.elastic.co/guide/en/ecs/current/index.html

## Testing Patterns

### Unit Tests
```python
def test_generator():
    gen = FileEventGenerator()
    host = Host.generate(template="workstation")
    user = User.generate(template="standard")

    event = gen.generate(host=host, user=user, is_malicious=True)

    assert event["host"]["id"] == host.id
    assert event["user"]["name"] == user.name
    assert "event" in event
```

### Integration Tests

Test entity correlation:
```python
def test_correlation():
    world = World()
    world.populate(num_hosts=5, num_users=10)

    host = world.get_random_host()
    user = world.get_random_user()
    world.assign_user_to_host(user, host)

    # Generate events from different generators
    file_gen = FileEventGenerator()
    dns_gen = DNSEventGenerator()

    file_event = file_gen.generate(host=host, user=user)
    dns_event = dns_gen.generate(host=host)

    # Verify correlation
    assert file_event["host"]["id"] == dns_event["host"]["id"]
```

## Code Style

- Line length: 100 characters
- Type hints required for all function signatures
- Docstrings following Google style
- Use `TYPE_CHECKING` imports for type hints to avoid circular imports
- Format with `black` before committing
- Run `ruff` linting before committing
