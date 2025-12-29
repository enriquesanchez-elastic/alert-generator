# Contributing to Security Data Generator

Thank you for your interest in contributing to Security Data Generator!

## Development Setup

1. **Clone the repository** (if contributing externally):
   ```bash
   git clone https://github.com/enriquesanchez-elastic/secgen
   cd secgen
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"  # Install with dev dependencies
   ```

## Code Structure

The project follows a modular architecture with entity-based correlation:

```
secgen/
├── core/                     # Core components
│   └── world.py              # World state management
├── models/
│   ├── entities/             # Entity models for correlation
│   │   ├── host.py           # Host entity
│   │   ├── user.py           # User entity
│   │   └── process_tree.py   # Process tree entity
│   ├── scenario.py           # Scenario definitions (legacy + multi-event)
│   ├── campaign.py           # Campaign model
│   └── alert.py              # Alert model
├── generators/
│   ├── endpoint/             # Endpoint event generators
│   │   ├── file.py           # File events
│   │   ├── registry.py       # Registry events (Windows)
│   │   └── network.py        # Endpoint network events
│   ├── network/              # Network event generators
│   │   ├── dns.py            # DNS events
│   │   ├── flow.py           # Network flow events
│   │   ├── http.py           # HTTP events
│   │   └── tls.py            # TLS events
│   ├── identity/             # Identity event generators
│   │   ├── auth.py           # Authentication events
│   │   └── iam.py            # IAM events
│   ├── cloud/                # Cloud audit log generators
│   │   ├── aws.py            # AWS CloudTrail
│   │   ├── azure.py          # Azure AD/Audit
│   │   └── gcp.py            # GCP Audit
│   ├── threat_intel/         # Threat intelligence
│   │   └── indicators.py     # Threat indicators
│   ├── alert.py              # Detection alert generator
│   ├── process.py            # Process event generator
│   ├── campaign.py           # Campaign generator
│   └── randomizers.py        # Random data utilities
├── indexers/                 # Storage backends
│   ├── base.py               # Base indexer interface
│   └── elasticsearch.py      # Elasticsearch implementation
├── time_distribution/        # Time distribution strategies
│   ├── base.py               # Base strategy
│   └── strategies.py         # Distribution implementations
├── config/
│   ├── loader.py             # YAML scenario loader
│   └── settings.py           # Pydantic settings
├── utils/                    # Utilities
│   └── logger.py             # Logging configuration
├── core.py                   # Alert orchestration
└── cli.py                    # Command-line interface
```

## Adding New Features

### Adding a New Event Generator

1. Create a new generator module in the appropriate subdirectory:
   - `generators/endpoint/` - for endpoint telemetry (file, registry, etc.)
   - `generators/network/` - for network events (DNS, HTTP, TLS, etc.)
   - `generators/identity/` - for identity events (auth, IAM)
   - `generators/cloud/` - for cloud audit logs
   - `generators/security/` - for security scan events (vulnerability, etc.)
   - `generators/analytics/` - for analytics events (risk scores, etc.)

2. **Use decorators for CLI discovery** - this enables your generator to be used via `secgen generate <name>` and discovered via `secgen list event-types`:

```python
"""New event generator for X events."""

import random
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
    name="my-event",                        # CLI name: secgen generate my-event
    category=GeneratorCategory.ENDPOINT,    # Category for grouping
    description="My events for X activity", # Shown in secgen list
    ecs_fields=[                            # Key ECS fields generated
        "field1",
        "field2",
        "host.id",
        "user.name",
    ],
    index_pattern="logs-my.events-default", # Elasticsearch index
    example_params={"is_malicious": True},  # Example parameters
)
class NewEventGenerator:
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
                "category": ["your_category"],
                "type": ["info"],
                "dataset": "my.events",
            },
            # ... ECS-compliant fields
        }
        
        if host:
            event["host"] = {"id": host.id, "name": host.name, ...}
        if user:
            event["user"] = {"name": user.name, "id": user.id, ...}
        
        return event

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        malicious_ratio: float = 0.2,
    ) -> list[Dict[str, Any]]:
        """Generate multiple events (recommended for CLI)."""
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
```

3. **Register in bootstrap** - Add to `secgen/registry_bootstrap.py`:

```python
from secgen.generators.mydir import NewEventGenerator  # noqa: F401
# ...
finalize_attack_patterns(NewEventGenerator)
```

4. Export in `generators/<subdir>/__init__.py`

5. Add corresponding index pattern handling in `indexers/elasticsearch.py` if needed

### Adding Attack Patterns

Attack patterns generate multiple correlated events. Use the `@register_attack_pattern` decorator to enable CLI discovery via `secgen attack <name>`:

```python
@register_attack_pattern(
    name="my-attack",                        # CLI: secgen attack my-attack
    description="Attack pattern description",
    ttps=["T1234", "T1235"],                 # MITRE ATT&CK TTPs
    category=GeneratorCategory.ENDPOINT,
    required_params=["host", "user"],        # Required method parameters
    optional_params=["count"],               # Optional parameters
    event_types=["my-event"],                # Event types generated
    detection_recommendations=[              # For describe output
        "Detection rule recommendation 1",
        "Detection rule recommendation 2",
    ],
)
def generate_my_attack(
    self,
    host: "Host",
    user: "User",
    count: int = 10,
) -> List[Dict[str, Any]]:
    """Generate events for attack pattern."""
    events = []
    # Generate correlated events
    return events
```

Examples of existing attack patterns:
- `generate_brute_force()` in `AuthenticationEventGenerator`
- `generate_c2_beacon()` in `EndpointNetworkEventGenerator`
- `generate_dga_activity()` in `DNSEventGenerator`
- `generate_registry_persistence()` in `RegistryEventGenerator`

### Available Generator Categories

Use these in the `@register_event_type` decorator:

```python
from secgen.registry import GeneratorCategory

GeneratorCategory.ENDPOINT      # Endpoint telemetry
GeneratorCategory.NETWORK       # Network events
GeneratorCategory.IDENTITY      # Identity/auth events
GeneratorCategory.CLOUD         # Cloud audit logs
GeneratorCategory.THREAT_INTEL  # Threat indicators
GeneratorCategory.SECURITY      # Security scan events
GeneratorCategory.ANALYTICS     # Analytics/risk events
```

### Adding Entity Support

1. Create entity model in `models/entities/`:

```python
@dataclass
class MyEntity:
    id: str
    name: str
    # ... other fields
    
    @classmethod
    def create_random(cls) -> "MyEntity":
        """Create a random instance."""
        ...
```

2. Register in World state (`core/world.py`)

3. Export in `models/entities/__init__.py`

### Adding Multi-Event Scenarios

Create YAML scenarios with multiple phases:

```yaml
scenarios:
  - name: "My Attack Scenario"
    severity: "high"
    threat_actor: "APT_Name"
    ttps: ["T1234.001"]
    
    environment:
      os_family: "windows"
      host_template: "workstation"
      
    phases:
      - name: "initial_access"
        duration_minutes: 5
        events:
          - type: "authentication"
            template: "successful_login"
          - type: "process"
            params:
              name: "powershell.exe"
              args: ["-enc", "..."]
          - type: "file"
            template: "malware_drop"
            
    generate_indicators: true
```

Available event types: `process`, `file`, `registry`, `network`, `authentication`, `dns`, `http`, `tls`, `aws_cloudtrail`, `azure_signin`, `azure_audit`, `gcp_audit`

### Adding a New Time Distribution Strategy

1. Add to `time_distribution/strategies.py`:

```python
class MyDistribution(TimeDistributionStrategy):
    def calculate_offset(self, index: int, total: int, **kwargs) -> timedelta:
        # Your distribution logic
        return timedelta(...)
```

2. Register in `get_strategy()` function

## Code Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Add docstrings following Google style
- Line length: 100 characters (configured in `pyproject.toml`)
- Run `black` for formatting: `black secgen/`
- Run `ruff` for linting: `ruff check secgen/`

## Testing

### Run All Tests
```bash
pytest
```

### Run with Coverage
```bash
pytest --cov=secgen --cov-report=html
```

### Run Specific Tests
```bash
# Test a specific module
pytest tests/test_generators/test_alert.py

# Test new components
PYTHONPATH=. python3 -c "
from secgen.core.world import World
from secgen.generators.endpoint.file import FileEventGenerator

world = World()
world.populate(num_hosts=5, num_users=10)
host = world.get_random_host()
user = world.get_random_user()

file_gen = FileEventGenerator()
event = file_gen.generate(host=host, user=user, is_malicious=True)
print(event)
"
```

### Testing Entity Correlation
```bash
PYTHONPATH=. python3 -c "
from secgen.core.world import World

world = World()
world.populate(num_hosts=5, num_users=10)

host = world.get_random_host()
user = world.get_random_user()
world.assign_user_to_host(user, host)

process = world.spawn_process(
    host_id=host.id,
    name='test.exe',
    executable='/bin/test',
    args=['--flag'],
    user=user,
)

# All events generated with these entities will share:
# - host.id
# - user.name
# - process.entity_id (for process tree)
"
```

## ECS Compliance

All generated events must follow [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html):

- Use proper field mappings (e.g., `host.id`, `user.name`, `process.entity_id`)
- Include correlation keys for entity linkage
- Use correct event.kind, event.category, event.type values
- Include timestamps in ISO 8601 format

Key correlation fields:
- `host.id` - Links events to same host
- `user.name` - Links events to same user
- `process.entity_id` - Links events in process tree
- `network.community_id` - Links network events

## Submitting Changes

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and test them

3. **Run linting**:
   ```bash
   black secgen/
   ruff check secgen/ --fix
   ```

4. **Commit with descriptive messages**:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```

5. **Push and create a pull request**

## Documentation

- Update docstrings when adding new functions/classes
- Update README.md if adding new features or changing usage
- Keep examples up-to-date
- Document new event types and their ECS mappings

## Questions?

If you have questions, please open an issue for discussion.
