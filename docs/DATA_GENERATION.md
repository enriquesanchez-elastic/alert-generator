# Data Generation Architecture

This document explains how the Alert Generator creates realistic, ECS-compliant security data for testing Elastic Security Solution.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [The World State](#the-world-state)
4. [Entity Correlation](#entity-correlation)
5. [Generation Pipeline](#generation-pipeline)
6. [Event Generators](#event-generators)
7. [Campaign Mode](#campaign-mode)
8. [Time Distribution](#time-distribution)
9. [Indexing to Elasticsearch](#indexing-to-elasticsearch)

---

## Overview

The Alert Generator is designed to produce security events that closely mirror real-world attack scenarios. The key design principles are:

1. **ECS Compliance**: All events follow the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
2. **Entity Correlation**: Events share consistent identifiers enabling proper correlation in Security features
3. **Realistic Attack Chains**: Multi-stage attacks with proper process hierarchies
4. **Configurable Scenarios**: YAML-defined attack patterns

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              CLI                                     │
│  (commands: generate, world create, perf-test, sample-scenario)     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       AlertOrchestrator                              │
│  - Coordinates generation across multiple components                 │
│  - Manages World state integration                                   │
│  - Handles campaign mode and time distribution                       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   World State    │  │    Generators    │  │   Time Strategy  │
│  - Hosts         │  │  - Alert         │  │  - Minutes       │
│  - Users         │  │  - Process       │  │  - Hours         │
│  - ProcessTrees  │  │  - File          │  │  - Days          │
│  - Network       │  │  - Network       │  │  - Working Hours │
│  - ThreatActors  │  │  - DNS           │  │                  │
└──────────────────┘  │  - Auth          │  └──────────────────┘
                      │  - Cloud         │
                      └────────┬─────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ElasticsearchIndexer                              │
│  - Bulk indexing to appropriate indices                              │
│  - Routes events by type (process, file, network, etc.)             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Core Concepts

### Scenarios

A **Scenario** defines an attack pattern with:

- **Name & Description**: Human-readable identification
- **Severity**: `low`, `medium`, `high`, or `critical`
- **Process Chain**: Ordered list of processes from root to malware
- **Malware File**: Information about the malicious file

Scenarios are defined in YAML (`alert_scenarios.yaml`):

```yaml
scenarios:
  - name: "Ransomware"
    description: "File encryption ransomware attack"
    severity: "critical"
    processes:
      - name: "explorer.exe"
        executable: "C:\\Windows\\explorer.exe"
        args: ["C:\\Windows\\explorer.exe"]
        working_dir: "C:\\Users\\victim"
        user: "victim"
      - name: "powershell.exe"
        executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        args: ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "C:\\Temp\\dropper.ps1"]
        working_dir: "C:\\Temp"
        user: "victim"
      - name: "encrypt.exe"
        executable: "C:\\Temp\\encrypt.exe"
        args: ["C:\\Temp\\encrypt.exe", "--target", "C:\\Users", "--extension", ".locked"]
        working_dir: "C:\\Temp"
        user: "victim"
    malware_file:
      name: "encrypt.exe"
      path: "C:\\Temp\\encrypt.exe"
      extension: ".exe"
```

### Entities

**Entities** are persistent objects that maintain consistent identifiers:

| Entity | Key Fields | Purpose |
|--------|-----------|---------|
| **Host** | `host.id`, `host.name`, `agent.id` | Machine identification |
| **User** | `user.name`, `user.id` | Identity correlation |
| **ProcessTree** | `process.entity_id` | Process hierarchy |
| **ThreatActor** | IPs, domains, TTPs | Campaign attribution |

---

## The World State

The **World** is the central state manager that maintains entity consistency across all generated events.

### World Components

```python
@dataclass
class World:
    hosts: dict[str, Host]           # host.id -> Host
    users: dict[str, User]           # user.name -> User
    process_trees: dict[str, ProcessTree]  # host.id -> ProcessTree
    network: NetworkTopology         # Internal network config
    threat_actors: list[ThreatActor] # APT groups for campaigns
    active_campaigns: list[Campaign] # Running attack campaigns
```

### Populating the World

When the World is populated, it creates:

1. **Hosts** with distribution across templates:
   - 50% Workstations (Windows)
   - 20% Generic Servers (Linux)
   - 10% Web Servers (Linux)
   - 10% Database Servers (Linux)
   - 5% Domain Controllers (Windows)
   - 5% Linux Workstations

2. **Users** with distribution across types:
   - 70% Standard users
   - 10% Admin users
   - 15% Service accounts
   - System accounts (root, SYSTEM)

3. **User-Host Assignments**: Standard and admin users are assigned to 1-3 random hosts

4. **Default Threat Actors**: APT29, FIN7, Lazarus Group with associated infrastructure

### Host Generation

Hosts are generated from templates that define OS, architecture, and naming:

```python
templates = {
    "workstation": {"prefix": "workstation", "os": "windows", "arch": "x86_64"},
    "server": {"prefix": "server", "os": "linux", "arch": "x86_64"},
    "domain_controller": {"prefix": "dc", "os": "windows", "arch": "x86_64"},
    "mac_workstation": {"prefix": "macbook", "os": "macos", "arch": "arm64"},
    # ... more templates
}
```

Each host receives:
- Unique `host.id` (UUID)
- Auto-generated hostname (e.g., `workstation-42`)
- Private IP addresses (10.x.x.x, 172.16.x.x, 192.168.x.x)
- MAC addresses
- `agent.id` for Elastic Agent correlation
- `boot_id` for process tree scoping

### User Generation

Users are generated with realistic attributes:

```python
# Standard user example
User(
    name="alice.smith",
    id="1042",
    domain="CORPORATE",
    email="alice.smith@company.com",
    full_name="Alice Smith",
    user_type="standard",
    roles=["user"],
    groups=["Domain Users", "Users"],
    is_privileged=False,
)
```

Service accounts use names like `www-data`, `nginx`, `postgres`.

---

## Entity Correlation

Entity correlation is what makes the generated data useful for testing Elastic Security features like **Timeline**, **Analyzer**, and **Entity Analytics**.

### Correlation Keys

| Key | Description | Used By |
|-----|-------------|---------|
| `host.id` | Unique host identifier | Timeline, Entity Analytics |
| `user.name` | Username | Entity Analytics, Authentication |
| `process.entity_id` | Unique process identifier | Process Analyzer |
| `process.Ext.ancestry` | Process parent chain | Process Analyzer |
| `network.community_id` | Network flow identifier | Network correlation |

### How Correlation Works

When generating events, the same Host and User entities are passed to all generators:

```python
# Get entities from World
host = world.get_random_host(os_family="windows")
user = world.get_random_user(user_type="standard")
world.assign_user_to_host(user, host)

# All events share the same host.id and user.name
file_event = file_generator.generate(host=host, user=user)
dns_event = dns_generator.generate(host=host)
process_event = process_generator.generate(host=host, user=user)

# Result: All events have identical host.id, enabling Timeline correlation
assert file_event["host"]["id"] == dns_event["host"]["id"]
```

### Process Tree Correlation

For process events, proper parent-child relationships are maintained:

```python
# Entity IDs form a chain
entity_ids = ["parent-uuid", "child-uuid", "grandchild-uuid"]

# Each process includes ancestry (reversed parent chain)
process_event = {
    "process": {
        "entity_id": "grandchild-uuid",
        "parent": {"entity_id": "child-uuid"},
        "Ext": {
            "ancestry": ["child-uuid", "parent-uuid"]  # Leaf to root
        },
        "session_leader": {"entity_id": "parent-uuid"},
    }
}
```

This enables the **Process Analyzer** to visualize the complete attack chain.

---

## Generation Pipeline

### Step-by-Step Flow

```
1. Load Scenarios (YAML)
         │
         ▼
2. Initialize/Load World State
         │
         ▼
3. For each alert to generate:
         │
    ┌────┴────┐
    │         │
    ▼         ▼
4a. Get Host  4b. Get User
    │         │
    └────┬────┘
         │
         ▼
5. Select Scenario (random or by campaign phase)
         │
         ▼
6. Calculate Timestamp Offset (time strategy)
         │
         ▼
7. Generate Detection Alert (AlertGenerator)
         │
         ▼
8. Generate Process Events (ProcessEventGenerator)
         │
         ▼
9. Generate Endpoint Alert
         │
         ▼
10. Index to Elasticsearch (if not dry-run)
```

### AlertOrchestrator.generate_multiple()

The main orchestration method handles:

```python
def generate_multiple(
    self,
    count: int,                    # Number of alerts
    dry_run: bool = False,         # Skip indexing
    campaign_mode: bool = False,   # Correlated campaign
    time_spread: str = "minutes",  # minutes/hours/days/weeks
    working_hours: bool = False,   # Business hours weighting
    use_world: bool = False,       # Enable entity correlation
):
    # Initialize World if needed
    if use_world and world is None:
        world = World()
        world.populate(num_hosts=10, num_users=30)
    
    # Create campaign if in campaign mode
    if campaign_mode:
        campaign = campaign_generator.generate(campaign_hosts)
    
    # Get time distribution strategy
    time_strategy = get_strategy(time_spread, working_hours)
    
    for i in range(count):
        # Get entities
        host = world.get_or_create_host(...)
        user = world.get_random_user(...)
        
        # Select scenario
        scenario = random.choice(scenarios)
        
        # Calculate timestamp
        timestamp_offset = time_strategy.calculate_offset(i, count)
        
        # Generate alert and events
        alert, entity_ids = alert_generator.generate(
            scenario, host=host, user=user, timestamp_offset=timestamp_offset
        )
        events = process_generator.generate(scenario, entity_ids, host=host, user=user)
        
        # Index
        indexer.index_events(events, endpoint_alert)
        indexer.index_alert(alert)
```

---

## Event Generators

### AlertGenerator

Generates detection rule alerts with full ECS compliance:

**Output includes:**
- `@timestamp`
- `host.*` fields (from Host entity)
- `user.*` fields (from User entity)
- `process.*` fields with full hierarchy
- `file.*` fields for malware
- `event.*` fields (kind: signal, category: malware)
- `kibana.alert.*` fields for Security app integration

### ProcessEventGenerator

Generates process execution events for the attack chain:

```python
# For a 4-process chain, generates 4 events:
#
# Event 1: apache2 (session leader)
#   - entity_id: "aaa"
#   - ancestry: []
#
# Event 2: php-fpm (child)
#   - entity_id: "bbb"
#   - parent.entity_id: "aaa"
#   - ancestry: ["aaa"]
#
# Event 3: sh (grandchild)
#   - entity_id: "ccc"
#   - parent.entity_id: "bbb"
#   - ancestry: ["bbb", "aaa"]
#
# Event 4: webshell.php (malware - leaf)
#   - entity_id: "ddd"
#   - parent.entity_id: "ccc"
#   - ancestry: ["ccc", "bbb", "aaa"]
```

### FileEventGenerator

Generates file system events (creation, modification, deletion, rename):

**Supports:**
- OS-specific paths (Windows vs Linux vs macOS)
- Malicious file characteristics (untrusted signatures, high entropy)
- Code signatures and PE metadata for Windows executables
- Attack patterns: malware drops, data staging

### DNSEventGenerator

Generates DNS query/response events:

**Attack Patterns:**
- **DGA Activity**: High-entropy domains with 90% NXDOMAIN
- **DNS Tunneling**: Long subdomains with encoded data
- **C2 Beaconing**: Regular queries to C2 domains

```python
# Example: Generate DGA activity
events = dns_generator.generate_dga_activity(
    host=infected_host,
    domain_count=50,
    nxdomain_ratio=0.9
)
```

### Other Generators

| Generator | Purpose | Key Features |
|-----------|---------|--------------|
| `EndpointNetworkEventGenerator` | Network connections | C2 beacons, data exfiltration |
| `AuthenticationEventGenerator` | Login events | Brute force, failed logins |
| `RegistryEventGenerator` | Windows Registry | Persistence mechanisms |
| `AWSCloudTrailGenerator` | AWS audit logs | Suspicious API calls |
| `AzureSignInGenerator` | Azure AD sign-ins | MFA bypass, risky sign-ins |
| `ThreatIndicatorGenerator` | IOCs | IPs, domains, file hashes |

---

## Campaign Mode

Campaign mode generates **correlated multi-host attacks** that simulate real APT activity.

### Campaign Structure

```python
@dataclass
class Campaign:
    id: str                    # "a3b2c1d4"
    attacker_ip: str           # "203.0.113.42"
    c2_domain: str             # "evil-c2.badactor.com"
    c2_ip: str                 # "198.51.100.10"
    malware_family: str        # "APT-Backdoor"
    target_hosts: list[str]    # ["workstation-01", "server-05", ...]
    file_hash_base: str        # Shared hash prefix for variants
```

### Attack Phases

Campaigns progress through phases based on generation progress:

| Phase | Progress | Scenario Types | Description |
|-------|----------|----------------|-------------|
| **Initial** | 0-10% | Web Shell, Backdoor | Initial compromise |
| **Execution** | 10-40% | Crypto Miner, Ransomware, Privilege Escalation | Malware execution |
| **Lateral** | 40-80% | Lateral Movement, Privilege Escalation | Spreading |
| **Exfiltration** | 80-100% | Data Exfiltration, Ransomware | Final objectives |

### Phase Timing

Attack speed affects timestamp distribution:

```python
speed_configs = {
    "fast": {      # Minutes to hours
        "initial": (50, 60),      # 50-60 min ago
        "execution": (30, 50),    # 30-50 min ago
        "lateral": (10, 30),      # 10-30 min ago
        "exfiltration": (0, 10),  # Just happened
    },
    "medium": {    # Hours to half day
        "initial": (480, 720),    # 8-12 hours ago
        "execution": (240, 480),  # 4-8 hours ago
        "lateral": (60, 240),     # 1-4 hours ago
        "exfiltration": (0, 60),  # Last hour
    },
    "slow": {      # Days to weeks
        "initial": (10080, 20160),  # 7-14 days ago
        "execution": (5040, 10080), # 3.5-7 days ago
        "lateral": (1440, 5040),    # 1-3.5 days ago
        "exfiltration": (0, 1440),  # Last day
    },
}
```

---

## Time Distribution

Time distribution controls how events are spread across time.

### Strategies

| Strategy | Time Range | Use Case |
|----------|------------|----------|
| `minutes` | Last 60 minutes | Quick testing |
| `hours` | Last 24 hours | Daily analysis |
| `days` | Last 7 days | Weekly review |
| `weeks` | Last 30 days | Monthly reports |

### Business Hours Weighting

When `--working-hours` is enabled:
- Events are shifted to weekdays (Mon-Fri)
- Times adjusted to 8am-6pm
- More realistic for insider threat testing

### Implementation

```python
class BasicTimeStrategy:
    def calculate_offset(self, index: int, total: int) -> int:
        # Linear distribution with jitter
        base_offset = int((index / (total - 1)) * self.max_offset_minutes)
        jitter = random.randint(-jitter_range, jitter_range)
        return max(0, base_offset + jitter)
```

---

## Indexing to Elasticsearch

### Index Patterns

Events are routed to appropriate indices based on type:

| Event Type | Index Pattern |
|------------|---------------|
| Process | `logs-endpoint.events.process-default` |
| File | `logs-endpoint.events.file-default` |
| Network | `logs-endpoint.events.network-default` |
| Registry | `logs-endpoint.events.registry-default` |
| Endpoint Alert | `logs-endpoint.alerts-default` |
| DNS | `logs-dns.query-default` |
| Authentication | `logs-system.auth-default` |
| AWS CloudTrail | `logs-aws.cloudtrail-default` |
| Detection Alert | `.alerts-security.alerts-default` |

### Bulk Indexing

Events are indexed in bulk for efficiency:

```python
def index_events(self, events: list, endpoint_alert: dict):
    bulk_body = ""
    
    # Add process events
    for event in events:
        bulk_body += json.dumps({"create": {"_index": "logs-endpoint.events.process-default"}}) + "\n"
        bulk_body += json.dumps(event) + "\n"
    
    # Add endpoint alert
    bulk_body += json.dumps({"create": {"_index": "logs-endpoint.alerts-default"}}) + "\n"
    bulk_body += json.dumps(endpoint_alert) + "\n"
    
    # POST to _bulk API
    response = requests.post(f"{base_url}/_bulk", data=bulk_body)
```

### Multi-Type Indexing

For mixed event generation (performance testing):

```python
indexer.index_multi_type_events({
    "file": file_events,
    "dns": dns_events,
    "network": network_events,
    "authentication": auth_events,
})
```

---

## Usage Examples

### Basic Generation

```bash
# Generate 20 alerts with default settings
python -m secgen --count 20

# Dry run (no indexing)
python -m secgen --count 20 --dry-run --output alerts.json
```

### With World State

```bash
# Create persistent World
python -m secgen world create --hosts 50 --users 100 --save world.json

# Generate with World correlation
python -m secgen generate --count 30 --world-file world.json

# Ephemeral World (not saved)
python -m secgen generate --count 30 --use-world
```

### Campaign Mode

```bash
# Fast campaign (1 hour attack)
python -m secgen --count 50 --campaign --campaign-hosts 5 --attack-speed fast

# Slow campaign (weeks-long APT)
python -m secgen --count 100 --campaign --campaign-hosts 10 --attack-speed slow

# With World and working hours
python -m secgen generate --count 50 --campaign --use-world --working-hours
```

### Performance Testing

```bash
# Test generator performance
python -m secgen perf-test --events 10000 --types file network dns

# Test specific generators
python -m secgen perf-test --events 5000 --types auth --dry-run
```

---

## Data Flow Diagram

```
                    alert_scenarios.yaml
                           │
                           ▼
                   ┌───────────────┐
                   │ ScenarioLoader│
                   └───────┬───────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │                   World State                      │
    │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐   │
    │  │  Hosts  │  │  Users  │  │  Process Trees  │   │
    │  │ (50)    │  │ (100)   │  │  (per host)     │   │
    │  └────┬────┘  └────┬────┘  └────────┬────────┘   │
    │       │            │                │            │
    │       └────────────┼────────────────┘            │
    │                    │                              │
    └────────────────────┼──────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   AlertOrchestrator   │
              │   - Select scenario   │
              │   - Get host/user     │
              │   - Calculate time    │
              └──────────┬───────────┘
                         │
    ┌────────────────────┼────────────────────┐
    │                    │                    │
    ▼                    ▼                    ▼
┌─────────┐      ┌───────────────┐    ┌─────────────┐
│ Alert   │      │    Process    │    │  Endpoint   │
│Generator│      │   Generator   │    │    Alert    │
└────┬────┘      └───────┬───────┘    └──────┬──────┘
     │                   │                   │
     │ Detection Alert   │ Process Events    │ Endpoint Alert
     │                   │ (N per chain)     │
     │                   │                   │
     └───────────────────┼───────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ ElasticsearchIndexer │
              │ (Bulk API)           │
              └──────────────────────┘
                         │
                         ▼
    ┌────────────────────┼────────────────────┐
    │                    │                    │
    ▼                    ▼                    ▼
.alerts-security    logs-endpoint.     logs-endpoint.
.alerts-default     events.process     alerts-default
```

---

## Summary

The Alert Generator creates realistic security data through:

1. **Persistent World State**: Maintains consistent entity identifiers
2. **ECS-Compliant Events**: All fields follow Elastic Common Schema
3. **Proper Correlation**: `host.id`, `user.name`, `process.entity_id` link events
4. **Realistic Attack Chains**: Multi-process hierarchies with ancestry
5. **Campaign Support**: Multi-host correlated attacks with phases
6. **Flexible Time Distribution**: Minutes to weeks with business hours support
7. **Efficient Indexing**: Bulk operations to appropriate indices

This enables comprehensive testing of:
- Timeline investigation
- Process Analyzer visualization
- Entity Analytics user tracking
- Detection rule correlation
- Alert triage workflows

