# SecGen Advanced Features Documentation

This document covers the advanced features for generating realistic, correlated security data including Beat events, MITRE ATT&CK threat mapping, Attack Discoveries, Security Cases, and AI-enhanced generation.

## Table of Contents

1. [Beat Event Generators](#beat-event-generators)
   - [Auditbeat](#auditbeat)
   - [Packetbeat](#packetbeat)
   - [Filebeat](#filebeat)
2. [MITRE ATT&CK Integration](#mitre-attck-integration)
3. [Detection Rules](#detection-rules)
4. [Attack Discovery](#attack-discovery)
5. [Security Cases](#security-cases)
6. [Correlated Attack Chains](#correlated-attack-chains)
7. [AI-Enhanced Generation](#ai-enhanced-generation)
8. [CLI Commands](#cli-commands)
9. [Python API Examples](#python-api-examples)

---

## Beat Event Generators

SecGen provides generators for the three main Elastic Beats: Auditbeat, Packetbeat, and Filebeat. These generate ECS-compliant events that match the format produced by real Beats agents.

### Auditbeat

Generates Linux audit and system monitoring events.

#### Supported Datasets

| Dataset | Description |
|---------|-------------|
| `auditd` | Linux audit framework events (syscalls, file access) |
| `system.login` | User login/logout events |
| `system.process` | Process start/stop events |
| `file_integrity` | File integrity monitoring (FIM) events |

#### CLI Usage

> **Note**: Add `--index` to send events to Elasticsearch.

```bash
# Generate 10 auditd events
python -m secgen generate auditbeat --count 10 --param dataset=auditd --index

# Generate malicious login attempts
python -m secgen generate auditbeat --count 20 --param dataset=system.login --param is_malicious=true --index

# Generate file integrity events
python -m secgen generate auditbeat --count 5 --param dataset=file_integrity --index
```

#### Python API

```python
from secgen.generators.beats import AuditbeatEventGenerator

gen = AuditbeatEventGenerator()

# Generate a single auditd event
event = gen.generate(dataset="auditd")

# Generate malicious login events
malicious_login = gen.generate(
    dataset="system.login",
    is_malicious=True,
)

# Generate process events with entity correlation
from secgen.models.entities import Host, User

host = Host.generate(template="linux-server")
user = User.generate(template="admin")

event = gen.generate(
    dataset="system.process",
    host=host,
    user=user,
    is_malicious=True,
)

# Batch generation
events = gen.generate_batch(count=100, dataset="auditd")
```

#### Attack Patterns

```python
# Generate brute force attack sequence
brute_force_events = gen.generate_brute_force(
    host=host,
    attempts=20,  # 19 failures + 1 success
    source_ip="192.168.1.100",
)

# Generate suspicious process execution
suspicious_events = gen.generate_suspicious_process(
    host=host,
    user=user,
    count=5,
)
```

### Packetbeat

Generates network traffic analysis events.

#### Supported Datasets

| Dataset | Description |
|---------|-------------|
| `dns` | DNS queries and responses |
| `http` | HTTP transactions |
| `tls` | TLS handshakes and metadata |
| `flow` | Network flow data (connections) |

#### CLI Usage

```bash
# Generate DNS events
python -m secgen generate packetbeat --count 50 --param dataset=dns --index

# Generate malicious HTTP traffic (C2 simulation)
python -m secgen generate packetbeat --count 20 --param dataset=http --param is_malicious=true --index

# Generate TLS events
python -m secgen generate packetbeat --count 30 --param dataset=tls --index
```

#### Python API

```python
from secgen.generators.beats import PacketbeatEventGenerator

gen = PacketbeatEventGenerator()

# Generate DNS query
dns_event = gen.generate(
    dataset="dns",
    domain="api.example.com",
    query_type="A",
)

# Generate HTTP request with specific parameters
http_event = gen.generate(
    dataset="http",
    method="POST",
    path="/api/login",
)

# Generate malicious DNS (DGA domain)
malicious_dns = gen.generate(
    dataset="dns",
    is_malicious=True,  # Uses DGA-like domains
)

# Generate TLS event
tls_event = gen.generate(
    dataset="tls",
    server_name="secure.example.com",
)
```

#### Attack Patterns

```python
# Generate C2 beacon traffic
c2_events = gen.generate_c2_beacon(
    host=host,
    beacon_count=10,
    c2_domain="evil.malware.com",
    beacon_interval_seconds=60,
)

# Generate DNS tunneling activity
tunnel_events = gen.generate_dns_tunnel(
    host=host,
    query_count=50,
)

# Generate DGA activity
dga_events = gen.generate_dga_activity(
    host=host,
    domain_count=100,
)
```

### Filebeat

Generates log file events from various sources.

#### Supported Datasets

| Dataset | Description |
|---------|-------------|
| `system.syslog` | System syslog messages |
| `system.auth` | Authentication logs (SSH, sudo) |
| `nginx.access` | Nginx HTTP access logs |
| `nginx.error` | Nginx error logs |
| `apache.access` | Apache HTTP access logs |
| `apache.error` | Apache error logs |

#### CLI Usage

```bash
# Generate syslog events
python -m secgen generate filebeat --count 100 --param dataset=system.syslog --index

# Generate auth events with failures
python -m secgen generate filebeat --count 30 --param dataset=system.auth --param is_malicious=true --index

# Generate nginx access logs
python -m secgen generate filebeat --count 200 --param dataset=nginx.access --index
```

#### Python API

```python
from secgen.generators.beats import FilebeatEventGenerator

gen = FilebeatEventGenerator()

# Generate syslog event
syslog = gen.generate(dataset="system.syslog")

# Generate auth event
auth_event = gen.generate(
    dataset="system.auth",
    is_malicious=True,  # Generates failed login attempts
)

# Generate nginx access log
nginx_event = gen.generate(
    dataset="nginx.access",
    method="GET",
    status_code=200,
)
```

#### Attack Patterns

```python
# Generate SSH brute force attack
brute_force = gen.generate_ssh_brute_force(
    host=host,
    attempts=50,
    source_ip="10.0.0.50",
)
```

---

## MITRE ATT&CK Integration

SecGen includes comprehensive MITRE ATT&CK mapping for realistic threat intelligence.

### Accessing MITRE Data

```python
from secgen.data.mitre_attack import (
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    get_tactic,
    get_technique,
    get_techniques_for_tactic,
    build_threat_mapping,
    get_ttps_for_attack_pattern,
)

# Get a specific tactic
tactic = get_tactic("TA0006")  # Credential Access
print(f"Tactic: {tactic['name']}")
print(f"Reference: {tactic['reference']}")

# Get a technique with subtechniques
technique = get_technique("T1110")  # Brute Force
print(f"Technique: {technique['name']}")
print(f"Tactics: {technique['tactic_ids']}")
print(f"Subtechniques: {technique['subtechniques']}")

# Get all techniques for a tactic
cred_techniques = get_techniques_for_tactic("TA0006")
for t in cred_techniques:
    print(f"  - {t['id']}: {t['name']}")
```

### Building Threat Mappings

```python
# Build ECS-compliant threat mapping for alerts
threat_mapping = build_threat_mapping(["T1110", "T1110.001", "T1059"])

# Returns format compatible with kibana.alert.rule.threat
# [
#   {
#     "framework": "MITRE ATT&CK",
#     "tactic": {"id": "TA0006", "name": "Credential Access", "reference": "..."},
#     "technique": [
#       {"id": "T1110", "name": "Brute Force", "reference": "...", "subtechnique": [...]}
#     ]
#   },
#   ...
# ]
```

### Attack Pattern to TTP Mapping

```python
# Get TTPs for known attack patterns
ttps = get_ttps_for_attack_pattern("brute-force")
# Returns: ["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004"]

ttps = get_ttps_for_attack_pattern("c2-beacon")
# Returns: ["T1071", "T1071.001", "T1571", "T1573"]
```

---

## Detection Rules

SecGen includes pre-built detection rule templates with proper MITRE mappings.

### Available Rules

| Rule ID | Name | TTPs |
|---------|------|------|
| `brute_force_attempt` | Brute Force Attempt | T1110, T1110.001 |
| `ssh_brute_force` | SSH Brute Force Attack | T1110, T1110.001 |
| `suspicious_process` | Suspicious Process Execution | T1059, T1059.001 |
| `c2_beacon` | Command and Control Beaconing | T1071, T1571 |
| `malware_execution` | Malware Execution Detected | T1204, T1059 |
| `lateral_movement` | Lateral Movement Detected | T1021, T1021.001 |
| `data_exfiltration` | Data Exfiltration Attempt | T1048, T1041 |

### Using Detection Rules

```python
from secgen.data.detection_rules import (
    DETECTION_RULES,
    get_rule,
    get_rule_with_threat_mapping,
    get_rule_for_attack_pattern,
    build_kibana_rule_fields,
)

# Get a specific rule
rule = get_rule("brute_force_attempt")
print(f"Rule: {rule['name']}")
print(f"Severity: {rule['severity']}")
print(f"TTPs: {rule['ttps']}")

# Get rule with full threat mapping (for alerts)
rule_with_mapping = get_rule_with_threat_mapping("ssh_brute_force")
print(f"Threat mapping: {rule_with_mapping['threat']}")

# Get rule for an attack pattern
rule = get_rule_for_attack_pattern("c2-beacon")

# Build Kibana alert rule fields
kibana_fields = build_kibana_rule_fields("brute_force_attempt")
# Returns all kibana.alert.rule.* fields with proper threat mapping
```

---

## Attack Discovery

Attack Discoveries summarize correlated attacks and provide investigation context.

### Model Structure

```python
from secgen.models.attack_discovery import AttackDiscovery, ATTACK_DISCOVERY_TEMPLATES

# Create an attack discovery
discovery = AttackDiscovery(
    title="Brute Force Attack Detected",
    alert_ids=["alert-1", "alert-2", "alert-3"],
    summary_markdown="Multiple failed authentication attempts detected...",
    details_markdown="## Attack Timeline\n...",
    mitre_attack_tactics=["TA0006"],
    mitre_attack_techniques=["T1110", "T1110.001"],
    risk_score=73,
)

# Convert to dictionary for indexing
doc = discovery.to_dict()
```

### Generator Usage

```python
from secgen.generators.attack_discovery import AttackDiscoveryGenerator

gen = AttackDiscoveryGenerator()

# Generate from attack pattern template
discovery = gen.generate(
    attack_pattern="brute-force",
    alert_ids=["alert-1", "alert-2", "alert-3"],
)

# Generate with entity information
discovery = gen.generate(
    attack_pattern="c2-beacon",
    alert_ids=["alert-1"],
    hosts=[host],
    users=[user],
)

# Generate from actual alert documents
alerts = [
    {"kibana.alert.uuid": "alert-1", "kibana.alert.rule.name": "Brute Force", ...},
    {"kibana.alert.uuid": "alert-2", "kibana.alert.rule.name": "Failed Auth", ...},
]
discovery = gen.generate_from_alerts(alerts, attack_pattern="brute-force")

# Batch generation
discoveries = gen.generate_batch(
    attack_patterns=["brute-force", "c2-beacon", "ransomware"],
    alerts_per_discovery=5,
)
```

### CLI Usage

```bash
# Generate attack discovery
python -m secgen generate attack-discovery --pattern brute-force --alerts 10 --index

# Generate and index
python -m secgen generate attack-discovery --pattern c2-beacon --alerts 5 --index

# List available patterns
python -m secgen describe attack-discovery
```

### Available Templates

| Template | Title | Risk Score |
|----------|-------|------------|
| `brute-force` | Brute Force Attack Detected | 73 |
| `c2-beacon` | Command and Control Beaconing Activity | 99 |
| `ransomware` | Ransomware Activity Detected | 99 |
| `lateral-movement` | Lateral Movement Detected | 73 |
| `data-exfiltration` | Data Exfiltration Attempt | 99 |
| `malware-drop` | Malware Dropper Activity | 73 |

---

## Security Cases

Security Cases provide incident management with full Elastic Cases API compatibility.

### Model Structure

```python
from secgen.models.case import SecurityCase, CaseComment, AlertAttachment

# Create a case
case = SecurityCase(
    title="Brute Force Attack Investigation",
    description="Investigation of brute force attack...",
    severity="high",
    tags=["brute-force", "investigation"],
    assignees=["analyst1"],
)

# Add a comment
case.add_comment("Initial triage completed", created_by="analyst1")

# Attach an alert
case.attach_alert(
    alert_id="alert-123",
    rule_name="SSH Brute Force",
    alert_index=".alerts-security.alerts-default",
)

# Link attack discovery
case.link_attack_discovery("discovery-456")

# Close the case
case.close(closed_by="analyst1")

# Convert to API format
api_doc = case.to_dict()
kibana_doc = case.to_kibana_format()
```

### Generator Usage

```python
from secgen.generators.case import CaseGenerator

gen = CaseGenerator()

# Generate from template
case = gen.generate(
    template="brute-force-investigation",
    severity=None,  # Use template severity
)

# Generate with alerts
case = gen.generate(
    template="malware-incident",
    alert_ids=["alert-1", "alert-2", "alert-3"],
)

# Generate with attack discovery link
case = gen.generate(
    template="c2-investigation",
    attack_discovery_ids=["discovery-1"],
)

# Generate from alert documents
alerts = [...]
case = gen.generate_from_alerts(alerts, attack_pattern="brute-force")

# Generate from attack discovery
case = gen.generate_from_attack_discovery(discovery)

# Simulate investigation workflow
case = gen.generate_investigation_workflow(case, analyst="analyst1")
```

### CLI Usage

```bash
# Generate a case from template
python -m secgen generate case --template brute-force-investigation --index

# Generate case with alerts
python -m secgen generate case --template malware-incident --alerts 10 --index

# List available templates
python -m secgen describe case
```

### Available Templates

| Template | Title | Severity |
|----------|-------|----------|
| `brute-force-investigation` | Brute Force Attack Investigation | high |
| `malware-incident` | Malware Incident Response | critical |
| `data-exfiltration-investigation` | Data Exfiltration Investigation | critical |
| `lateral-movement-investigation` | Lateral Movement Investigation | high |
| `ransomware-incident` | Ransomware Incident | critical |
| `c2-investigation` | C2 Activity Investigation | high |

---

## Correlated Attack Chains

Generate complete attack chains with linked events, alerts, discoveries, and cases.

### Using the Orchestrator

```python
from secgen.generators.correlated_attack import CorrelatedAttackOrchestrator
from secgen.config.settings import get_settings
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.core.world import World

settings = get_settings()
indexer = ElasticsearchIndexer(settings)

orchestrator = CorrelatedAttackOrchestrator(
    settings=settings,
    indexer=indexer,
)

# Create world state for entity correlation
world = World()
world.populate(num_hosts=10, num_users=20)

# Generate full attack chain
result = orchestrator.generate_full_chain(
    attack_pattern="brute-force",
    world=world,
    source_events=50,      # Number of source Beat events
    alerts_per_discovery=5,
    index=True,            # Index to Elasticsearch
)

print(f"Generated {result['event_count']} events")
print(f"Generated {result['alert_count']} alerts")
print(f"Generated {result['discovery_count']} attack discoveries")
print(f"Generated {result['case_count']} cases")
```

### CLI Usage

> **Note**: Add `--index` to send events to Elasticsearch. Without it, events are generated but not indexed.

```bash
# Generate full correlated attack chain
python -m secgen correlated-attack brute-force --events 100 --index

# Generate with specific world state
python -m secgen correlated-attack c2-beacon --world-file world.json --events 50 --index

# Dry run (no indexing)
python -m secgen correlated-attack ransomware --events 200

# Skip attack discovery or case generation
python -m secgen correlated-attack brute-force --events 50 --no-discovery --index
python -m secgen correlated-attack brute-force --events 50 --no-case --index
```

### Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Correlated Attack Chain                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐             │
│  │ Auditbeat  │    │ Packetbeat │    │ Filebeat   │             │
│  │   Events   │    │   Events   │    │   Events   │             │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘             │
│        │                 │                 │                     │
│        └────────────┬────┴─────────────────┘                    │
│                     ▼                                            │
│              ┌─────────────┐                                     │
│              │   Alerts    │  (with MITRE ATT&CK mapping)       │
│              │  (Signals)  │                                     │
│              └──────┬──────┘                                     │
│                     │                                            │
│                     ▼                                            │
│           ┌─────────────────┐                                    │
│           │ Attack Discovery │  (correlated findings)           │
│           └────────┬────────┘                                    │
│                    │                                             │
│                    ▼                                             │
│            ┌──────────────┐                                      │
│            │ Security Case │  (incident management)             │
│            └──────────────┘                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## AI-Enhanced Generation

SecGen includes optional AI-powered features that use Google Gemini to generate realistic, context-aware security data artifacts.

### Features Overview

| Generator | Purpose | Output |
|-----------|---------|--------|
| **CommandLibraryGenerator** | Realistic attack commands | Commands organized by MITRE ATT&CK tactic |
| **CampaignNarrativeGenerator** | Multi-day attack stories | Complete campaign narratives with phases |
| **EntityProfileGenerator** | User behavior profiles | Industry-specific personas |
| **ScenarioVariationGenerator** | Attack scenario variants | Multiple variations of base scenarios |

### Quick Setup

```bash
# Install google-genai
pip install google-genai

# Set API key
export GEMINI_API_KEY="your-api-key-here"
```

### CLI Usage

```bash
# Generate command library for lateral movement
secgen llm commands --tactic lateral_movement --actor APT29

# Generate campaign narrative
secgen llm campaign --actor APT29 --target technology --days 14

# Generate entity profiles for healthcare
secgen llm profiles --industry healthcare --roles 15

# View cache statistics
secgen llm cache stats
```

### Example: Generate Attack Commands (Python API)

```python
from secgen.config.settings import get_settings
from secgen.llm.client import GeminiClient
from secgen.llm.cache import ArtifactCache
from secgen.llm.generators.commands import CommandLibraryGenerator

settings = get_settings()
client = GeminiClient(api_key=settings.gemini_api_key)
cache = ArtifactCache(base_dir=settings.llm_artifacts_path)

cmd_gen = CommandLibraryGenerator(client=client, cache=cache)

# Generate commands styled after APT29 for lateral movement
data = cmd_gen.generate(
    tactic="lateral_movement",
    count=30,
    threat_actor_style="APT29",
    os_family="windows",
)

# Get a random command
cmd = cmd_gen.get_random_command(tactic="execution", category="powershell")
```

### Example: Generate Campaign Narrative

```python
from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

campaign_gen = CampaignNarrativeGenerator(client=client, cache=cache)

# Generate a 14-day APT campaign
data = campaign_gen.generate(
    threat_actor="APT29",
    target_sector="technology",
    dwell_time_days=14,
    objective="data_theft",
)

# Get IOCs from campaign
iocs = campaign_gen.get_indicators(threat_actor="APT29", target_sector="technology")

# Convert to executable scenarios
scenarios = campaign_gen.convert_to_scenarios(threat_actor="APT29", target_sector="technology")
```

### Available Threat Actors

- `APT29` - Russian state-sponsored, stealthy
- `APT28` - Russian military intelligence, aggressive
- `APT41` - Chinese state-sponsored with criminal sideline
- `FIN7` - Financial crime group
- `Lazarus` - North Korean state-sponsored
- `REvil`, `Conti` - Ransomware groups
- `generic_apt`, `generic_criminal` - Generic profiles

### Available Industries (for Entity Profiles)

- Healthcare (HIPAA, PHI access)
- Finance (PCI-DSS, trading systems)
- Technology (CI/CD, cloud infrastructure)
- Retail (POS systems)
- Manufacturing (OT/ICS systems)
- Government (classified information)
- Education (research data)
- Legal (client privilege)

> 📖 **For complete AI documentation**, see [AI_ENHANCED_GENERATION.md](AI_ENHANCED_GENERATION.md)

---

## CLI Commands

### Generate Commands

> **Note**: Add `--index` to send events to Elasticsearch.

```bash
# Beat events
python -m secgen generate auditbeat --count 50 --param dataset=auditd --index
python -m secgen generate packetbeat --count 100 --param dataset=dns --index
python -m secgen generate filebeat --count 200 --param dataset=system.syslog --index

# Attack discoveries
python -m secgen generate attack-discovery --pattern brute-force --alerts 10 --index

# Security cases
python -m secgen generate case --template malware-incident --alerts 5 --index

# Full correlated chain
python -m secgen correlated-attack --pattern c2-beacon --events 100 --index
```

### List and Describe

```bash
# List all event types
python -m secgen list event-types

# List Beat-specific event types
python -m secgen list event-types --category endpoint

# Describe a generator
python -m secgen describe event-type auditbeat
python -m secgen describe event-type packetbeat

# Describe attack patterns
python -m secgen describe attack auditbeat-brute-force
python -m secgen describe attack packetbeat-c2-beacon
```

### Indexing Options

```bash
# Index to Elasticsearch (required to write data)
python -m secgen generate auditbeat --count 100 --index

# Delete all generated data
python -m secgen --delete-all

# Validate Elasticsearch connection
python -m secgen validate-es
```

---

## Python API Examples

### Complete Attack Simulation

```python
"""
Complete example: Generate a brute force attack with all correlated data.
"""
from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.generators.beats import AuditbeatEventGenerator, FilebeatEventGenerator
from secgen.generators.alert import AlertGenerator
from secgen.generators.attack_discovery import AttackDiscoveryGenerator
from secgen.generators.case import CaseGenerator
from secgen.data.mitre_attack import build_threat_mapping
from secgen.indexers.elasticsearch import ElasticsearchIndexer

# Setup
settings = get_settings()
indexer = ElasticsearchIndexer(settings)

# Create world for entity correlation
world = World()
world.populate(num_hosts=5, num_users=10)

# Get target host and user
host = world.get_random_host(os_family="linux")
user = world.get_random_user()
world.assign_user_to_host(user, host)

# 1. Generate source events (Auditbeat login failures)
auditbeat = AuditbeatEventGenerator()
login_events = auditbeat.generate_brute_force(
    host=host,
    user=user,
    attempts=25,
    source_ip="10.0.0.100",
)
print(f"Generated {len(login_events)} login events")

# 2. Generate correlated filebeat auth events
filebeat = FilebeatEventGenerator()
auth_events = filebeat.generate_ssh_brute_force(
    host=host,
    attempts=25,
    source_ip="10.0.0.100",
)
print(f"Generated {len(auth_events)} auth log events")

# 3. Generate alert for the attack
alert_gen = AlertGenerator(settings)
alert, entity_ids = alert_gen.generate_from_events(
    events=login_events + auth_events,
    rule_id="brute_force_attempt",
    host=host,
    user=user,
)
print(f"Generated alert: {alert['kibana.alert.uuid']}")

# 4. Generate attack discovery
discovery_gen = AttackDiscoveryGenerator()
discovery = discovery_gen.generate(
    attack_pattern="brute-force",
    alert_ids=[alert["kibana.alert.uuid"]],
    hosts=[host],
    users=[user],
)
print(f"Generated attack discovery: {discovery.id}")

# 5. Generate security case
case_gen = CaseGenerator()
case = case_gen.generate_from_attack_discovery(discovery)
print(f"Generated case: {case.id}")

# 6. Index everything
all_events = {
    "auditbeat.login": login_events,
    "filebeat.auth": auth_events,
}
indexer.index_multi_type_events(all_events)
indexer.index_alert(alert)
indexer.index_typed_events([discovery.to_dict()], "attack_discovery")
indexer.index_typed_events([case.to_dict()], "case")

print("All data indexed successfully!")
```

### C2 Beacon Detection Simulation

```python
"""
Example: Generate C2 beacon traffic with network events and detection.
"""
from secgen.generators.beats import PacketbeatEventGenerator
from secgen.generators.attack_discovery import AttackDiscoveryGenerator

# Setup
packetbeat = PacketbeatEventGenerator()
discovery_gen = AttackDiscoveryGenerator()

# Generate C2 beacon traffic
c2_events = packetbeat.generate_c2_beacon(
    host=host,
    c2_domain="command.evil.com",
    beacon_count=50,
    beacon_interval_seconds=60,
)

# Generate related DNS events
dns_events = packetbeat.generate_batch(
    count=50,
    dataset="dns",
    domain="command.evil.com",
    is_malicious=True,
)

# Generate HTTP C2 traffic
http_events = packetbeat.generate_batch(
    count=20,
    dataset="http",
    method="POST",
    path="/c2/beacon",
    is_malicious=True,
)

# Generate attack discovery
discovery = discovery_gen.generate(
    attack_pattern="c2-beacon",
    alert_ids=[f"c2-alert-{i}" for i in range(5)],
    hosts=[host],
)

print(f"Generated {len(c2_events)} C2 events")
print(f"Generated {len(dns_events)} DNS events")  
print(f"Generated {len(http_events)} HTTP events")
print(f"Attack Discovery: {discovery.title}")
```

### Ransomware Incident Simulation

```python
"""
Example: Full ransomware incident simulation.
"""
from secgen.generators.beats import AuditbeatEventGenerator, FilebeatEventGenerator
from secgen.generators.attack_discovery import AttackDiscoveryGenerator
from secgen.generators.case import CaseGenerator

# Setup generators
auditbeat = AuditbeatEventGenerator()
filebeat = FilebeatEventGenerator()
discovery_gen = AttackDiscoveryGenerator()
case_gen = CaseGenerator()

# 1. Initial access (phishing email opened)
# Simulated by suspicious process execution
process_events = auditbeat.generate_suspicious_process(
    host=host,
    user=user,
    count=5,
)

# 2. Execution (malware running)
execution_events = auditbeat.generate_batch(
    count=10,
    dataset="system.process",
    is_malicious=True,
    host=host,
)

# 3. File encryption activity (FIM events)
fim_events = auditbeat.generate_batch(
    count=100,
    dataset="file_integrity",
    is_malicious=True,
    host=host,
)

# 4. Generate attack discovery
discovery = discovery_gen.generate(
    attack_pattern="ransomware",
    alert_ids=[f"ransom-alert-{i}" for i in range(10)],
    hosts=[host],
    users=[user],
)

# 5. Create incident case
case = case_gen.generate(
    template="ransomware-incident",
    severity=None,
    attack_discovery_ids=[discovery.id],
)

# 6. Add investigation comments
case.add_comment("CRITICAL: Ransomware detected on host", created_by="soc-analyst")
case.add_comment("Containment actions initiated", created_by="ir-team")
case.add_comment("Affected systems isolated from network", created_by="ir-team")

print(f"Ransomware simulation complete!")
print(f"  - Process events: {len(process_events)}")
print(f"  - Execution events: {len(execution_events)}")
print(f"  - FIM events: {len(fim_events)}")
print(f"  - Attack Discovery: {discovery.title}")
print(f"  - Case: {case.title} (Status: {case.status})")
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTIC_URL` | Elasticsearch URL (host:port) | `localhost:9200` |
| `ELASTIC_USERNAME` | Elasticsearch username | `elastic` |
| `ELASTIC_PASSWORD` | Elasticsearch password | `changeme` |
| `KIBANA_URL` | Kibana URL for Cases API | Auto-derived from ELASTIC_URL |
| `ALERTS_INDEX` | Alerts index pattern | `.alerts-security.alerts-default` |

**Note**: If `KIBANA_URL` is not set, it's automatically derived from `ELASTIC_URL` by replacing port 9200 with 5601. For Elastic Cloud, set this explicitly.

---

## Index Patterns

The following Elasticsearch index patterns are used:

| Event Type | Index Pattern |
|------------|---------------|
| Auditbeat (auditd) | `auditbeat-*` |
| Packetbeat (dns) | `packetbeat-*` |
| Packetbeat (http) | `packetbeat-*` |
| Packetbeat (tls) | `packetbeat-*` |
| Packetbeat (flow) | `packetbeat-*` |
| Filebeat (syslog) | `filebeat-*` |
| Filebeat (auth) | `filebeat-*` |
| Filebeat (nginx) | `filebeat-*` |
| Security Alerts | `.alerts-security.alerts-default` |
| Attack Discovery | `.ai-attack-discovery-default` |
| Security Cases | `logs-case-default` |

---

## Best Practices

### 1. Use World State for Correlation

```python
# Always use World for consistent entity correlation
world = World()
world.populate(num_hosts=10, num_users=20)

host = world.get_random_host()
user = world.get_random_user()
world.assign_user_to_host(user, host)

# All events will share host.id, user.name for proper correlation
```

### 2. Link Events to Alerts

```python
# Store event IDs for alert linkage
event_ids = [event["event"]["id"] for event in events]

# Reference in alerts
alert["kibana.alert.original_event.id"] = event_ids[0]
```

### 3. Use Templates for Consistency

```python
# Use pre-built templates for consistent, realistic data
discovery = gen.generate(attack_pattern="brute-force", ...)
case = gen.generate(template="brute-force-investigation", ...)
```

### 4. Test with Dry Run First

```bash
# Test without indexing first (no --index flag)
python -m secgen correlated-attack brute-force --events 100

# Then index when ready
python -m secgen correlated-attack brute-force --events 100 --index
```

---

## Troubleshooting

### Common Issues

1. **Events not appearing in Kibana Timeline**
   - Ensure `host.id` is consistent across related events
   - Verify timestamps are in ISO 8601 format

2. **Alerts missing MITRE mapping**
   - Use `build_kibana_rule_fields()` for proper threat mapping
   - Verify rule templates include TTPs

3. **Cases not linking to alerts**
   - Ensure alert UUIDs match in case attachments
   - Verify alert index pattern is correct

### Debug Mode

```bash
# Enable debug logging
LOG_LEVEL=DEBUG python -m secgen generate auditbeat --count 10
```

