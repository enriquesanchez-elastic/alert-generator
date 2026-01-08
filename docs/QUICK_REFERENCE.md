# SecGen Quick Reference

## CLI Commands

### Beat Event Generation

> **Note**: Add `--index` to send events to Elasticsearch. Without it, events are generated but not indexed.

```bash
# Auditbeat
python -m secgen generate auditbeat --count 50 --param dataset=auditd --index
python -m secgen generate auditbeat --count 20 --param dataset=system.login --param is_malicious=true --index
python -m secgen generate auditbeat --count 30 --param dataset=file_integrity --index

# Packetbeat
python -m secgen generate packetbeat --count 100 --param dataset=dns --index
python -m secgen generate packetbeat --count 50 --param dataset=http --param is_malicious=true --index
python -m secgen generate packetbeat --count 30 --param dataset=tls --index

# Filebeat
python -m secgen generate filebeat --count 200 --param dataset=system.syslog --index
python -m secgen generate filebeat --count 50 --param dataset=system.auth --param is_malicious=true --index
python -m secgen generate filebeat --count 100 --param dataset=nginx.access --index
```

### Attack Discovery & Cases

```bash
# Attack Discovery
python -m secgen generate attack-discovery --pattern brute-force --alerts 10 --index
python -m secgen generate attack-discovery --pattern c2-beacon --alerts 5 --index

# Security Cases
python -m secgen generate case --template brute-force-investigation --index
python -m secgen generate case --template ransomware-incident --alerts 10 --index
```

### Correlated Attack Chains

```bash
# Full attack chain (events → alerts → discovery → case)
python -m secgen correlated-attack brute-force --events 100 --index
python -m secgen correlated-attack c2-beacon --events 50 --index
python -m secgen correlated-attack ransomware --events 200 --index

# With world state
python -m secgen correlated-attack brute-force --world-file world.json --events 100 --index
```

---

## Python Quick Start

### Beat Events

```python
from secgen.generators.beats import (
    AuditbeatEventGenerator,
    PacketbeatEventGenerator,
    FilebeatEventGenerator,
)

# Auditbeat
auditbeat = AuditbeatEventGenerator()
event = auditbeat.generate(dataset="auditd")
events = auditbeat.generate_batch(count=50, dataset="system.login")

# Packetbeat
packetbeat = PacketbeatEventGenerator()
dns = packetbeat.generate(dataset="dns", domain="example.com")
http = packetbeat.generate(dataset="http", method="POST", path="/api")

# Filebeat
filebeat = FilebeatEventGenerator()
syslog = filebeat.generate(dataset="system.syslog")
auth = filebeat.generate(dataset="system.auth", is_malicious=True)
```

### Attack Patterns

```python
# Brute force attack
events = auditbeat.generate_brute_force(host=host, attempts=20, source_ip="10.0.0.1")

# C2 beacon
events = packetbeat.generate_c2_beacon(host=host, beacon_count=50, c2_domain="evil.com")

# SSH brute force
events = filebeat.generate_ssh_brute_force(host=host, attempts=30, source_ip="10.0.0.1")
```

### Attack Discovery

```python
from secgen.generators.attack_discovery import AttackDiscoveryGenerator

gen = AttackDiscoveryGenerator()

# From template
discovery = gen.generate(attack_pattern="brute-force", alert_ids=["alert-1", "alert-2"])

# From alerts
discovery = gen.generate_from_alerts(alerts, attack_pattern="c2-beacon")

# With entities
discovery = gen.generate(attack_pattern="ransomware", alert_ids=ids, hosts=[host], users=[user])
```

### Security Cases

```python
from secgen.generators.case import CaseGenerator

gen = CaseGenerator()

# From template
case = gen.generate(template="brute-force-investigation", severity=None)

# With alerts
case = gen.generate(template="malware-incident", alert_ids=["alert-1", "alert-2"])

# From attack discovery
case = gen.generate_from_attack_discovery(discovery)

# Add comments
case.add_comment("Investigation started", created_by="analyst1")
```

### MITRE ATT&CK

```python
from secgen.data.mitre_attack import (
    get_tactic,
    get_technique,
    build_threat_mapping,
    get_ttps_for_attack_pattern,
)

# Get data
tactic = get_tactic("TA0006")  # Credential Access
technique = get_technique("T1110")  # Brute Force

# Build threat mapping for alerts
mapping = build_threat_mapping(["T1110", "T1110.001"])

# Get TTPs for pattern
ttps = get_ttps_for_attack_pattern("brute-force")
```

### Detection Rules

```python
from secgen.data.detection_rules import (
    get_rule,
    get_rule_with_threat_mapping,
    build_kibana_rule_fields,
)

# Get rule
rule = get_rule("brute_force_attempt")

# With MITRE mapping
rule = get_rule_with_threat_mapping("ssh_brute_force")

# Build Kibana fields
fields = build_kibana_rule_fields("c2_beacon")
```

---

## Available Templates

### Attack Patterns (for Attack Discovery)

| Pattern | Description | Risk Score |
|---------|-------------|------------|
| `brute-force` | Brute force attack | 73 |
| `c2-beacon` | C2 beaconing | 99 |
| `ransomware` | Ransomware activity | 99 |
| `lateral-movement` | Lateral movement | 73 |
| `data-exfiltration` | Data exfiltration | 99 |
| `malware-drop` | Malware dropper | 73 |

### Case Templates

| Template | Description | Severity |
|----------|-------------|----------|
| `brute-force-investigation` | Brute force investigation | high |
| `malware-incident` | Malware incident response | critical |
| `ransomware-incident` | Ransomware incident | critical |
| `c2-investigation` | C2 activity investigation | high |
| `data-exfiltration-investigation` | Data exfil investigation | critical |
| `lateral-movement-investigation` | Lateral movement investigation | high |

### Detection Rules

| Rule ID | Name | TTPs |
|---------|------|------|
| `brute_force_attempt` | Brute Force Attempt | T1110 |
| `ssh_brute_force` | SSH Brute Force | T1110.001 |
| `suspicious_process` | Suspicious Process | T1059 |
| `c2_beacon` | C2 Beaconing | T1071 |
| `malware_execution` | Malware Execution | T1204 |
| `lateral_movement` | Lateral Movement | T1021 |

---

## Entity Correlation

```python
from secgen.core.world import World

# Create world for correlation
world = World()
world.populate(num_hosts=10, num_users=20)

# Get entities
host = world.get_random_host(os_family="linux")
user = world.get_random_user()
world.assign_user_to_host(user, host)

# Use in generators (all events will share host.id, user.name)
event = auditbeat.generate(dataset="auditd", host=host, user=user)
```

---

## Index Patterns

| Data Type | Index Pattern |
|-----------|---------------|
| Auditbeat | `auditbeat-*` |
| Packetbeat | `packetbeat-*` |
| Filebeat | `filebeat-*` |
| Alerts | `.alerts-security.alerts-default` |
| Attack Discovery | `.ai-attack-discovery-default` |
| Cases | `logs-case-default` |

