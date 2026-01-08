# SecGen Preset System

Presets provide one-command workflows for complex data generation scenarios. This guide covers built-in presets and how to create custom presets.

## Quick Reference

```bash
# List all available presets
secgen preset --list
secgen preset -l

# Run a preset
secgen preset <preset-name>

# Run without indexing (preview)
secgen preset <preset-name> --no-index

# Save events to file
secgen preset <preset-name> --output events.json

# Run from custom YAML file
secgen preset ./my-preset.yaml
```

## Built-in Presets (25 Total)

### Quick Start & Testing

| Preset | Description | Hosts | Users | Events |
|--------|-------------|-------|-------|--------|
| `quick-start` | Minimal data to verify Elastic Security setup | 5 | 10 | ~80 |
| `siem-demo` | Balanced SIEM data for sales demos | 15 | 30 | ~700 |
| `load-test` | High-volume event generation for performance testing | 100 | 200 | ~18,000 |

### Attack Simulation

| Preset | Description | Hosts | Users | Events |
|--------|-------------|-------|-------|--------|
| `attack-simulation` | Multi-stage attack chain for detection rule testing | 15 | 30 | ~100 |
| `ransomware-attack` | Ransomware attack from initial access to encryption | 10 | 20 | ~500 |
| `apt-campaign` | Week-long Advanced Persistent Threat campaign | 20 | 40 | ~500 |
| `insider-threat` | Insider threat scenario with data theft indicators | 10 | 25 | ~500 |
| `credential-attack` | Brute force, credential stuffing, phishing attacks | 15 | 50 | ~400 |

### Feature-Specific

| Preset | Description | Hosts | Users | Events |
|--------|-------------|-------|-------|--------|
| `timeline-investigation` | Correlated events for Timeline investigation | 5 | 10 | ~400 |
| `analyzer-showcase` | Process-heavy data for Analyzer visualization | 5 | 10 | ~200 |
| `network-map-demo` | Geo-diverse network flows for Network Map | 30 | 50 | ~2,100 |
| `vulnerability-dashboard` | Vulnerability data for VM dashboard | 50 | 25 | ~750 |
| `cspm-compliance` | Cloud posture data for CSPM dashboards | 10 | 20 | ~700 |
| `entity-analytics-showcase` | Entity Analytics with diverse risk scores | 30 | 60 | ~500 |

### Cloud Security

| Preset | Description | Hosts | Users | Events |
|--------|-------------|-------|-------|--------|
| `cloud-security` | Multi-cloud security events | 10 | 20 | ~750 |
| `aws-security` | AWS-focused CloudTrail and CSPM | 10 | 30 | ~1,100 |
| `azure-security` | Azure AD and identity security | 10 | 40 | ~900 |

### Specialized Use Cases

| Preset | Description | Hosts | Users | Events |
|--------|-------------|-------|-------|--------|
| `demo-cluster` | Comprehensive demo data for all features | 25 | 50 | ~1,800 |
| `detection-engineering` | Malicious events for tuning detection rules | 20 | 40 | ~400 |
| `threat-hunting` | Mixed benign/malicious data for hunting exercises | 30 | 60 | ~2,300 |
| `incident-response` | Complete attack chain for IR training | 15 | 30 | ~600 |
| `soc-training` | Varied alerts for SOC analyst training | 25 | 50 | ~900 |
| `endpoint-telemetry` | Rich endpoint telemetry for EDR testing | 20 | 40 | ~1,300 |
| `dns-security` | DNS-focused events and attacks | 15 | 30 | ~1,200 |
| `network-visibility` | Network flows for Network Map analysis | 20 | 40 | ~1,500 |

---

## Detailed Preset Descriptions

### Quick Start Presets

#### `quick-start`

**Purpose:** Minimal data to quickly verify Elastic Security is working correctly.

```bash
secgen preset quick-start
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | file | 20 |
| event | authentication | 20 |
| event | dns | 20 |
| attack | brute-force | 1 |

---

#### `siem-demo`

**Purpose:** Balanced data for sales demos and presentations.

```bash
secgen preset siem-demo
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | file | 100 |
| event | registry | 50 |
| event | endpoint-network | 100 |
| event | network-flow | 150 |
| event | dns | 100 |
| event | authentication | 100 |
| attack | brute-force | 1 |
| attack | c2-beacon | 1 |

---

### Attack Simulation Presets

#### `ransomware-attack`

**Purpose:** Simulate a complete ransomware attack chain.

**MITRE ATT&CK Techniques Covered:**
- T1105 (Ingress Tool Transfer)
- T1547.001 (Boot or Logon Autostart Execution)
- T1562.001 (Impair Defenses)
- T1021 (Remote Services)
- T1071 (Application Layer Protocol)
- T1041 (Exfiltration Over C2 Channel)

```bash
secgen preset ransomware-attack
```

| Step Type | Name | Count |
|-----------|------|-------|
| attack | malware-drop | 1 |
| attack | registry-persistence | 2 |
| attack | security-disable | 1 |
| event | dns | 50 |
| event | endpoint-network | 100 |
| attack | lateral-movement | 3 |
| attack | data-staging | 2 |
| attack | c2-beacon | 2 |
| attack | data-exfiltration | 1 |
| event | file | 200 |

---

#### `apt-campaign`

**Purpose:** Week-long Advanced Persistent Threat campaign simulation.

**Time Spread:** 168 hours (1 week)

```bash
secgen preset apt-campaign
```

Simulates:
- Day 1: Initial compromise and persistence
- Day 1-2: C2 establishment
- Day 2-3: Internal reconnaissance
- Day 3-4: Credential harvesting
- Day 4-5: Lateral movement
- Day 5-6: Data collection
- Day 6-7: Exfiltration

---

#### `insider-threat`

**Purpose:** Simulate malicious insider data theft.

```bash
secgen preset insider-threat
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | authentication | 150 |
| event | file | 100 |
| event | authentication (suspicious) | 30 |
| event | file (sensitive) | 150 |
| attack | data-staging | 2 |
| event | http | 50 |
| attack | data-exfiltration | 1 |
| event | risk-score | 25 |

---

#### `credential-attack`

**Purpose:** Credential-focused attack scenarios.

```bash
secgen preset credential-attack
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | authentication | 200 |
| attack | brute-force | 3 |
| attack | credential-stuffing | 2 |
| attack | impossible-travel | 2 |
| attack | mfa-bypass | 1 |
| event | risk-score | 50 |

---

### Feature-Specific Presets

#### `timeline-investigation`

**Purpose:** Dense correlated events for Timeline investigation practice.

```bash
secgen preset timeline-investigation
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | file | 100 |
| event | registry | 50 |
| event | endpoint-network | 100 |
| event | dns | 75 |
| event | authentication | 50 |
| attack | malware-drop | 1 |
| attack | c2-beacon | 1 |

---

#### `analyzer-showcase`

**Purpose:** Data optimized for Analyzer (process tree) visualization.

```bash
secgen preset analyzer-showcase
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | file | 50 |
| event | registry | 30 |
| event | endpoint-network | 50 |
| attack | malware-drop | 2 |
| attack | registry-persistence | 2 |
| attack | c2-beacon | 2 |

---

#### `network-map-demo`

**Purpose:** Geo-diverse network flows for Network Map visualization.

```bash
secgen preset network-map-demo
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | network-flow | 1000 |
| event | dns | 500 |
| event | http | 300 |
| event | tls | 300 |
| attack | c2-beacon | 2 |
| attack | dga-activity | 1 |
| attack | dns-tunneling | 1 |

---

#### `vulnerability-dashboard`

**Purpose:** Vulnerability data for VM dashboard testing.

```bash
secgen preset vulnerability-dashboard
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | vulnerability | 500 |
| event | file | 100 |
| event | endpoint-network | 100 |
| event | risk-score (host) | 50 |

---

#### `cspm-compliance`

**Purpose:** Cloud posture data for CSPM compliance dashboards.

```bash
secgen preset cspm-compliance
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | cspm (AWS) | 200 |
| event | cspm (Azure) | 150 |
| event | cspm (GCP) | 100 |
| event | aws-cloudtrail | 100 |
| event | azure-audit | 100 |
| event | gcp-audit | 50 |

---

### Cloud Security Presets

#### `aws-security`

**Purpose:** AWS-focused cloud security events.

```bash
secgen preset aws-security
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | aws-cloudtrail | 500 |
| event | cspm (AWS) | 300 |
| event | network-flow | 200 |
| event | dns | 100 |

---

#### `azure-security`

**Purpose:** Azure AD and identity-focused security events.

```bash
secgen preset azure-security
```

| Step Type | Name | Count |
|-----------|------|-------|
| event | azure-audit | 400 |
| event | authentication | 200 |
| event | cspm (Azure) | 250 |
| attack | brute-force | 2 |
| attack | impossible-travel | 2 |
| attack | mfa-bypass | 1 |

---

### Specialized Use Cases

#### `detection-engineering`

**Purpose:** High ratio of malicious events for detection rule testing.

```bash
secgen preset detection-engineering
```

Includes all attack patterns:
- brute-force, credential-stuffing
- malware-drop, registry-persistence, security-disable
- c2-beacon, dga-activity, dns-tunneling
- lateral-movement, data-exfiltration

---

#### `threat-hunting`

**Purpose:** Mixed benign and malicious data for threat hunting exercises.

**Time Spread:** 72 hours

```bash
secgen preset threat-hunting
```

Heavy baseline of normal activity (~2,200 events) with hidden malicious indicators (~60 events) - "needle in haystack" scenario.

---

#### `incident-response`

**Purpose:** Complete attack chain for IR training and tabletop exercises.

**Time Spread:** 48 hours

```bash
secgen preset incident-response
```

Simulates:
1. Pre-incident baseline
2. Initial compromise
3. Persistence establishment
4. Discovery phase
5. Credential access
6. Lateral movement
7. C2 and exfiltration
8. Post-incident risk assessment

---

#### `soc-training`

**Purpose:** Varied alerts and events for SOC analyst training.

```bash
secgen preset soc-training
```

Mixed event types and attack patterns with varying severity levels for triage practice.

---

## Creating Custom Presets

### YAML Schema

```yaml
name: my-custom-preset
description: Description of what this preset does

# World configuration
world:
  hosts: 20
  users: 40

# Time distribution
time_spread_hours: 24

# Whether to index by default
index: true

# Steps to execute
steps:
  - type: event
    name: dns
    count: 100
    params:
      is_malicious: false

  - type: attack
    name: brute-force
    count: 2
    params:
      success_at_end: true
```

### Step Types

#### `event` - Generate Event Type

```yaml
- type: event
  name: dns           # Event type name
  count: 100          # Number of events
  params:             # Optional parameters
    is_malicious: true
```

**Available event types:** `file`, `registry`, `endpoint-network`, `dns`, `http`, `tls`, `network-flow`, `authentication`, `iam`, `aws-cloudtrail`, `azure-audit`, `gcp-audit`, `threat-indicator`, `vulnerability`, `cspm`, `risk-score`

#### `attack` - Execute Attack Pattern

```yaml
- type: attack
  name: brute-force   # Attack pattern name
  count: 3            # Number of iterations
  params:             # Optional override parameters
    attempts: 100
```

**Available attack patterns:** `brute-force`, `credential-stuffing`, `impossible-travel`, `mfa-bypass`, `dga-activity`, `dns-tunneling`, `c2-beacon`, `c2-dns`, `data-exfiltration`, `lateral-movement`, `malware-drop`, `data-staging`, `registry-persistence`, `security-disable`

---

## Best Practices

### Naming Conventions

```
team-purpose-variant.yaml

Examples:
- qa-regression-full.yaml
- demo-customer-a.yaml
- training-soc-tier1.yaml
```

### Organization

```
presets/
├── demos/
│   ├── quick-demo.yaml
│   └── full-demo.yaml
├── training/
│   ├── soc-analyst.yaml
│   └── incident-responder.yaml
├── testing/
│   ├── load-test-10k.yaml
│   └── detection-coverage.yaml
└── customers/
    ├── acme-corp.yaml
    └── globex-inc.yaml
```

### Tips

1. **Start Small:** Use `quick-start` to verify setup before running large presets
2. **Use `--no-index` First:** Preview what will be generated before indexing
3. **Save for Analysis:** Use `--output` to save events for offline review
4. **Combine with World State:** Use `--world-file` to share entities across runs
