# Enhanced Security Alerts Generator

This tool generates realistic, varied security alerts for testing Kibana Security Solution with support for correlated attack campaigns, flexible time distribution, and custom scenario configuration.

## Features

### 1. Configuration File Support

Load custom attack scenarios from YAML files without modifying code.

**Usage:**

```bash
python generate_multiple_alerts_cloud.py --count 20 --scenarios-file custom_scenarios.yaml
```

**Configuration Files:**

- `alert_scenarios.yaml` - Default scenarios (7 attack types)
- `example_custom_scenarios.yaml` - Template for creating custom scenarios

**Scenario Structure:**

```yaml
scenarios:
  - name: "Attack Name"
    description: "What the attack does"
    severity: "high"  # low, medium, high, critical
    processes:
      - name: "process1"
        executable: "/path/to/binary"
        args: ["arg1", "arg2"]
        working_dir: "/working/directory"
        user: "username"
      # ... more processes (2-5 recommended)
    malware_file:
      name: "filename"
      path: "/full/path"
      extension: ".ext"
```

### 2. Correlated Attack Campaigns

Generate multi-host attacks that appear to come from the same threat actor.

**Features:**

- Shared attacker IP address
- Common C2 (Command & Control) infrastructure
- Related file hashes (same malware family)
- Progressive attack phases
- Multiple targeted hosts

**Usage:**

```bash
# Generate a 50-alert campaign across 10 hosts
python generate_multiple_alerts_cloud.py --count 50 --campaign --campaign-hosts 10

# Slow-moving APT campaign
python generate_multiple_alerts_cloud.py --count 100 --campaign --campaign-hosts 15 --attack-speed slow

# Fast attack (minutes to hours)
python generate_multiple_alerts_cloud.py --count 30 --campaign --attack-speed fast
```

**Attack Phases:**
Campaigns follow a realistic attack progression:

1. **Initial Access** (10% of alerts)
   - Web shell deployment
   - Backdoor installation

2. **Execution** (30% of alerts)
   - Crypto miners
   - Ransomware
   - Privilege escalation

3. **Lateral Movement** (40% of alerts)
   - Credential theft
   - Remote execution
   - Additional privilege escalation

4. **Exfiltration** (20% of alerts)
   - Data theft
   - Ransomware encryption

**Attack Speed Options:**

- `fast`: Minutes to hours (initial: 50-60 min ago, exfil: 0-10 min ago)
- `medium`: Hours to half-day (initial: 8-12 hours ago, exfil: 0-1 hour ago) [default]
- `slow`: Days to weeks (initial: 7-14 days ago, exfil: 0-1 day ago)

**Campaign Output Example:**

```
Campaign ID: abc12345
Attacker IP: 203.0.113.42
C2 Server: evil-c2.badactor.com (198.51.100.15)
Malware Family: RedTeam-Ransomware
Affected Hosts: 5
  - web-server-01
  - db-prod-03
  - app-server-12
  - workstation-45
  - file-server-07
Time Span: 6.5 hours

Phase Distribution:
  initial         [████████          ] 5 alerts
  execution       [██████████████████] 15 alerts
  lateral         [████████████      ] 12 alerts
  exfiltration    [██████            ] 8 alerts
```

### 3. Time Distribution

Spread alerts realistically over time instead of generating all at once.

**Time Spread Options:**

```bash
# Last hour (default)
--time-spread minutes

# Last 24 hours
--time-spread hours

# Last 7 days
--time-spread days

# Last 30 days
--time-spread weeks
```

**Business Hours Weighting:**
Weight alerts toward business hours (8am-6pm) and weekdays:

```bash
python generate_multiple_alerts_cloud.py --count 100 --time-spread days --working-hours
```

This filters out:

- Weekend activity (moves to Friday)
- After-hours activity (moves to 8am-6pm)

**Examples:**

```bash
# Simulate a week of security events during business hours
python generate_multiple_alerts_cloud.py --count 200 --time-spread days --working-hours

# Month-long campaign
python generate_multiple_alerts_cloud.py --count 500 --time-spread weeks
```

## Complete Examples

### Basic Usage

```bash
# Generate 20 varied alerts
python generate_multiple_alerts_cloud.py --count 20

# Dry run (no indexing)
python generate_multiple_alerts_cloud.py --count 10 --dry-run

# Save to JSON file
python generate_multiple_alerts_cloud.py --count 50 --output alerts.json

# Delete all logs and alerts from Elasticsearch
python generate_multiple_alerts_cloud.py --delete-all
```

### Campaign Scenarios

```bash
# Ransomware outbreak across organization
python generate_multiple_alerts_cloud.py --count 100 --campaign --campaign-hosts 20 \
  --attack-speed fast --index-all

# Slow APT campaign over weeks
python generate_multiple_alerts_cloud.py --count 200 --campaign --campaign-hosts 10 \
  --attack-speed slow --time-spread weeks --working-hours

# Crypto mining infection
python generate_multiple_alerts_cloud.py --count 50 --campaign --campaign-hosts 30 \
  --attack-speed medium --time-spread days
```

### Custom Scenarios

```bash
# Use custom attack scenarios
python generate_multiple_alerts_cloud.py --count 25 --scenarios-file my_scenarios.yaml

# Custom scenarios with campaign
python generate_multiple_alerts_cloud.py --count 100 --scenarios-file apt_scenarios.yaml \
  --campaign --campaign-hosts 15 --attack-speed slow
```

### Testing & Development

```bash
# Quick test with 5 alerts
python generate_multiple_alerts_cloud.py --count 5 --dry-run

# Generate large dataset for performance testing
python generate_multiple_alerts_cloud.py --count 1000 --time-spread weeks --output large_dataset.json

# Realistic production simulation
python generate_multiple_alerts_cloud.py --count 500 --time-spread days --working-hours \
  --campaign --campaign-hosts 50 --attack-speed medium --index-all
```

## Command-Line Reference

### Required Arguments

- `--count N` - Number of alerts to generate (default: 10)

### Mode Options

- `--index-all` - Index immediately without preview
- `--dry-run` - Generate without indexing
- `--output FILE` - Save to JSON file
- `--delete-all` - Delete all data (logs and alerts) from Elasticsearch indices

### Configuration

- `--scenarios-file FILE` - Load scenarios from YAML

### Campaign Mode

- `--campaign` - Enable campaign mode
- `--campaign-hosts N` - Number of hosts (default: 5)
- `--attack-speed SPEED` - Speed: fast, medium, slow (default: medium)

### Time Distribution

- `--time-spread UNIT` - Time range: minutes, hours, days, weeks (default: minutes)
- `--working-hours` - Weight to business hours (8am-6pm)
- `--timezone TZ` - Timezone (default: UTC)

## Output

### Summary Statistics

```
📊 GENERATION SUMMARY
======================================================================

Scenario Distribution:
  Web Shell Deployment        :  15 alerts
  Ransomware                  :  20 alerts
  Lateral Movement            :  12 alerts
  Data Exfiltration           :   8 alerts

Severity Distribution:
  medium    :  15 alerts
  high      :  35 alerts
  critical  :  20 alerts

✅ Successfully indexed: 70/70 alerts
```

### Alert Details

Each alert includes:

- Detection rule alert (`.alerts-security.alerts-default`)
- Process events (2-5 processes per alert)
- Endpoint alert
- Full ECS field compliance

## Installation Requirements

**Required:**

```bash
pip install requests
```

**Optional (for YAML support):**

```bash
pip install pyyaml
```

Without PyYAML, the script uses hardcoded scenarios only.

## Data Generated

### Indices Used

- `.alerts-security.alerts-default` - Detection rule alerts
- `logs-endpoint.events.process-default` - Process events
- `logs-endpoint.alerts-default` - Endpoint alerts

### Data Management

**Delete All Data:**

```bash
python generate_multiple_alerts_cloud.py --delete-all
```

This command deletes all documents from:
- `.alerts-security.alerts-default` (Kibana security alerts)
- `logs-endpoint.events.process-*` (all process event indices)
- `logs-endpoint.alerts-*` (all endpoint alert indices)

The command provides a summary showing how many documents were deleted from each index pattern. Missing or empty indices are handled gracefully.

### Fields Populated

- All standard ECS fields
- Kibana alert fields (`kibana.alert.*`)
- Process hierarchies with entity IDs
- Session leader information
- File hashes and metadata
- Host information (IPs, MACs, hostnames)

## Tips & Best Practices

1. **Start Small**: Test with `--count 5 --dry-run` first
2. **Use Campaigns for Realism**: Mimics real attacker behavior
3. **Time Distribution**: Use `--working-hours` for realistic patterns
4. **Custom Scenarios**: Create scenarios matching your threat model
5. **Save to File**: Use `--output` to review before indexing
6. **Large Datasets**: For 1000+ alerts, consider running overnight
7. **Clean Slate**: Use `--delete-all` to clear all generated data before new test runs

## Troubleshooting

**PyYAML not available**

```
⚠️  PyYAML not available - using hardcoded scenarios only
```

Solution: `pip install pyyaml` or omit `--scenarios-file`

**Scenarios file not found**

```
❌ Scenarios file not found: my_file.yaml
```

Solution: Check file path, use absolute path if needed

**Failed to index**

```
❌ Failed to index alert: 401
```

Solution: Check ELASTIC_URL, USERNAME, PASSWORD in script

## Architecture

```
Campaign
  ├─ Shared Infrastructure
  │   ├─ Attacker IP
  │   ├─ C2 Domain/IP
  │   └─ Malware Family
  ├─ Target Hosts [N]
  └─ Attack Phases
      ├─ Initial Access (10%)
      ├─ Execution (30%)
      ├─ Lateral Movement (40%)
      └─ Exfiltration (20%)

Each Alert
  ├─ Detection Rule Alert (.alerts-security.alerts-default)
  ├─ Process Events (2-5) (logs-endpoint.events.process-default)
  │   └─ Process Hierarchy with Entity IDs
  └─ Endpoint Alert (logs-endpoint.alerts-default)
```

## Related Files

- `generate_multiple_alerts_cloud.py` - Main script
- `full_alert_example_cloud.py` - Single alert generator (original)
- `alert_scenarios.yaml` - Default scenarios configuration
- `example_custom_scenarios.yaml` - Custom scenario examples
