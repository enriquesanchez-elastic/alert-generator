# Quick Reference: Dual MCP Testing Workflows

## 🎯 Quick Decision Matrix

**Ask yourself**: *What's my goal?*

| Goal | Start With | Then Use | Example Prompt |
|------|------------|----------|----------------|
| Understand what to test | test-plan-generator | alert-generator | "Analyze PR #123 and create a test plan with data" |
| Generate security test data | alert-generator | - | "Generate DNS tunneling attack data" |
| Test detection rule | alert-generator | test-plan-generator | "Test my brute-force detection rule" |
| Comprehensive epic testing | test-plan-generator | alert-generator | "Test epic #456 end-to-end" |
| Exploratory testing | test-plan-generator | alert-generator | "Start exploratory session for PR #789" |

---

## 🚀 Common Workflows (Copy & Paste)

### Workflow 1: Test a Single PR

```
Prompt: "Analyze elastic/kibana PR #<NUMBER> and generate test data for the top 5 priority test cases"

Expected Flow:
1. [test-plan-generator] analyze_pr_risk
2. [test-plan-generator] generate_test_cases
3. [alert-generator] create_world
4. [alert-generator] generate_events (per test case)
5. [alert-generator] index_events (if ready)
```

**Copy this prompt**:
```
Create a comprehensive test plan for elastic/kibana PR #12345, focusing on security risks and coverage gaps. Then generate test data for the top 5 highest priority test cases.
```

---

### Workflow 2: Test an Entire Epic

```
Prompt: "Test epic elastic/kibana#<NUMBER> with all PRs"

Expected Flow:
1. [test-plan-generator] fetch_epic_hierarchy
2. [test-plan-generator] analyze_pr_risk (all PRs)
3. [test-plan-generator] generate_test_cases
4. [alert-generator] create_world (large environment)
5. [alert-generator] execute_attack (multiple patterns)
6. [test-plan-generator] export_test_plan
```

**Copy this prompt**:
```
Fetch the complete hierarchy for elastic/kibana epic #232342, analyze all PRs for risks and coverage gaps, generate a comprehensive test plan, and create realistic test data covering all major scenarios.
```

---

### Workflow 3: Detection Rule Testing

```
Prompt: "Test detection rule for <ATTACK_TYPE>"

Expected Flow:
1. [alert-generator] list_attack_patterns (find relevant)
2. [alert-generator] describe_attack_pattern
3. [alert-generator] execute_attack (malicious data)
4. [alert-generator] generate_events (benign baseline)
5. [Manual] Validate true/false positives
6. [test-plan-generator] continue_conversation (refine)
```

**Copy this prompt**:
```
I have a detection rule for DNS tunneling. Generate realistic test data including both malicious DNS tunneling patterns and benign DNS traffic to test for false positives. Use 3 attack iterations and 500 benign events.
```

---

### Workflow 4: Exploratory Testing

```
Prompt: "Start exploratory testing for PR #<NUMBER>"

Expected Flow:
1. [test-plan-generator] create_session
2. [test-plan-generator] start_pair_session
3. [Free exploration with on-demand data generation]
4. [alert-generator] generate_events (as needed)
5. [test-plan-generator] capture_scenario (findings)
6. [test-plan-generator] export_pair_session
```

**Copy this prompt**:
```
Start an exploratory pair testing session for elastic/kibana PR #12345. I want to interactively explore edge cases and generate test data on-demand as we discover scenarios.
```

---

### Workflow 5: Performance Testing

```
Prompt: "Test performance with <N> events"

Expected Flow:
1. [alert-generator] create_world (large scale)
2. [alert-generator] generate_events (high volume)
3. [alert-generator] index_events
4. [test-plan-generator] generate_test_cases (perf validation)
5. [Manual] Validate query times, CPU, memory
```

**Copy this prompt**:
```
Generate 100,000 security events distributed across endpoint, network, and identity event types to test Elasticsearch cluster performance. Create a World with 100 hosts and 500 users for realistic entity correlation.
```

---

## 🎨 MCP Tool Cheat Sheet

### test-plan-generator Tools (18 total)

#### Discovery & Analysis (Core)
```
fetch_epic_hierarchy(owner, repo, epic_number)
  → Auto-discover all sub-issues and PRs in an epic

analyze_pr_risk(session_id)
  → Identify security risks, coverage gaps, breaking changes

analyze_and_ask(session_id)
  → Generate adaptive clarifying questions
```

#### Test Generation (Core)
```
create_session(repo, epic, sub_issues, prs)
  → Initialize test planning session

generate_test_cases(session_id, max_tests=30)
  → AI-powered test case generation with quality evaluation

refine_test_case(session_id, test_case_id, action)
  → Modify or remove specific test cases
```

#### Conversational (Core)
```
continue_conversation(session_id, message)
  → Multi-turn dialogue for refinement

interactive_refine(session_id, feedback, target)
  → Apply feedback (target: "all", "coverage", "quality")

get_reasoning(session_id)
  → Get full reasoning trace
```

#### Pair Testing (Advanced)
```
start_pair_session(session_id)
  → Convert to exploratory testing mode

get_context_for_conversation(session_id)
  → Get rich context block for Claude chat

capture_scenario(session_id, scenario)
  → Save discovered test scenarios

get_exploration_status(session_id)
  → Check exploration coverage

get_challenge_suggestions(session_id, area)
  → AI-generated edge cases
```

#### Export
```
export_test_plan(session_id, format, include_risk_report)
  → Export as markdown/JSON with reasoning
```

---

### alert-generator Tools (15 total)

#### Discovery (Core)
```
list_event_types(category?)
  → List all available generators (15+ types)

list_attack_patterns(category?, ttp?)
  → List attack patterns with MITRE TTPs

describe_event_type(name)
  → Get ECS fields, parameters, examples

describe_attack_pattern(name)
  → Get TTPs, detection recommendations
```

#### Generation (Core)
```
generate_events(event_type, count=10, use_world=true, params?)
  → Generate specific event types

execute_attack(pattern, count=1, use_world=true)
  → Multi-event attack sequences (brute-force, c2-beacon, etc.)

generate_campaign(num_hosts=5, num_alerts=20, attack_speed, time_spread)
  → Coordinated attack campaign with phases
```

#### World State (Core)
```
create_world(num_hosts=10, num_users=20, reset=false)
  → Setup entity correlation environment

get_world_info()
  → Get summary (hosts by OS, users by type)

save_world(file_path)
  → Persist World to JSON

load_world(file_path)
  → Restore World from JSON
```

#### Testing (Core)
```
test_elastic_feature(feature, count?)
  → Feature-specific data (network-map, timeline, analyzer, etc.)
```

#### Utility
```
validate_elasticsearch()
  → Check ES connection (read-only)

get_capabilities()
  → Get server capabilities

index_events(enable_indexing=true, confirm=true)
  → Enable ES indexing (safety gate)
```

---

## 🔧 Configuration Templates

### Claude Desktop Config (Both Servers)

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "test-plan-generator": {
      "command": "/Users/enrique/workspace/test-plan-generator/run_mcp_server.sh",
      "env": {
        "OPENAI_API_KEY": "sk-...",
        "GITHUB_TOKEN": "ghp_..."
      }
    },
    "alert-generator": {
      "command": "/Users/enrique/workspace/alert-generator/run_mcp.sh",
      "env": {
        "ELASTIC_URL": "localhost:9200",
        "ELASTIC_USERNAME": "elastic",
        "ELASTIC_PASSWORD": "changeme"
      }
    }
  }
}
```

**After editing**: Restart Claude Desktop

---

## 💡 Pro Tips

### Tip 1: Always Plan Before Generating Data
```
❌ BAD:  "Generate 1000 DNS events"
✅ GOOD: "Analyze PR #123, then generate test data for the identified risks"
```

**Why**: Planning ensures data is targeted and useful, not just random.

---

### Tip 2: Use World State for Correlation
```
❌ BAD:  generate_events(use_world=false)
✅ GOOD: create_world() → generate_events(use_world=true)
```

**Why**: Entity correlation (host.id, user.name) is critical for Timeline, Analyzer, Entity Analytics.

---

### Tip 3: Dry-Run First, Index Later
```
❌ BAD:  index_events() → generate_events()
✅ GOOD: generate_events() → [review] → index_events() → [re-generate]
```

**Why**: Prevents polluting Elasticsearch with bad data.

---

### Tip 4: Export Test Plans for Documentation
```
✅ ALWAYS: export_test_plan() after completing testing
```

**Why**: Creates audit trail and living documentation.

---

### Tip 5: Use Pair Testing for Complex Features
```
For simple features: generate_test_cases (linear mode)
For complex features: start_pair_session (exploratory mode)
```

**Why**: Exploratory mode enables creative edge case discovery.

---

## 🎯 Tool Selection Guide

### "Which server should I use?"

```
┌─────────────────────────────────────────────────────────────┐
│                  DECISION TREE                               │
└─────────────────────────────────────────────────────────────┘

Question: "Do I know WHAT to test?"

    ├─ NO → Use test-plan-generator first
    │        ├─ analyze_pr_risk
    │        ├─ generate_test_cases
    │        └─ Then use alert-generator for data
    │
    └─ YES → Use alert-generator directly
             ├─ create_world
             ├─ generate_events / execute_attack
             └─ Optionally use test-plan-generator to document

Question: "Do I need entity correlation?"

    ├─ YES → Always use create_world in alert-generator
    │        └─ Set use_world=true for all generation
    │
    └─ NO → Use generate_events with use_world=false
            (Rare - most Elastic features need correlation)

Question: "Do I know the exact scenarios?"

    ├─ NO → Use pair testing mode
    │        ├─ start_pair_session
    │        └─ Exploratory discovery with on-demand data
    │
    └─ YES → Use linear test generation
             ├─ generate_test_cases
             └─ Generate all data upfront

Question: "Is this for production or exploration?"

    ├─ EXPLORATION → Keep dry_run=true (default)
    │                Review events before indexing
    │
    └─ PRODUCTION → index_events(enable_indexing=true, confirm=true)
                    Write to Elasticsearch cluster
```

---

## 📋 Common Event Types & Attack Patterns

### Event Types (alert-generator)

| Category | Event Types | Use Case |
|----------|-------------|----------|
| Endpoint | process, file, registry, endpoint-network | Host-based detection testing |
| Network | dns, http, tls, network-flow | Network detection testing |
| Identity | authentication, iam-audit | Auth testing, privilege escalation |
| Cloud | aws-cloudtrail, azure-signin, gcp-audit | Cloud security testing |
| Security | vulnerability-scan, cspm-finding | Vulnerability management |
| Analytics | risk-score, user-analytics | Entity Analytics testing |

### Attack Patterns (alert-generator)

| Pattern | MITRE TTPs | Events Generated | Use Case |
|---------|------------|------------------|----------|
| brute-force | T1110.001, T1110.003 | 50+ auth events (failures + success) | Test credential-based detections |
| c2-beacon | T1071.001 | Network events with beaconing pattern | Test C2 communications |
| dns-tunneling | T1071.004 | High-entropy DNS queries | Test DNS exfiltration |
| dga-activity | T1568.002 | DGA domain patterns | Test domain generation |
| lateral-movement | T1021.001, T1021.002 | RDP/SMB auth + process events | Test lateral movement |
| privilege-escalation | T1068, T1548 | Process events with priv changes | Test escalation detections |
| data-staging | T1074.001 | Large file operations | Test data exfiltration prep |
| credential-dumping | T1003.001 | LSASS access events | Test credential theft |

---

## 🐛 Troubleshooting

### Problem: "MCP server not appearing in Claude Desktop"

**Solution**:
1. Check config path: `~/Library/Application Support/Claude/claude_desktop_config.json`
2. Validate JSON syntax: `python -m json.tool <config_file>`
3. Restart Claude Desktop
4. Check logs: `~/Library/Logs/Claude/mcp-server-*.log`

---

### Problem: "Tool calls failing with 'Unknown tool'"

**Solution**:
1. Verify server is running: Check Claude Desktop status
2. Verify tool names: Use exact names from this guide (case-sensitive)
3. Check server logs for startup errors

---

### Problem: "Generated events missing correlation fields"

**Solution**:
```
# Always create World first:
create_world(num_hosts=10, num_users=20)

# Then use World in generation:
generate_events(..., use_world=true)  # Default is true
execute_attack(..., use_world=true)
```

---

### Problem: "Events not appearing in Elasticsearch"

**Solution**:
```
# Check dry-run mode (default is true):
1. validate_elasticsearch()  # Verify connection
2. index_events(enable_indexing=true, confirm=true)  # Enable indexing
3. Re-run generate_events()  # Events now write to ES
```

---

### Problem: "Test plan export missing reasoning"

**Solution**:
```
# Use get_reasoning before export:
get_reasoning(session_id)
export_test_plan(session_id, format="markdown")
```

---

## 📚 Additional Resources

- **Full Strategy Doc**: `docs/MCP_DUAL_SERVER_STRATEGY.md`
- **test-plan-generator**: `/Users/enrique/workspace/test-plan-generator`
- **alert-generator MCP Guide**: `docs/MCP_INTEGRATION.md`
- **MCP Specification**: https://modelcontextprotocol.io/

---

**Last Updated**: 2025-12-30
**Quick Tip**: Bookmark this page and use Cmd+F to search for workflows!
