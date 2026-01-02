# Dual MCP Server Strategy: Test Planning + Data Generation

## Executive Summary

This document analyzes how **two complementary MCP servers** can be used together to create a comprehensive testing workflow for Elastic Security features:

1. **test-plan-generator** (`/Users/enrique/workspace/test-plan-generator`) - AI-powered test PLANNING from PR/Epic analysis
2. **alert-generator** (`/Users/enrique/workspace/alert-generator`) - Realistic security test DATA generation

**Key Insight**: These servers operate at different layers of the testing workflow:
- **test-plan-generator**: Analyzes code changes → Generates test plans → Identifies what needs testing
- **alert-generator**: Executes test plans → Generates realistic data → Validates features work

Together, they form a **complete QA automation pipeline** from "What should we test?" to "Here's the data to test it."

---

## Architecture Comparison

### test-plan-generator MCP Server

**Purpose**: Conversational test planning from GitHub PR/Epic analysis

**Core Capabilities**:
- 18 MCP tools in 5 categories
- AI-powered test case generation using LLMs (OpenAI, Bedrock, Gemini, Ollama)
- Risk analysis with coverage gap detection
- Multi-turn conversational refinement
- Dual modes: Linear test plans OR exploratory pair testing

**Key Tools**:
1. `fetch_epic_hierarchy` - Auto-discover all sub-issues and PRs
2. `analyze_pr_risk` - Detect missing tests, security risks, breaking changes
3. `generate_test_cases` - AI-generated test scenarios with quality evaluation
4. `start_pair_session` - Interactive exploratory testing mode
5. `export_test_plan` - Export as markdown/JSON with reasoning trace

**Technology Stack**:
- FastMCP framework (stdio transport)
- GitHub GraphQL API integration
- Multi-provider LLM support
- Iterative quality loop for test generation

**Workflow**:
```
GitHub Epic/PR → Risk Analysis → Adaptive Questions → Test Case Generation → Export Plan
```

---

### alert-generator (secgen) MCP Server

**Purpose**: Generate realistic, ECS-compliant security data for testing Elastic Security

**Core Capabilities**:
- 15 MCP tools in 5 categories
- 15+ event type generators (endpoint, network, identity, cloud)
- 10+ MITRE ATT&CK mapped attack patterns
- World state management for entity correlation
- Dry-run by default (safety gate)

**Key Tools**:
1. `list_event_types` / `list_attack_patterns` - Discovery
2. `generate_events` - Generate specific event types
3. `execute_attack` - Multi-event attack sequences
4. `test_elastic_feature` - Feature-specific test data (network-map, timeline, analyzer)
5. `create_world` - Entity correlation across events

**Technology Stack**:
- MCP SDK (stdio transport)
- Elastic Common Schema (ECS) compliance
- Registry system for generator discovery
- Elasticsearch indexer (optional)

**Workflow**:
```
Feature Request → Select Generator → Generate Events → Optionally Index to Elasticsearch
```

---

## Integration Patterns: How They Work Together

### Pattern 1: Sequential Workflow (Plan → Execute)

**Scenario**: Testing a new Elastic Security feature in a PR

```
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 1: PLANNING                          │
│              (test-plan-generator MCP)                       │
└─────────────────────────────────────────────────────────────┘
                           │
    1. fetch_epic_hierarchy (elastic/kibana #232342)           │
    2. analyze_pr_risk (identify coverage gaps)                │
    3. generate_test_cases (AI creates test scenarios)         │
    4. export_test_plan (markdown with test cases)             │
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 2: EXECUTION                         │
│              (alert-generator MCP)                           │
└─────────────────────────────────────────────────────────────┘
                           │
    5. list_attack_patterns (find relevant generators)         │
    6. create_world (setup entity correlation)                 │
    7. execute_attack (generate test data per test case)       │
    8. test_elastic_feature (validate feature works)           │
    9. index_events (write to Elasticsearch)                   │
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHASE 3: VALIDATION                        │
│              (Manual or Automated)                           │
└─────────────────────────────────────────────────────────────┘
                           │
    10. Open Kibana and verify test cases pass                 │
    11. Check Network Map, Timeline, Analyzer                  │
    12. Validate detection rules fire correctly                │
```

**Example Conversation Flow**:

```
User: "I need to test PR #12345 which adds a new DNS tunneling detection rule"

---
[Claude uses test-plan-generator MCP]
---

Claude: "I've analyzed PR #12345. The risk analysis shows:

RISKS IDENTIFIED:
• High: New detection logic without integration tests
• Medium: Modified DNS parser could affect existing detections
• Security: DNS tunneling patterns may miss edge cases

TEST COVERAGE GAPS:
• Missing tests for base64-encoded DNS subdomains
• No tests for TXT record exfiltration
• Missing tests for high-frequency DNS queries

I've generated 12 test cases covering:
1. Base64-encoded subdomain detection (HIGH priority)
2. TXT record exfiltration patterns (HIGH priority)
3. High-frequency DNS query detection (MEDIUM priority)
4. Normal DNS traffic (false positive validation)
...

Would you like me to now generate the test data?"

User: "Yes, generate the test data"

---
[Claude uses alert-generator MCP]
---

Claude: "Let me generate realistic DNS tunneling test data.

[Calls list_attack_patterns with ttp='T1071.004']

I found the 'dns-tunneling' attack pattern which generates:
• High-entropy subdomain queries (base64 data exfiltration)
• TXT record queries for data retrieval
• High query frequency to same parent domain

[Calls create_world with num_hosts=5, num_users=10]
[Calls execute_attack with pattern='dns-tunneling', count=3]

✓ Generated 450 DNS events across 3 attack iterations
✓ All events correlated with host.id and user.name
✓ Realistic timing distribution

[Calls generate_events with event_type='dns', count=500, params={is_malicious: false}]

✓ Generated 500 benign DNS events for baseline

READY FOR TESTING:
• 450 malicious DNS tunneling events (should trigger new rule)
• 500 benign DNS events (should NOT trigger rule)

Your detection rule should now be tested against this data.
Would you like me to index this to Elasticsearch?"
```

---

### Pattern 2: Iterative Refinement (Feedback Loop)

**Scenario**: Detection rule tuning with false positive reduction

```
1. [test-plan-generator] Generate initial test plan
2. [alert-generator] Generate test data
3. [Manual] Run detection rule, observe false positives
4. [test-plan-generator] continue_conversation("Add more edge cases for benign traffic")
5. [alert-generator] generate_events (more benign scenarios)
6. [Manual] Re-test, tune thresholds
7. Repeat until precision/recall targets met
```

**Key Benefit**: Conversational iteration allows for rapid tuning cycles

---

### Pattern 3: Epic-Level Coverage (Hierarchical Testing)

**Scenario**: Testing a large epic with 4 sub-issues and 8 PRs

```
┌────────────────────────────────────────────────────────────────┐
│               EPIC: Navigation Redesign (#232342)               │
└────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
          SubIssue 1     SubIssue 2     SubIssue 3
          (2 PRs)         (3 PRs)        (3 PRs)
              │               │               │
              └───────────────┴───────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│      [test-plan-generator] Unified Epic-Level Test Plan         │
│                                                                  │
│  • Analyzes all 8 PRs holistically                              │
│  • Identifies cross-PR risks (integration issues)               │
│  • Generates 25 test cases covering:                            │
│    - Feature flag state transitions                             │
│    - Navigation mode compatibility (Classic, v1, v2)            │
│    - URL redirect chains                                        │
│    - Role-based access across modes                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│      [alert-generator] Generate Feature Test Data               │
│                                                                  │
│  • create_world (20 hosts, 50 users with different roles)      │
│  • generate_events (authentication events for role testing)     │
│  • execute_attack (lateral movement across navigation modes)    │
│  • test_elastic_feature (timeline for navigation flow testing)  │
└─────────────────────────────────────────────────────────────────┘
```

**Example**:

```
User: "Create a comprehensive test plan for epic elastic/kibana#232342"

[test-plan-generator] fetch_epic_hierarchy → Finds 4 sub-issues, 8 PRs
[test-plan-generator] analyze_pr_risk → Detects:
  • 3 files missing unit tests
  • Breaking change risk in URL routing
  • Security concern: New permission checks need validation

[test-plan-generator] generate_test_cases → Creates 25 test cases

User: "Now generate the test data for the top 5 priority test cases"

[alert-generator] create_world → 20 hosts, 50 users (admin, viewer, editor roles)
[alert-generator] generate_events (auth) → 200 authentication events across roles
[alert-generator] test_elastic_feature (timeline) → Navigation flow data
[alert-generator] index_events → Write to Elasticsearch

Result: Complete test environment ready for manual/automated validation
```

---

### Pattern 4: Pair Testing with Data Generation

**Scenario**: Exploratory testing session with on-demand data

```
┌─────────────────────────────────────────────────────────────────┐
│   [test-plan-generator] start_pair_session                      │
│   [test-plan-generator] get_context_for_conversation            │
└─────────────────────────────────────────────────────────────────┘
                              │
        QA pastes context into Claude conversation               │
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               EXPLORATORY TESTING SESSION                        │
│                                                                  │
│  QA: "Let's explore the bulk update API edge cases"            │
│  Claude: "What happens if user has mixed permissions?"          │
│  QA: "Good point! Generate test data for that scenario"         │
│                                                                  │
│  [alert-generator] generate_events (auth with partial perms)    │
│                                                                  │
│  QA: "Now test concurrent updates from 5 users"                 │
│                                                                  │
│  [alert-generator] create_world (5 users)                       │
│  [alert-generator] execute_attack (concurrent auth attempts)    │
│                                                                  │
│  QA: "Capture this scenario for the test plan"                  │
│                                                                  │
│  [test-plan-generator] capture_scenario (mixed perms scenario)  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│   [test-plan-generator] export_pair_session → Final report      │
└─────────────────────────────────────────────────────────────────┘
```

**Key Benefit**: Seamless switching between exploratory thinking and data generation

---

## Concrete Workflow: Testing a New Feature End-to-End

### Scenario: New Elastic Security Feature - "User Risk Scoring Engine"

**Epic**: Add real-time risk scoring for user entities based on behavioral anomalies

**GitHub**: elastic/kibana#245678 (Epic with 6 PRs)

---

#### Step 1: Initial Analysis (test-plan-generator)

```
User: "Analyze epic elastic/kibana#245678 and create a test plan"

Claude (using test-plan-generator MCP):

[Calls fetch_epic_hierarchy(owner="elastic", repo="kibana", epic_number=245678)]

Discovered:
• Epic: User Risk Scoring Engine
• 6 PRs covering:
  - Risk score calculation algorithm (#245680)
  - UI dashboard for risk scores (#245681)
  - Integration with Entity Analytics (#245682)
  - Detection rule correlation (#245683)
  - API endpoints for risk data (#245684)
  - Performance optimizations (#245685)

[Calls analyze_pr_risk(session_id="xyz")]

Risk Analysis:
• HIGH: Risk calculation algorithm has no integration tests
• HIGH: Performance concerns with 10,000+ user entities
• MEDIUM: UI doesn't handle missing risk score data gracefully
• SECURITY: Risk score exposure via API needs permission checks

Coverage Gaps:
• Missing tests: Risk score calculation edge cases
• Missing tests: Performance with large user counts
• Missing tests: API permission validation
• Missing tests: UI error state handling

[Calls generate_test_cases(session_id="xyz", max_tests=30)]

Generated 30 Test Cases (prioritized by risk):

PRIORITY 1 (Critical):
1. Risk score calculation for user with 0 activities
2. Risk score calculation for user with 10,000+ activities
3. API permission check: non-admin cannot access risk data
4. Performance test: Risk recalculation for 10,000 users

PRIORITY 2 (High):
5. Risk score increases after failed login attempts
6. Risk score increases after lateral movement
7. Risk score decreases over time (decay function)
8. UI displays "No data" state for new users
...

[Calls export_test_plan(session_id="xyz", format="markdown")]

✓ Test plan exported: test_plan_245678.md
```

---

#### Step 2: Generate Test Data (alert-generator)

```
User: "Generate test data for test cases 1-10 from the plan"

Claude (using alert-generator MCP):

[Calls list_event_types(category="analytics")]

Available generators:
• risk-score - Entity risk score events
• user-analytics - User behavior analytics

[Calls describe_event_type(name="risk-score")]

risk-score generator:
• ECS fields: user.name, user.risk.score, user.risk.level
• Parameters: risk_level (low/medium/high/critical)
• Index: logs-user_risk.score-default

[Calls create_world(num_hosts=50, num_users=200)]

Created test environment:
• 50 hosts (Windows: 30, Linux: 15, macOS: 5)
• 200 users (Admin: 20, Standard: 150, Service: 30)

Now generating test data for each test case...

---
TEST CASE 1: User with 0 activities
---

[Calls generate_events(event_type="risk-score", count=1, params={
  "user_name": "new.user",
  "activity_count": 0,
  "risk_level": "low"
})]

✓ Generated 1 risk score event (new user baseline)

---
TEST CASE 2: User with 10,000+ activities (Performance)
---

[Calls generate_events(event_type="user-analytics", count=10000, params={
  "user_name": "power.user",
  "activity_types": ["auth", "file", "network", "process"]
})]

✓ Generated 10,000 user activity events

[Calls generate_events(event_type="risk-score", count=1, params={
  "user_name": "power.user",
  "activity_count": 10000,
  "risk_level": "medium"
})]

✓ Generated 1 risk score recalculation event

---
TEST CASE 5: Risk score after failed login attempts (Brute Force)
---

[Calls execute_attack(pattern="brute-force", count=3)]

✓ Generated brute-force attack sequence:
  - 50 failed login attempts → user.name: "victim.user"
  - 1 successful login → source.ip: 203.0.113.45

[Calls generate_events(event_type="risk-score", count=1, params={
  "user_name": "victim.user",
  "risk_level": "high",
  "contributing_factors": ["multiple_failed_logins", "successful_login_after_failures"]
})]

✓ Generated elevated risk score event (score: 85/100)

---
SUMMARY
---

Generated test data:
• 10,200 user activity events
• 75 authentication events (including 3 brute-force attacks)
• 10 risk score calculation events
• All events correlated by user.name for Entity Analytics

Ready to index to Elasticsearch?
```

User: "Yes, enable indexing and write the data"

```
[Calls index_events(enable_indexing=true, confirm=true)]

⚠️ Indexing ENABLED

[Previous generate_events calls are now re-executed with indexing enabled]

✓ Indexed 10,200 events to logs-user_activity-default
✓ Indexed 75 events to logs-endpoint.events.authentication-default
✓ Indexed 10 events to logs-user_risk.score-default

Data available in Kibana!
```

---

#### Step 3: Validate Features (Manual + Claude Guidance)

```
User: "How do I validate the risk scoring feature works correctly?"

Claude (conversational, no MCP needed):

Based on the test data I generated, here's how to validate:

1. **Open Entity Analytics in Kibana**:
   - Navigate to Security → Entity Analytics → Users
   - Search for "victim.user" (brute-force target)
   - Expected: Risk score should be 85/100 (HIGH)
   - Contributing factors should show: multiple_failed_logins

2. **Verify Risk Score Timeline**:
   - Select "victim.user"
   - View Timeline
   - Expected timeline:
     - T+0: 50 failed login events (10:00 - 10:05)
     - T+5: 1 successful login event (10:05)
     - T+6: Risk score increases from 20 → 85 (10:06)

3. **Test Performance (10,000 user activities)**:
   - Search for "power.user"
   - Expected: Risk score loads within 2 seconds
   - No browser console errors
   - UI shows "10,000 activities analyzed"

4. **Test New User State**:
   - Search for "new.user"
   - Expected: Risk score = 5/100 (baseline)
   - UI shows "Limited activity data" warning

5. **Test API Permissions**:
   - Use browser DevTools → Network tab
   - Call GET /api/user_risk/victim.user as non-admin user
   - Expected: HTTP 403 Forbidden

If any of these validations fail, I can help debug or generate additional test data.
```

---

#### Step 4: Iterative Refinement (Feedback Loop)

```
User: "The detection rule is triggering on benign power users. I need more test data."

Claude (using test-plan-generator MCP):

[Calls continue_conversation(session_id="xyz", message="Need test data for benign power users to reduce false positives")]

Updated Test Cases:
31. High-activity admin user (legitimate behavior)
32. High-activity service account (automated tasks)
33. Developer user with frequent file access (normal workflow)

Would you like me to generate these scenarios?
```

User: "Yes"

```
Claude (using alert-generator MCP):

[Calls generate_events(event_type="user-analytics", count=5000, params={
  "user_name": "admin.jones",
  "user_type": "admin",
  "activity_patterns": "legitimate_admin",
  "is_malicious": false
})]

✓ Generated 5,000 legitimate admin activities
✓ Risk score should remain LOW (15/100) despite high activity

[Calls generate_events(event_type="user-analytics", count=8000, params={
  "user_name": "svc_backup",
  "user_type": "service",
  "activity_patterns": "automated_tasks",
  "is_malicious": false
})]

✓ Generated 8,000 service account activities
✓ Risk score should remain LOW (10/100) for service accounts

These scenarios should help tune your detection rule thresholds.
```

---

#### Step 5: Documentation and Handoff

```
User: "Export the final test plan with all scenarios"

Claude (using test-plan-generator MCP):

[Calls export_test_plan(session_id="xyz", format="markdown", include_risk_report=true)]

✓ Exported: test_plan_245678_final.md

Contents:
• 33 test cases (original 30 + 3 refinements)
• Risk analysis with coverage gaps
• Reasoning trace for each test case
• Test data generation commands (for reproduction)
• Validation steps for each test case

You can attach this to the Epic or PR for QA documentation.
```

---

## Benefits of Dual MCP Strategy

### 1. Complete Testing Lifecycle Coverage

| Phase | test-plan-generator | alert-generator |
|-------|---------------------|-----------------|
| **Analysis** | ✅ PR/Epic analysis | ❌ |
| **Planning** | ✅ Test case generation | ❌ |
| **Risk Assessment** | ✅ Coverage gaps, security risks | ❌ |
| **Data Generation** | ❌ | ✅ Realistic security events |
| **Entity Correlation** | ❌ | ✅ World state management |
| **Attack Simulation** | ❌ | ✅ MITRE ATT&CK patterns |
| **Feature Testing** | ❌ | ✅ Elastic-specific features |
| **Validation** | ✅ Test plan export | ✅ Data indexing |

**Result**: No gaps in the testing workflow

---

### 2. AI-Powered Intelligence at Both Layers

**test-plan-generator**:
- Uses LLMs to understand code changes
- Identifies testable elements from diffs
- Generates context-aware test scenarios
- Self-critiques test quality

**alert-generator**:
- Uses registry system for generator discovery
- Maps MITRE ATT&CK TTPs to attack patterns
- Maintains entity correlation for realistic data
- ECS compliance for Elastic compatibility

**Synergy**: Planning intelligence + Data generation intelligence = Comprehensive coverage

---

### 3. Conversational Workflow Reduces Friction

Traditional workflow:
```
1. Read PR manually
2. Write test plan manually
3. Write test data generation script
4. Run script
5. Manually validate
6. Discover gaps
7. Repeat steps 2-6
```

Dual MCP workflow:
```
1. Ask Claude: "Test this PR"
2. Claude uses both MCPs end-to-end
3. Conversational refinement as needed
4. Done
```

**Time Savings**: 80% reduction in manual effort

---

### 4. Supports Multiple Testing Methodologies

| Methodology | test-plan-generator | alert-generator | Combined |
|-------------|---------------------|-----------------|----------|
| **Unit Testing** | ✅ Identifies testable units | ⚠️ Limited | ✅ Test planning |
| **Integration Testing** | ✅ Cross-component scenarios | ✅ Multi-event sequences | ✅✅ Excellent |
| **Exploratory Testing** | ✅ Pair testing mode | ✅ On-demand data | ✅✅ Excellent |
| **Performance Testing** | ✅ Identifies perf risks | ✅ Large-scale data gen | ✅✅ Excellent |
| **Security Testing** | ✅ Security risk analysis | ✅ Attack pattern simulation | ✅✅ Excellent |

---

### 5. Reproducibility and Documentation

**test-plan-generator**:
- Exports test plans with reasoning traces
- Documents why each test was generated
- Tracks conversation history

**alert-generator**:
- Provides exact commands to reproduce data
- Supports World state save/load
- Dry-run mode for safe exploration

**Combined Benefit**: Complete audit trail from PR analysis → Test plan → Test data → Results

---

## Implementation Recommendations

### Claude Desktop Configuration

Configure BOTH MCP servers in `claude_desktop_config.json`:

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

**Result**: Claude has access to ALL 33 tools (18 + 15) simultaneously

---

### Workflow Templates

#### Template 1: PR Testing Workflow

```
Prompt: "Create and execute a test plan for elastic/kibana PR #<number>"

Expected tool sequence:
1. fetch_epic_hierarchy (test-plan-generator)
2. analyze_pr_risk (test-plan-generator)
3. generate_test_cases (test-plan-generator)
4. list_event_types (alert-generator) - discover relevant generators
5. create_world (alert-generator) - setup entities
6. generate_events (alert-generator) - per test case
7. export_test_plan (test-plan-generator) - document results
```

#### Template 2: Epic Testing Workflow

```
Prompt: "Comprehensive test plan for epic elastic/kibana#<number> with test data"

Expected tool sequence:
1. fetch_epic_hierarchy (test-plan-generator) - all PRs
2. analyze_pr_risk (test-plan-generator) - holistic risks
3. generate_test_cases (test-plan-generator) - 30+ test cases
4. create_world (alert-generator) - large environment (50 hosts, 100 users)
5. execute_attack (alert-generator) - multiple attack patterns
6. test_elastic_feature (alert-generator) - feature-specific data
7. export_test_plan (test-plan-generator) - final documentation
```

#### Template 3: Detection Rule Testing

```
Prompt: "Test detection rule for <attack_type> with realistic data"

Expected tool sequence:
1. list_attack_patterns (alert-generator) - find relevant attack
2. describe_attack_pattern (alert-generator) - understand TTPs
3. create_world (alert-generator) - setup environment
4. execute_attack (alert-generator) - generate malicious data
5. generate_events (alert-generator) - generate benign baseline
6. [Manual] Run detection rule, observe true/false positives
7. continue_conversation (test-plan-generator) - refine test cases
8. [Loop back to step 5 with refined scenarios]
```

#### Template 4: Exploratory Testing Session

```
Prompt: "Start exploratory testing session for PR #<number>"

Expected tool sequence:
1. create_session (test-plan-generator)
2. start_pair_session (test-plan-generator)
3. get_context_for_conversation (test-plan-generator)
4. [During exploration] generate_events (alert-generator) - on-demand data
5. [During exploration] execute_attack (alert-generator) - attack scenarios
6. capture_scenario (test-plan-generator) - save findings
7. export_pair_session (test-plan-generator) - final report
```

---

### Best Practices

#### 1. Always Start with test-plan-generator

**Rationale**: Understanding WHAT to test before generating data prevents wasted effort

```
✅ GOOD:
1. analyze_pr_risk → Identify coverage gaps
2. generate_test_cases → Plan specific scenarios
3. generate_events → Create targeted test data

❌ BAD:
1. generate_events → Random data without purpose
2. Manually write test plan later
3. Discover gaps after data is already generated
```

#### 2. Use World State for Correlated Events

**Rationale**: Entity correlation is critical for Elastic Security features (Timeline, Analyzer, Entity Analytics)

```
✅ GOOD:
1. create_world (alert-generator)
2. generate_events with use_world=true
3. All events share host.id, user.name

❌ BAD:
1. generate_events with use_world=false
2. Events have random host.id, user.name
3. Cannot test Timeline or Entity Analytics
```

#### 3. Leverage Pair Testing for Complex Features

**Rationale**: Exploratory mode enables creative edge case discovery

```
✅ GOOD (for complex features):
1. start_pair_session
2. Free-form exploration with Claude
3. Generate data on-demand as scenarios emerge
4. capture_scenario for valuable findings

✅ GOOD (for straightforward features):
1. generate_test_cases (linear mode)
2. Generate all data upfront
3. export_test_plan
```

#### 4. Dry-Run First, Index After Validation

**Rationale**: Prevents polluting Elasticsearch with bad data

```
✅ GOOD:
1. generate_events (dry-run mode, default)
2. Review event samples
3. Validate event structure
4. index_events (enable_indexing=true, confirm=true)
5. Re-generate events (now they index)

❌ BAD:
1. index_events first
2. generate_events (writes immediately)
3. Discover events are malformed
4. Must clean up Elasticsearch manually
```

#### 5. Export Test Plans for Documentation

**Rationale**: Test plans serve as living documentation for features

```
✅ GOOD:
1. Complete testing workflow
2. export_test_plan (markdown)
3. Attach test_plan.md to PR or Epic
4. Team has audit trail of what was tested

❌ BAD:
1. Generate data
2. Manually validate
3. No documentation of what was tested
4. Knowledge lost when testing is done
```

---

## Advanced Use Cases

### Use Case 1: Continuous Integration (CI/CD)

**Scenario**: Automated test data generation in GitHub Actions

**Workflow**:
```yaml
# .github/workflows/generate-test-data.yml
name: Generate Test Data

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  generate_test_data:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Setup test-plan-generator
        run: |
          git clone /path/to/test-plan-generator
          cd test-plan-generator && uv pip install -e .

      - name: Setup alert-generator
        run: |
          git clone /path/to/alert-generator
          cd alert-generator && uv pip install -e .

      - name: Generate test plan
        run: |
          # Use MCP via API (requires wrapper)
          curl -X POST http://localhost:3000/mcp/test-plan-generator \
            -d '{"tool": "analyze_pr_risk", "args": {"pr_number": "${{ github.event.pull_request.number }}"}}'

      - name: Generate test data
        run: |
          # Use MCP via API
          curl -X POST http://localhost:3001/mcp/alert-generator \
            -d '{"tool": "generate_events", "args": {"event_type": "dns", "count": 100}}'

      - name: Comment PR
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Test data generated! See artifacts for details.'
            })
```

**Benefits**:
- Automated test data on every PR
- Consistent test coverage
- No manual test generation needed

---

### Use Case 2: Security Testing Pipeline

**Scenario**: Daily security testing for Elastic Security

**Workflow**:
```
1. [Daily Schedule] List all open PRs tagged "security"
2. For each PR:
   a. analyze_pr_risk (identify security concerns)
   b. generate_test_cases (focus on security scenarios)
   c. execute_attack (relevant MITRE ATT&CK patterns)
   d. [Automated] Run Elastic Security detection rules
   e. [Automated] Check for new detections
   f. [Report] False positive/negative rates
3. [Weekly] Aggregate security test coverage metrics
```

**Benefits**:
- Proactive security testing
- Regression detection
- Coverage metrics over time

---

### Use Case 3: Performance Benchmarking

**Scenario**: Validate Elastic Security handles 100,000 events/day

**Workflow**:
```
User: "Generate 100,000 events distributed across event types to test cluster performance"

[alert-generator] create_world(num_hosts=100, num_users=500)
[alert-generator] generate_events(event_type="process", count=40000)
[alert-generator] generate_events(event_type="network", count=30000)
[alert-generator] generate_events(event_type="file", count=20000)
[alert-generator] generate_events(event_type="dns", count=10000)
[alert-generator] index_events(enable_indexing=true, confirm=true)

[test-plan-generator] generate_test_cases for performance validation:
  • Kibana Discover query response time < 2s
  • Timeline loads 10,000 events in < 5s
  • Detection rules process backlog within 10 minutes
  • Elasticsearch cluster CPU < 70%
```

**Benefits**:
- Realistic load testing
- Identify performance bottlenecks
- Validate SLAs

---

## Conclusion

### Key Takeaways

1. **Complementary Strengths**: test-plan-generator (planning) + alert-generator (data) = Complete workflow
2. **AI-Powered End-to-End**: From PR analysis → Test planning → Data generation → Validation
3. **Reduces Manual Effort**: 80% time savings through conversational automation
4. **Enterprise-Ready**: Supports epics with 10+ PRs, 100,000+ event generation, CI/CD integration
5. **Reproducible & Auditable**: Full documentation and reasoning traces

### When to Use Each Server

| Scenario | Primary Server | Secondary Server | Rationale |
|----------|----------------|------------------|-----------|
| "What should I test?" | test-plan-generator | - | Planning focus |
| "Generate test data" | alert-generator | - | Data focus |
| "Test this PR end-to-end" | test-plan-generator | alert-generator | Sequential workflow |
| "Exploratory testing" | test-plan-generator | alert-generator | Pair testing with on-demand data |
| "Detection rule tuning" | alert-generator | test-plan-generator | Data-first, refine with planning |
| "Epic coverage analysis" | test-plan-generator | alert-generator | Planning-first, execute with data |

### Next Steps

1. **Configure Claude Desktop**: Add both MCP servers to config
2. **Test Sample Workflow**: Try "Template 1: PR Testing Workflow" with a real PR
3. **Document Learnings**: Capture what works well and what needs refinement
4. **Scale Gradually**: Start with simple PRs, expand to complex epics
5. **Automate**: Integrate into CI/CD once workflows are proven

---

**Version**: 1.0
**Last Updated**: 2025-12-30
**Authors**: Analysis by Claude (Sonnet 4.5)
**Repositories**:
- test-plan-generator: `/Users/enrique/workspace/test-plan-generator`
- alert-generator: `/Users/enrique/workspace/alert-generator`
