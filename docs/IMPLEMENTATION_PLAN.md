# SecGen UX & Data Generation Improvements - Implementation Plan

**Version**: 1.0
**Date**: December 2024
**Status**: Approved - Ready for Implementation
**Timeline**: 7 weeks across 6 phases

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Goals and Objectives](#goals-and-objectives)
4. [Phased Implementation Plan](#phased-implementation-plan)
5. [Critical Design Decisions](#critical-design-decisions)
6. [File Changes Overview](#file-changes-overview)
7. [Success Criteria](#success-criteria)
8. [Risk Mitigation](#risk-mitigation)
9. [Testing Strategy](#testing-strategy)
10. [Documentation Updates](#documentation-updates)

---

## Executive Summary

This plan addresses two major improvement areas for SecGen:

### 1. UX Enhancement
Transform the CLI from **generator-centric** to **feature-oriented**, enabling QA/developers to test Elastic Security features directly without writing Python code.

### 2. Data Generation Gaps
Add missing ECS-compliant data types identified from comprehensive Elastic Security Solution reference analysis:
- Vulnerability scan events (CVE/CVSS)
- Cloud Security Posture Management (CSPM) findings
- Entity Analytics enhancements (risk scores, asset criticality)
- Complete geo-enrichment for Network Map visualization

### Key Principles
- ✅ **Backward Compatibility**: All existing commands continue working
- ✅ **Incremental Delivery**: Each phase provides independent value
- ✅ **No New Dependencies**: Uses existing libraries only
- ✅ **QA-First Design**: Focused on real testing workflows

---

## Current State Analysis

### What Works Well ✅

**Strong Foundation**:
- **17 generators** with consistent patterns across endpoint, network, identity, cloud, threat intel
- **40+ attack patterns** exposed as methods (brute_force, c2_beacon, dga_activity, etc.)
- **World state management** for entity correlation (host.id, user.name, process.entity_id)
- **Extensible indexer** with multi-index routing ready for new event types
- **Geo-enrichment** exists in network flows with geo_point support for Network Map

**Architecture**:
- Duck-typed generator interface with consistent `generate()` methods
- Entity-first design with Host/User correlation
- ECS compliance across all event types
- Proper data stream and index routing

### Critical Gaps ❌

**UX Problems** (from QA/developer perspective):

| Problem | Impact | User Pain |
|---------|--------|-----------|
| No feature-oriented commands | Can't test Network Map easily | "How do I test Network Map?" |
| No direct event generation | Must write Python code | "How do I generate just DNS events?" |
| No attack pattern CLI | Complex Python imports required | "How do I test brute force detection?" |
| No discovery mechanism | Must read source code | "What attack patterns exist?" |
| Inconsistent output | Hard to parse results | "What indices were written to?" |

**Data Generation Gaps**:

| Data Type | Status | Impact |
|-----------|--------|--------|
| Vulnerability events | ❌ Missing | Can't test vulnerability management |
| CSPM findings | ❌ Missing | Can't test cloud security posture |
| Entity Analytics | ⚠️ Partial | Has entities but missing risk scores |
| Geo-enrichment | ⚠️ Partial | In flows but not in Host entities |

---

## Goals and Objectives

### Primary Goals

1. **Enable Feature Testing**: QA can test any Elastic Security feature with one command
2. **Simplify Event Generation**: Generate any event type via CLI without coding
3. **Complete Data Coverage**: Support all major Elastic Security data types
4. **Improve Discoverability**: Users can discover capabilities via CLI

### Success Metrics

- **Time to Test**: Reduce from 30 minutes (coding) to 30 seconds (one command)
- **Discovery**: 100% of generators discoverable via `list`/`describe`
- **Coverage**: Support 25+ ECS data types (currently 15)
- **Adoption**: QA team uses CLI for 80%+ of test data generation

---

## Phased Implementation Plan

### Phase 1: Foundation - Registry & Discovery (Week 1)

#### Goal
Build infrastructure for command discovery and generator registration that enables all future phases.

#### What Gets Built

**Core Registry System**:
- `secgen/registry.py` - Central registry with decorator-based registration
- Decorator: `@register_event_type(name, category, description, ecs_fields, ...)`
- Decorator: `@register_attack_pattern(name, ttps, description, ...)`
- Registry methods: `get_event_type()`, `list_event_types()`, `list_attack_patterns()`

**Bootstrap System**:
- `secgen/registry_bootstrap.py` - Import all generators to trigger decorators
- Lazy initialization (only runs when commands need it)
- Scan generator methods for attack pattern decorators

**Discovery Commands**:
```bash
# List all event types
secgen list event-types
secgen list event-types --filter network

# List attack patterns
secgen list attack-patterns
secgen list attack-patterns --ttp T1110

# List generators by category
secgen list generators

# Describe specific items
secgen describe event-type dns
secgen describe attack brute-force
```

#### Implementation Steps

1. **Create Registry Module** (`secgen/registry.py`):
   - Define `GeneratorCategory` enum
   - Create `EventTypeMetadata` and `AttackPatternMetadata` dataclasses
   - Implement `GeneratorRegistry` class with registration/lookup methods
   - Create decorator functions for registration

2. **Create Bootstrap Module** (`secgen/registry_bootstrap.py`):
   - Import all generator modules
   - Scan for attack pattern decorators on methods
   - Register all discovered patterns

3. **Create List Handler** (`secgen/cli/handlers/list_handler.py`):
   - Handle `list event-types` with category filtering
   - Handle `list attack-patterns` with TTP filtering
   - Handle `list generators` by category
   - Format output as tables

4. **Create Describe Handler** (`secgen/cli/handlers/describe_handler.py`):
   - Handle `describe event-type <name>`
   - Handle `describe attack <pattern>`
   - Show detailed metadata, examples, usage

5. **Update All Generators**:
   - Add `@register_event_type` decorator to 17 generator classes
   - Add `@register_attack_pattern` to ~40 attack methods
   - Include metadata: description, ECS fields, example params

6. **Update CLI** (`secgen/cli.py`):
   - Bootstrap registry at startup
   - Add routing for `list` and `describe` commands

#### Files Created (4)
- `secgen/registry.py`
- `secgen/registry_bootstrap.py`
- `secgen/cli/handlers/list_handler.py`
- `secgen/cli/handlers/describe_handler.py`

#### Files Modified (20)
- `secgen/cli.py` - Bootstrap and routing
- All 17 generator files - Add decorators
- All generator `__init__.py` files - Ensure exports

#### User Value
✅ Discover generators without reading code
✅ Find attack patterns by MITRE TTP
✅ Get usage examples for any event type
✅ Living documentation via CLI

#### Success Criteria
```bash
✅ secgen list event-types shows 17+ generators
✅ secgen list attack-patterns shows 40+ patterns
✅ secgen describe event-type dns shows ECS fields and examples
✅ secgen describe attack brute-force shows TTPs and description
```

---

### Phase 2: Direct Event Generation (Week 2)

#### Goal
Enable direct generation of specific event types via CLI with rich output formatting.

#### What Gets Built

**Output Formatter**:
- `secgen/output/formatter.py` - Consistent output across commands
- `GenerationSummary` - Event stats, correlation IDs, Kibana links
- `OutputFormatter` - Format tables, summaries, JSON
- No external dependencies (pure Python with ANSI codes)

**Generate Command**:
```bash
# Basic generation
secgen generate dns --count 50

# With parameters
secgen generate dns --count 50 --param query_type=A --param is_malicious=true

# With World state
secgen generate process --count 30 --use-world --world-file qa-world.json

# Output to file
secgen generate file --count 100 --output events.json

# Index to Elasticsearch
secgen generate network-flow --count 200 --index
```

**Rich Output**:
```
======================================================================
GENERATION SUMMARY
======================================================================
Command: secgen generate dns
Duration: 2.35s

Events Generated:
  Total: 50
    dns.query: 50

Time Range:
  Start: 2024-12-26T10:00:00Z
  End:   2024-12-26T10:05:00Z

Correlation IDs:
  host.id: 3 unique
    - host-abc123
    - host-def456
    - host-ghi789
  user.name: 5 unique

Indexed to Elasticsearch:
  - logs-dns.query-default

Kibana Queries:
  All events: host.id:(host-abc123 OR host-def456 OR host-ghi789)
  Timeline: http://localhost:5601/app/security/timelines

======================================================================
```

#### Implementation Steps

1. **Create Output Formatter** (`secgen/output/formatter.py`):
   - `EventStats` dataclass for statistics
   - `GenerationSummary` dataclass for complete summary
   - `OutputFormatter` class with formatting methods
   - `format_summary()`, `format_table()`, `build_kibana_discover_link()`

2. **Create Generate Handler** (`secgen/cli/handlers/generate_handler.py`):
   - Parse event type from args
   - Look up generator in registry
   - Parse `--param key=value` arguments
   - Generate events with World state if requested
   - Collect statistics
   - Format and display summary
   - Index if requested

3. **Move Legacy Logic** (`secgen/cli/handlers/generate_legacy.py`):
   - Move existing campaign generation logic
   - Keep backward compatibility

4. **Update CLI** (`secgen/cli.py`):
   - Route `generate <event-type>` to new handler
   - Route `generate --campaign` to legacy handler

#### Files Created (3)
- `secgen/output/formatter.py`
- `secgen/cli/handlers/generate_handler.py`
- `secgen/cli/handlers/generate_legacy.py`

#### Files Modified (3)
- `secgen/cli.py` - Routing logic
- `secgen/cli/commands.py` - Update generate command args
- `secgen/config/settings.py` - Add `kibana_url` setting

#### User Value
✅ Generate any event type without Python coding
✅ See correlation IDs for Timeline/Analyzer
✅ Get Kibana queries to find generated data
✅ Parameter customization for edge cases

#### Success Criteria
```bash
✅ secgen generate dns --count 50 works
✅ Output shows correlation IDs and Kibana links
✅ --param key=value works for customization
✅ Backward compatibility: secgen generate --campaign still works
✅ --index writes to correct Elasticsearch indices
```

---

### Phase 3: Attack Pattern Commands (Week 3)

#### Goal
Quick execution of attack patterns for detection rule testing with attack-specific insights.

#### What Gets Built

**Attack Command**:
```bash
# Execute brute force
secgen attack brute-force --count 3 --index

# C2 beaconing
secgen attack c2-beacon --world-file qa-world.json --index

# Lateral movement
secgen attack lateral-movement --index
```

**Attack-Specific Output**:
```
======================================================================
ATTACK PATTERN: brute-force
======================================================================
Description: Password brute force attack with multiple failed attempts
MITRE ATT&CK TTPs: T1110.001, T1110.003

Executing 3 iterations...

Iteration 1/3...
  Generated 25 events (20 failures + 5 metadata)
Iteration 2/3...
  Generated 25 events
Iteration 3/3...
  Generated 25 events

Total events: 75

======================================================================
ATTACK INSIGHTS
======================================================================

Event Timeline:
  authentication.start: 60
  authentication.failure: 60
  authentication.success: 3
  iam.info: 12

Detection Opportunities:
  MITRE ATT&CK TTPs: T1110.001, T1110.003
  Recommended Detection Rules:
    T1110.001: Failed authentication threshold, account lockout events
    T1110.003: Multiple usernames from same IP, credential stuffing patterns

Kibana Links:
  View Timeline for user admin: http://localhost:5601/app/security/timelines
  View all events: host.id:host-abc123

======================================================================
```

#### Implementation Steps

1. **Create Attack Handler** (`secgen/cli/handlers/attack_handler.py`):
   - Look up attack pattern in registry
   - Setup World state (filter by OS if needed)
   - Execute attack pattern method multiple times
   - Collect all events
   - Build attack-specific Kibana links
   - Print detection insights

2. **Update CLI** (`secgen/cli.py`):
   - Add routing for `attack` command

#### Files Created (1)
- `secgen/cli/handlers/attack_handler.py`

#### Files Modified (2)
- `secgen/cli.py` - Routing
- `secgen/cli/commands.py` - Add attack command

#### User Value
✅ Test detection rules with realistic attacks
✅ Get MITRE ATT&CK context automatically
✅ See detection recommendations
✅ Timeline/Analyzer links for investigation

#### Success Criteria
```bash
✅ secgen attack brute-force generates correlated failed auth events
✅ Output shows MITRE TTPs and detection recommendations
✅ Kibana links work for Timeline and Analyzer views
✅ World state filtering by OS works (e.g., Windows-only attacks)
```

---

### Phase 4: Missing Data Generators (Week 4-5)

#### Goal
Add generators for critical missing data types to achieve complete Elastic Security coverage.

#### What Gets Built

**1. Vulnerability Generator** (`secgen/generators/security/vulnerability.py`):
```python
# CVE database with realistic vulnerabilities
- CVE-2021-44228 (Log4j) - Critical
- CVE-2021-3156 (Sudo) - High
- CVE-2023-23397 (Outlook) - Critical
- 20+ common CVEs

# Features
- CVSS scoring (v3.1)
- Package correlation
- Scanner metadata
- Host correlation
```

**2. CSPM Generator** (`secgen/generators/cloud/cspm.py`):
```python
# Compliance frameworks
- CIS AWS Foundations Benchmark v1.4.0
- CIS Azure Foundations Benchmark v1.5.0
- PCI-DSS v3.2.1

# Features
- Pass/fail evaluation
- Resource details
- Compliance scoring
- Benchmark references
```

**3. Entity Analytics Enhancement**:
```python
# Risk Score Generator (secgen/generators/analytics/risk_score.py)
- Host risk scores (0-100)
- User risk scores (0-100)
- Risk inputs tracking
- Risk level categorization (Low/Medium/High/Critical)

# Entity Model Updates
- Host.asset_criticality (low/medium/high/critical)
- Host.risk_score
- User.risk_score
```

**4. Geo-Enrichment Utility** (`secgen/utils/geo.py`):
```python
# Extract geo database from network/flow.py
- 14+ global locations with lat/lon
- Country codes, cities, regions
- AS organization data
- Apply to Host entities during World.populate()
```

#### Usage Examples

```bash
# Vulnerability scanning
secgen generate vulnerability --count 200 --param severity=critical
secgen generate vulnerability --count 100 --use-world

# Cloud security posture
secgen generate cspm --param cloud_provider=aws --param framework="CIS AWS" --count 150
secgen generate cspm --param cloud_provider=azure --count 100

# Entity Analytics
secgen generate risk-score --use-world --count 30

# All hosts now have geo data automatically
secgen generate network-flow --use-world --count 500
```

#### Implementation Steps

1. **Create Vulnerability Generator**:
   - Define CVE database with 20+ common vulnerabilities
   - Implement `generate()` with severity filtering
   - Implement `generate_scan_report()` for full host scans
   - Add ECS compliance (vulnerability.*, package.*)

2. **Create CSPM Generator**:
   - Define compliance rules for CIS AWS, CIS Azure, PCI-DSS
   - Implement `generate()` with pass/fail logic
   - Implement `generate_compliance_report()` with pass rate
   - Add cloud resource details

3. **Create Risk Score Generator**:
   - Implement `generate_host_risk_score()` with risk inputs
   - Implement `generate_user_risk_score()`
   - Calculate normalized scores (0-100)
   - Map scores to levels

4. **Create Geo Utility**:
   - Extract geo database to `secgen/utils/geo.py`
   - Add `get_random_geo()`, `get_geo_for_country()`
   - Update `Host.generate()` to assign geo

5. **Update Entity Models**:
   - Add fields to Host: `asset_criticality`, `risk_score`, `geo`
   - Add fields to User: `risk_score`
   - Update `to_ecs_dict()` methods

6. **Update Indexer**:
   - Add index patterns: `logs-vulnerability.scan-default`
   - Add: `logs-cloud_security_posture.findings-default`
   - Add: `logs-entity_analytics.risk-default`

#### Files Created (4)
- `secgen/generators/security/vulnerability.py`
- `secgen/generators/cloud/cspm.py`
- `secgen/generators/analytics/risk_score.py`
- `secgen/utils/geo.py`

#### Files Modified (4)
- `secgen/models/entities/host.py` - Add risk/criticality/geo
- `secgen/models/entities/user.py` - Add risk_score
- `secgen/generators/network/flow.py` - Use geo utility
- `secgen/indexers/elasticsearch.py` - Add index patterns

#### User Value
✅ Test vulnerability management workflows
✅ Test cloud security posture dashboards
✅ Test Entity Analytics risk scoring
✅ Complete Network Map geo-diversity

#### Success Criteria
```bash
✅ secgen generate vulnerability creates CVE events with CVSS scores
✅ secgen generate cspm creates compliance findings
✅ Hosts have asset_criticality and risk_score fields
✅ All network events include geo_point for source/destination
✅ New indices work in Elasticsearch
```

---

### Phase 5: Feature Testing Commands (Week 6)

#### Goal
Feature-oriented commands that generate optimized data for testing specific Elastic Security features.

#### What Gets Built

**Feature Test Registry**:
```python
# Define feature tests
- network-map: Network flows with geo-diversity
- timeline: Correlated events for single host/user
- analyzer: Process tree for Resolver
- entity-analytics: Risk scores and alerts
- detection-rule: Malicious events for rule testing
- vulnerability-management: Vulnerability scans
- cloud-posture: Compliance findings
```

**Test Command**:
```bash
# Test Network Map
secgen test network-map --index

# Test Timeline
secgen test timeline --index

# Test Analyzer
secgen test analyzer --index

# Test Entity Analytics
secgen test entity-analytics --index

# Test vulnerability management
secgen test vulnerability-management --index

# Test cloud security posture
secgen test cloud-posture --index
```

**Feature-Specific Output**:
```
======================================================================
FEATURE TEST: network-map
======================================================================
Description: Network Map visualization with diverse network flows
Event Types: network-flow, dns, http, tls
Correlation Keys: source.ip, destination.ip, source.geo, destination.geo

Generating 200 network flows...
Generated 200 events

======================================================================
TESTING GUIDANCE
======================================================================

1. Open Kibana Security → Network Map
2. Verify diverse source and destination IPs
3. Check geo-location markers on map
4. Filter by source.geo.country_name or destination.geo.country_name
5. Verify network flow statistics

Kibana Links:
  http://localhost:5601/app/security/network - Network Map

======================================================================
```

#### Implementation Steps

1. **Create Feature Definitions** (`secgen/features/definitions.py`):
   - Register 7 feature tests
   - Define event types, correlation keys, recommended counts
   - Store in registry

2. **Create Feature Test Handler** (`secgen/cli/handlers/test_handler.py`):
   - Implement feature-specific generation logic
   - `_test_network_map()` - Geo-diverse flows
   - `_test_timeline()` - Correlated events
   - `_test_analyzer()` - Process tree
   - `_test_entity_analytics()` - Risk scores + alerts
   - `_test_detection_rule()` - Malicious events
   - `_test_vulnerability_management()` - Vuln scans
   - `_test_cloud_posture()` - CSPM findings
   - Print feature-specific testing guidance

3. **Update CLI** (`secgen/cli.py`):
   - Add routing for `test` command

4. **Update List Handler**:
   - Add `list feature-tests` support

#### Files Created (2)
- `secgen/features/definitions.py`
- `secgen/cli/handlers/test_handler.py`

#### Files Modified (3)
- `secgen/cli.py` - Routing
- `secgen/cli/commands.py` - Add test command
- `secgen/cli/handlers/list_handler.py` - List feature-tests

#### User Value
✅ Test any Elastic Security feature with one command
✅ Get feature-specific testing guidance
✅ Optimized data for each feature
✅ Kibana links to relevant views

#### Success Criteria
```bash
✅ secgen test network-map generates geo-diverse flows
✅ secgen test timeline generates correlated events for same host
✅ secgen test entity-analytics generates risk scores and alerts
✅ Testing guidance is printed for each feature
✅ Kibana links work correctly
```

---

### Phase 6: Preset System (Week 7)

#### Goal
One-command workflows for common QA scenarios using declarative YAML presets.

#### What Gets Built

**Preset Schema** (`secgen/presets/schema.py`):
```yaml
name: demo-cluster
description: Comprehensive demo data

world:
  num_hosts: 30
  num_users: 50
  os_distribution:
    windows: 0.6
    linux: 0.3
    macos: 0.1

events:
  - type: process
    count: 200
    malicious_ratio: 0.15

  - type: vulnerability
    count: 200

attacks:
  - pattern: brute-force
    count: 2

  - pattern: c2-beacon
    count: 1

index_to_es: true
```

**Built-in Presets**:
1. **demo-cluster** - Comprehensive demo for all features
2. **entity-analytics-showcase** - Focused on Entity Analytics
3. **load-test** - High-volume performance testing
4. **attack-simulation** - Realistic attack scenarios

**Preset Command**:
```bash
# Built-in presets
secgen preset demo-cluster
secgen preset entity-analytics-showcase
secgen preset load-test
secgen preset attack-simulation

# Custom preset
secgen preset my-scenario.yaml

# Override indexing
secgen preset demo-cluster --no-index
```

**Preset Output**:
```
======================================================================
PRESET: demo-cluster
======================================================================
Description: Comprehensive demo data for showcasing all Elastic Security features

Creating World...
  Hosts: 30
  Users: 50

Generating events...
  process: 200 events
  file: 150 events
  network-flow: 300 events
  vulnerability: 200 events

Executing attack patterns...
  brute-force: 2 iterations
  c2-beacon: 1 iteration

Total events generated: 1,500

Indexing to Elasticsearch...
✅ Indexed to 12 indices

======================================================================
NEXT STEPS
======================================================================

This preset generated comprehensive demo data. You can now:

1. Explore Security Overview dashboard
2. View Network Map with diverse geo-locations
3. Check Entity Analytics for risk scores
4. Review Vulnerability Management
5. Create Timelines for specific hosts/users
6. Test detection rules against malicious events

======================================================================
```

#### Implementation Steps

1. **Create Preset Schema** (`secgen/presets/schema.py`):
   - Define `Preset`, `PresetEventConfig`, `PresetAttackConfig` dataclasses
   - Implement `from_yaml()` and `to_yaml()` methods
   - Validate preset structure

2. **Create Built-in Presets**:
   - `demo-cluster.yaml` - 30 hosts, all event types, multiple attacks
   - `entity-analytics-showcase.yaml` - Risk scores focus
   - `load-test.yaml` - 100 hosts, 20K+ events
   - `attack-simulation.yaml` - Multiple attack patterns

3. **Create Preset Handler** (`secgen/cli/handlers/preset_handler.py`):
   - Load preset from file (builtin or custom path)
   - Create World with preset configuration
   - Execute event generation
   - Execute attack patterns
   - Print preset-specific guidance

4. **Update CLI** (`secgen/cli.py`):
   - Add routing for `preset` command

#### Files Created (6)
- `secgen/presets/schema.py`
- `secgen/presets/demo-cluster.yaml`
- `secgen/presets/entity-analytics-showcase.yaml`
- `secgen/presets/load-test.yaml`
- `secgen/presets/attack-simulation.yaml`
- `secgen/cli/handlers/preset_handler.py`

#### Files Modified (2)
- `secgen/cli.py` - Routing
- `secgen/cli/commands.py` - Add preset command

#### User Value
✅ One-command demo environment setup
✅ Shareable test scenarios (YAML files)
✅ Reproducible QA workflows
✅ Custom presets for team needs

#### Success Criteria
```bash
✅ secgen preset demo-cluster generates comprehensive data
✅ secgen preset load-test generates 10K+ events
✅ Custom YAML presets work
✅ Preset-specific guidance is helpful
✅ --no-index flag works to skip Elasticsearch
```

---

## Critical Design Decisions

### 1. Command Organization: Flat Top-Level Structure

**Decision**: Use flat command structure instead of deep nesting

```bash
# CHOSEN APPROACH (Flat)
secgen generate <event-type>
secgen attack <pattern>
secgen test <feature>
secgen list <category>
secgen describe <item>
secgen preset <name>

# REJECTED APPROACH (Nested)
secgen event generate <type>
secgen pattern execute <name>
secgen feature test <name>
```

**Rationale**:
- ✅ More discoverable (tab completion works better)
- ✅ Shorter commands (fewer keystrokes)
- ✅ Maps to QA mental models ("I want to test X")
- ✅ Consistent with industry standards (kubectl, docker, aws)

### 2. Discovery Mechanism: Decorator-Based Registration

**Decision**: Use Python decorators for static registration

```python
@register_event_type(
    name="dns",
    category=GeneratorCategory.NETWORK,
    description="DNS query events",
    ecs_fields=["dns.question.name", "dns.resolved_ip"],
)
class DNSEventGenerator:
    pass
```

**Alternatives Considered**:
- ❌ Runtime reflection (fragile, slow, hard to debug)
- ❌ YAML manifests (duplication, out of sync with code)
- ❌ Manual registration (easy to forget, maintenance burden)

**Rationale**:
- ✅ Compile-time safety (decorator errors caught early)
- ✅ Rich metadata attached to classes
- ✅ Self-documenting (description next to code)
- ✅ Zero runtime overhead (decorators run once at import)
- ✅ Maintainable (decorator enforces metadata schema)

### 3. Output Formatting: Custom Module, No Dependencies

**Decision**: Create custom formatter without external libraries

```python
# secgen/output/formatter.py
class OutputFormatter:
    """Pure Python formatting with simple ANSI codes."""

    @staticmethod
    def format_summary(summary: GenerationSummary) -> str:
        # Uses only stdlib and simple string formatting
        pass
```

**Alternatives Considered**:
- ❌ `rich` library (heavy dependency, 5MB+, not CI-friendly)
- ❌ `tabulate` (another dependency, limited customization)
- ❌ `colorama` (cross-platform ANSI, but unnecessary for Linux/Mac targets)

**Rationale**:
- ✅ No dependency bloat (keeps pip install fast)
- ✅ CI/CD compatible (plain text fallback)
- ✅ JSON output option (for scripting)
- ✅ Simple ANSI codes work on all target platforms
- ✅ Full control over formatting

### 4. Preset System: YAML-Based Configuration

**Decision**: Use YAML for preset definitions

```yaml
# demo-cluster.yaml
name: demo-cluster
description: Demo data

events:
  - type: dns
    count: 100
    params:
      is_malicious: true

attacks:
  - pattern: brute-force
    count: 2
```

**Alternatives Considered**:
- ❌ JSON (no comments, less readable)
- ❌ Python code (requires code review for sharing)
- ❌ Custom DSL (learning curve, tooling needed)

**Rationale**:
- ✅ Familiar to QA/DevOps (widely used in testing)
- ✅ Supports comments (inline documentation)
- ✅ Easy to share (version control, gists, docs)
- ✅ Declarative (what to generate, not how)
- ✅ Already dependency (pyyaml used for scenarios)

### 5. New Generator Organization

**Decision**: Organize by security domain

```
secgen/generators/
  security/          # NEW: Vulnerability scanning
    vulnerability.py
  cloud/
    cspm.py          # NEW: CSPM findings
  analytics/         # NEW: Entity Analytics
    risk_score.py
  utils/             # NEW: Shared utilities
    geo.py
```

**Alternatives Considered**:
- ❌ Flat structure (17+ generators in one dir)
- ❌ By event.category (mixes concerns)
- ❌ By data source (elasticsearch, beats, etc.)

**Rationale**:
- ✅ Follows existing pattern (endpoint/, network/, identity/, cloud/)
- ✅ Groups related functionality
- ✅ Clear ownership (security team owns security/)
- ✅ Scales well (each domain can grow independently)

---

## File Changes Overview

### Summary Statistics

- **Total New Files**: 37
- **Total Modified Files**: 22
- **Total Lines of Code (estimated)**: ~8,000 LOC
- **Test Files to Create**: ~15

### New Files by Phase

| Phase | New Files | Purpose |
|-------|-----------|---------|
| Phase 1 | 4 | Registry & discovery infrastructure |
| Phase 2 | 3 | Output formatting & event generation |
| Phase 3 | 1 | Attack pattern execution |
| Phase 4 | 4 | New data generators |
| Phase 5 | 2 | Feature testing |
| Phase 6 | 6 | Preset system |
| **Total** | **20** | **Core functionality** |
| Tests | 15+ | Unit & integration tests |
| Docs | 2 | Command reference, preset guide |

### Modified Files by Category

| Category | Files | Changes |
|----------|-------|---------|
| CLI Infrastructure | 3 | Routing, commands, settings |
| Entity Models | 2 | Add risk scores, geo, criticality |
| Generators | 17 | Add @register decorators |
| Indexer | 1 | Add new index patterns |
| **Total** | **23** | **Enhancements** |

### Detailed File Changes

#### Phase 1: Registry & Discovery

**New Files**:
```
secgen/registry.py                      # 300 LOC - Core registry
secgen/registry_bootstrap.py            # 80 LOC - Bootstrap
secgen/cli/handlers/list_handler.py     # 150 LOC - List command
secgen/cli/handlers/describe_handler.py # 120 LOC - Describe command
```

**Modified Files**:
```
secgen/cli.py                           # +20 LOC - Bootstrap & routing
secgen/generators/endpoint/file.py      # +10 LOC - Decorator
secgen/generators/endpoint/registry.py  # +10 LOC - Decorator
secgen/generators/endpoint/network.py   # +10 LOC - Decorator
secgen/generators/network/dns.py        # +10 LOC - Decorator
secgen/generators/network/flow.py       # +10 LOC - Decorator
secgen/generators/network/http.py       # +10 LOC - Decorator
secgen/generators/network/tls.py        # +10 LOC - Decorator
secgen/generators/identity/auth.py      # +10 LOC - Decorator
secgen/generators/identity/iam.py       # +10 LOC - Decorator
secgen/generators/cloud/aws.py          # +10 LOC - Decorator
secgen/generators/cloud/azure.py        # +10 LOC - Decorator
secgen/generators/cloud/gcp.py          # +10 LOC - Decorator
secgen/generators/threat_intel/indicators.py # +10 LOC - Decorator
secgen/generators/alert.py              # +10 LOC - Decorator
secgen/generators/process.py            # +10 LOC - Decorator
secgen/generators/campaign.py           # +10 LOC - Decorator
```

#### Phase 2: Direct Event Generation

**New Files**:
```
secgen/output/__init__.py               # Empty
secgen/output/formatter.py              # 250 LOC - Formatting
secgen/cli/handlers/generate_handler.py # 200 LOC - Generate command
secgen/cli/handlers/generate_legacy.py  # 100 LOC - Legacy moved
```

**Modified Files**:
```
secgen/cli.py                           # +30 LOC - Routing
secgen/cli/commands.py                  # +40 LOC - Command args
secgen/config/settings.py               # +5 LOC - kibana_url
```

#### Phase 3: Attack Pattern Commands

**New Files**:
```
secgen/cli/handlers/attack_handler.py   # 300 LOC - Attack execution
```

**Modified Files**:
```
secgen/cli.py                           # +15 LOC - Routing
secgen/cli/commands.py                  # +20 LOC - Attack command
```

#### Phase 4: Missing Data Generators

**New Files**:
```
secgen/generators/security/__init__.py           # Empty
secgen/generators/security/vulnerability.py      # 400 LOC - CVE events
secgen/generators/cloud/cspm.py                  # 350 LOC - CSPM
secgen/generators/analytics/__init__.py          # Empty
secgen/generators/analytics/risk_score.py        # 200 LOC - Risk scores
secgen/utils/__init__.py                         # Empty
secgen/utils/geo.py                              # 150 LOC - Geo utility
```

**Modified Files**:
```
secgen/models/entities/host.py          # +30 LOC - Add fields
secgen/models/entities/user.py          # +10 LOC - Add risk_score
secgen/generators/network/flow.py       # +10 LOC - Use geo utility
secgen/indexers/elasticsearch.py        # +15 LOC - Index patterns
```

#### Phase 5: Feature Testing Commands

**New Files**:
```
secgen/features/__init__.py             # Empty
secgen/features/definitions.py          # 150 LOC - Feature metadata
secgen/cli/handlers/test_handler.py     # 500 LOC - Test execution
```

**Modified Files**:
```
secgen/cli.py                           # +15 LOC - Routing
secgen/cli/commands.py                  # +20 LOC - Test command
secgen/cli/handlers/list_handler.py     # +30 LOC - List features
```

#### Phase 6: Preset System

**New Files**:
```
secgen/presets/__init__.py                       # Empty
secgen/presets/schema.py                         # 200 LOC - Schema
secgen/presets/demo-cluster.yaml                 # 80 lines - Preset
secgen/presets/entity-analytics-showcase.yaml    # 50 lines - Preset
secgen/presets/load-test.yaml                    # 40 lines - Preset
secgen/presets/attack-simulation.yaml            # 60 lines - Preset
secgen/cli/handlers/preset_handler.py            # 300 LOC - Executor
```

**Modified Files**:
```
secgen/cli.py                           # +15 LOC - Routing
secgen/cli/commands.py                  # +20 LOC - Preset command
```

---

## Success Criteria

### Phase 1 Success Criteria

```bash
# Discovery works
✅ secgen list event-types
   Output: 17+ event types grouped by category

✅ secgen list attack-patterns
   Output: 40+ attack patterns with TTPs

✅ secgen describe event-type dns
   Output: Description, ECS fields, example usage

✅ secgen describe attack brute-force
   Output: TTPs, description, event count estimate
```

### Phase 2 Success Criteria

```bash
# Direct generation works
✅ secgen generate dns --count 50
   Output: 50 DNS events with summary

✅ secgen generate dns --count 50 --param is_malicious=true
   Output: 50 malicious DNS events

✅ secgen generate process --use-world --count 30
   Output: 30 process events with consistent host.id

✅ secgen generate network-flow --index --count 100
   Output: 100 flows indexed to Elasticsearch

# Backward compatibility
✅ secgen generate --campaign --count 50
   Output: Works as before (legacy mode)
```

### Phase 3 Success Criteria

```bash
# Attack patterns work
✅ secgen attack brute-force --count 2
   Output: Brute force events with MITRE TTPs

✅ secgen attack c2-beacon --index
   Output: C2 beaconing events, Kibana links

✅ Attack output shows detection recommendations
   Output: TTPs mapped to detection types
```

### Phase 4 Success Criteria

```bash
# New generators work
✅ secgen generate vulnerability --count 100
   Output: 100 CVE events with CVSS scores

✅ secgen generate cspm --count 50
   Output: 50 compliance findings

✅ secgen generate risk-score --use-world --count 10
   Output: 10 risk score events

# Entity enhancements
✅ Hosts have geo, asset_criticality, risk_score fields
✅ Network flows include geo_point for Network Map
✅ New indices work in Elasticsearch
```

### Phase 5 Success Criteria

```bash
# Feature tests work
✅ secgen test network-map --index
   Output: Geo-diverse flows, testing guidance

✅ secgen test timeline --index
   Output: Correlated events for same host

✅ secgen test entity-analytics --index
   Output: Risk scores, alerts, criticality

# Testing guidance is useful
✅ Each test prints step-by-step Kibana instructions
✅ Kibana links are correct
```

### Phase 6 Success Criteria

```bash
# Presets work
✅ secgen preset demo-cluster
   Output: Comprehensive demo data (1000+ events)

✅ secgen preset entity-analytics-showcase
   Output: Focused Entity Analytics data

✅ secgen preset load-test
   Output: 10K+ events for performance testing

# Custom presets work
✅ secgen preset my-custom.yaml
   Output: Custom scenario executes correctly
```

---

## Risk Mitigation

### Risk 1: Breaking Existing Workflows

**Risk Level**: High
**Impact**: Users' scripts and automation break

**Mitigation**:
- ✅ Maintain 100% backward compatibility
- ✅ Legacy commands route to separate handlers
- ✅ New commands use distinct names (no conflicts)
- ✅ Comprehensive backward compatibility tests
- ✅ Deprecation warnings (not removal) for old patterns

**Testing**:
```bash
# All existing commands must still work
secgen --count 20
secgen --count 50 --campaign
secgen generate --count 30 --use-world
secgen world create --hosts 50
```

### Risk 2: Registry Overhead

**Risk Level**: Medium
**Impact**: Slower startup time

**Mitigation**:
- ✅ Lazy initialization via bootstrap (only when needed)
- ✅ Decorators have zero runtime cost (execute once at import)
- ✅ Registry uses dicts (O(1) lookup)
- ✅ No reflection or dynamic imports in hot paths

**Benchmark Target**:
- Registry bootstrap: < 200ms
- Command execution: Same as current (no regression)

### Risk 3: Output Formatter Complexity

**Risk Level**: Low
**Impact**: Inconsistent output, hard to parse

**Mitigation**:
- ✅ Keep formatter simple (no complex dependencies)
- ✅ Provide JSON output option for CI/CD
- ✅ Use dataclasses for type safety
- ✅ Unit tests for all formatting functions

**Output Modes**:
- Default: Human-readable with ANSI colors
- `--json`: Machine-parseable JSON
- `--quiet`: Minimal output (just errors)

### Risk 4: ECS Schema Compliance

**Risk Level**: High
**Impact**: Data doesn't work in Elastic Security

**Mitigation**:
- ✅ Reference official ECS documentation for each field
- ✅ Validate against Elasticsearch field mappings
- ✅ Test with actual Elastic Security dashboards
- ✅ Use existing generators as templates

**Validation Process**:
1. Generate events
2. Index to Elasticsearch
3. Verify in Kibana Discover
4. Check field types in Index Management
5. Test in relevant Elastic Security app (Network Map, Timeline, etc.)

### Risk 5: Scope Creep

**Risk Level**: Medium
**Impact**: Timeline extends, features incomplete

**Mitigation**:
- ✅ Phased delivery (each phase is independent)
- ✅ Clear success criteria per phase
- ✅ Ship Phase 1 before starting Phase 2
- ✅ Get user feedback between phases
- ✅ Defer "nice-to-have" features to future

**Phase Gates**:
- Each phase must pass success criteria before next phase starts
- User feedback collected after Phases 1, 3, 5
- Timeline adjustments based on actual velocity

---

## Testing Strategy

### Unit Tests

**Coverage Target**: 80% minimum

**Test Organization**:
```
tests/
  test_registry.py              # Registry registration/lookup
  test_output_formatter.py      # Output formatting
  test_vulnerability.py         # Vulnerability generator
  test_cspm.py                  # CSPM generator
  test_risk_score.py            # Risk score generator
  test_geo_util.py              # Geo-enrichment
  test_preset_schema.py         # Preset YAML loading
```

**Key Test Cases**:
```python
# Registry tests
def test_register_event_type()
def test_list_event_types_by_category()
def test_get_event_type_not_found()
def test_register_attack_pattern()
def test_list_attack_patterns_by_ttp()

# Generator tests
def test_vulnerability_generate()
def test_vulnerability_scan_report()
def test_cspm_generate()
def test_cspm_compliance_report()
def test_risk_score_calculate()

# Formatter tests
def test_format_summary()
def test_format_table()
def test_build_kibana_link()

# Preset tests
def test_preset_from_yaml()
def test_preset_validation()
```

### Integration Tests

**Test Scenarios**:
```bash
# Phase 1
tests/integration/test_list_commands.py
  - test_list_event_types()
  - test_describe_event_type()
  - test_list_attack_patterns()

# Phase 2
tests/integration/test_generate_commands.py
  - test_generate_dns()
  - test_generate_with_params()
  - test_generate_with_world()
  - test_backward_compatibility()

# Phase 3
tests/integration/test_attack_commands.py
  - test_attack_brute_force()
  - test_attack_with_world()

# Phase 4
tests/integration/test_new_generators.py
  - test_vulnerability_events()
  - test_cspm_events()
  - test_entity_analytics_fields()

# Phase 5
tests/integration/test_feature_tests.py
  - test_network_map()
  - test_timeline()
  - test_entity_analytics()

# Phase 6
tests/integration/test_presets.py
  - test_builtin_preset()
  - test_custom_preset()
```

### End-to-End Tests

**Elasticsearch Integration**:
```bash
# E2E test: Full workflow
1. secgen generate dns --count 50 --index
2. Verify 50 docs in logs-dns.query-*
3. Verify fields in Kibana Discover
4. Verify correlation IDs present

# E2E test: Feature test
1. secgen test network-map --index
2. Verify geo_point fields present
3. Open Network Map in Kibana
4. Verify markers on map

# E2E test: Preset
1. secgen preset demo-cluster
2. Verify multiple indices populated
3. Verify risk scores calculated
4. Verify vulnerabilities indexed
```

### Backward Compatibility Tests

**Critical Scenarios**:
```bash
# Must continue working unchanged
✅ secgen --count 20
✅ secgen --count 50 --campaign
✅ secgen --count 30 --use-world
✅ secgen --dry-run --count 10
✅ secgen world create --hosts 50
✅ secgen perf-test --events 1000
✅ secgen llm commands --tactic execution
```

### Performance Tests

**Benchmarks**:
```bash
# Baseline (current)
secgen --count 1000
  Time: ~5 seconds
  Memory: ~200MB

# After Phase 1 (registry)
secgen generate process --count 1000
  Target: < 5.5 seconds (< 10% regression)
  Memory: < 220MB

# After Phase 6 (full)
secgen preset load-test
  Target: 10K events in < 60 seconds
  Memory: < 500MB
```

---

## Documentation Updates

### Required Documentation

**1. Update README.md**:
```markdown
## Quick Start

# Discovery
secgen list event-types
secgen describe event-type dns

# Direct generation
secgen generate dns --count 50 --param is_malicious=true

# Attack patterns
secgen attack brute-force --count 3 --index

# Feature testing
secgen test network-map --index

# Presets
secgen preset demo-cluster
```

**2. Update CLAUDE.md**:
```markdown
## Adding a New Event Generator

1. Create generator following pattern
2. Add @register_event_type decorator
3. Add to generators/<category>/__init__.py
4. Generator auto-discovered via registry
```

**3. Create docs/COMMANDS.md**:
```markdown
# Command Reference

## List Commands
- secgen list event-types [--filter <category>]
- secgen list attack-patterns [--ttp <ttp>]
- secgen list generators
- secgen list feature-tests

## Describe Commands
- secgen describe event-type <name>
- secgen describe attack <pattern>

## Generate Commands
- secgen generate <event-type> [options]

## Attack Commands
- secgen attack <pattern> [options]

## Test Commands
- secgen test <feature> [options]

## Preset Commands
- secgen preset <name|file>
```

**4. Create docs/PRESETS.md**:
```markdown
# Preset Creation Guide

## Preset Schema

## Built-in Presets

## Creating Custom Presets

## Sharing Presets
```

**5. Update CONTRIBUTING.md**:
```markdown
## Adding a New Generator

1. Create generator class
2. Add @register_event_type decorator
3. Add tests
4. Update docs

## Adding a New Attack Pattern

1. Add method to generator
2. Add @register_attack_pattern decorator
3. Add tests
```

---

## Timeline and Milestones

### Week-by-Week Schedule

| Week | Phase | Deliverables | Milestone |
|------|-------|--------------|-----------|
| **Week 1** | Phase 1 | Registry, list, describe commands | Discovery working |
| **Week 2** | Phase 2 | Output formatter, generate command | Direct generation working |
| **Week 3** | Phase 3 | Attack command | Attack patterns via CLI |
| **Week 4** | Phase 4 | Vulnerability, CSPM generators | New data types |
| **Week 5** | Phase 4 | Entity Analytics, geo-enrichment | Complete data coverage |
| **Week 6** | Phase 5 | Feature test commands | Feature testing |
| **Week 7** | Phase 6 | Preset system | One-command workflows |

### Phase Dependencies

```
Phase 1 (Registry) ──┬──> Phase 2 (Generate)
                     │
                     ├──> Phase 3 (Attack)
                     │
                     ├──> Phase 4 (New Generators)
                     │
                     └──> Phase 5 (Test) ──> Phase 6 (Presets)
```

**Critical Path**: Phase 1 → Phase 2 → Phase 5 → Phase 6

**Parallel Work**:
- Phase 4 can start during Phase 2 (independent generators)
- Phase 3 can start during Phase 2 (uses registry from Phase 1)

### Delivery Schedule

**Alpha Release** (End of Week 2):
- Phase 1 & 2 complete
- `list`, `describe`, `generate` commands working
- Internal testing with QA team

**Beta Release** (End of Week 5):
- Phase 1-4 complete
- All new generators working
- External testing with pilot users

**GA Release** (End of Week 7):
- All 6 phases complete
- Full documentation
- Production-ready

---

## Appendix: Command Examples

### Discovery Examples

```bash
# List all event types
secgen list event-types
  Output: 17+ event types by category

# List network event types
secgen list event-types --filter network
  Output: dns, http, tls, flow

# List attack patterns
secgen list attack-patterns
  Output: 40+ patterns with TTPs

# List by MITRE TTP
secgen list attack-patterns --ttp T1110
  Output: brute-force, credential-stuffing

# Describe DNS generator
secgen describe event-type dns
  Output: Full metadata, ECS fields, examples

# Describe brute force attack
secgen describe attack brute-force
  Output: TTPs, description, event count
```

### Generation Examples

```bash
# Generate DNS events
secgen generate dns --count 50

# Generate malicious DNS
secgen generate dns --count 50 --param is_malicious=true

# Generate with World state
secgen generate process --use-world --count 30

# Generate and index
secgen generate network-flow --count 200 --index

# Output to file
secgen generate file --count 100 --output events.json

# Use persistent World
secgen generate process --world-file qa-world.json --count 50
```

### Attack Examples

```bash
# Brute force attack
secgen attack brute-force --count 3 --index

# C2 beaconing
secgen attack c2-beacon --index

# Lateral movement
secgen attack lateral-movement --world-file prod-world.json --index

# Data exfiltration
secgen attack data-exfiltration --index
```

### Feature Test Examples

```bash
# Test Network Map
secgen test network-map --index

# Test Timeline
secgen test timeline --index

# Test Entity Analytics
secgen test entity-analytics --index

# Test with custom count
secgen test network-map --count 500 --index
```

### Preset Examples

```bash
# Demo environment
secgen preset demo-cluster

# Entity Analytics showcase
secgen preset entity-analytics-showcase

# Performance testing
secgen preset load-test

# Attack simulation
secgen preset attack-simulation

# Custom preset
secgen preset my-scenario.yaml

# Override indexing
secgen preset demo-cluster --no-index
```

---

## Appendix: Technical References

### ECS Field References

**Vulnerability Fields**:
- `vulnerability.id` (CVE-2021-44228)
- `vulnerability.severity` (critical/high/medium/low)
- `vulnerability.score.base` (0.0-10.0 CVSS)
- `vulnerability.score.version` (3.1)
- `vulnerability.description`
- `package.name`, `package.version`

**CSPM Fields**:
- `rule.id` (cis-aws-1.1)
- `rule.name`, `rule.description`
- `rule.reference` (CIS AWS Foundations Benchmark)
- `cloud.account.id`, `cloud.provider`
- `event.outcome` (success/failure)

**Entity Analytics Fields**:
- `host.risk.calculated_score_norm` (0-100)
- `host.risk.calculated_level` (Low/Medium/High/Critical)
- `host.asset.criticality` (low/medium/high/critical)
- `user.risk.calculated_score_norm` (0-100)

**Geo Fields** (Network Map):
- `source.geo.location` (geo_point: {lat, lon})
- `source.geo.country_iso_code`
- `destination.geo.location` (geo_point)

### Index Pattern References

| Event Type | Index Pattern |
|------------|---------------|
| Vulnerability | `logs-vulnerability.scan-default` |
| CSPM | `logs-cloud_security_posture.findings-default` |
| Entity Risk | `logs-entity_analytics.risk-default` |
| DNS | `logs-dns.query-default` |
| Process | `logs-endpoint.events.process-default` |
| Network Flow | `logs-network_traffic.flow-default` |

---

**END OF IMPLEMENTATION PLAN**
