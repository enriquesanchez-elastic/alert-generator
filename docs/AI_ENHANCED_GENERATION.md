# AI-Enhanced Generation

SecGen includes optional AI-powered features that use Google Gemini to generate realistic, context-aware security data artifacts. These features enhance the base generators with dynamic, LLM-generated content.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Configuration](#configuration)
4. [Features](#features)
   - [Command Library Generator](#command-library-generator)
   - [Campaign Narrative Generator](#campaign-narrative-generator)
   - [Entity Profile Generator](#entity-profile-generator)
   - [Scenario Variation Generator](#scenario-variation-generator)
5. [Artifact Caching](#artifact-caching)
6. [Python API Examples](#python-api-examples)
7. [Cost Considerations](#cost-considerations)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The AI-enhanced generation module uses Google's Gemini LLM to create:

| Generator | Purpose | Output |
|-----------|---------|--------|
| **CommandLibraryGenerator** | Realistic attack commands | Commands organized by MITRE ATT&CK tactic |
| **CampaignNarrativeGenerator** | Multi-day attack stories | Complete campaign narratives with phases |
| **EntityProfileGenerator** | User behavior profiles | Industry-specific personas with anomaly indicators |
| **ScenarioVariationGenerator** | Attack scenario variants | Multiple variations of base attack scenarios |

### Key Benefits

- **Realistic Content**: LLM-generated commands and narratives are more realistic than static templates
- **Threat Actor Emulation**: Generate content styled after specific APT groups
- **Industry-Specific Profiles**: User personas tailored to healthcare, finance, technology, etc.
- **Dynamic Variations**: Automatically create scenario variations without manual authoring
- **Caching**: Generated artifacts are cached locally to minimize API costs

---

## Prerequisites

### 1. Install google-genai

The Gemini client requires the `google-genai` package:

```bash
# Using uv
uv pip install google-genai

# Using pip
pip install google-genai
```

### 2. Get a Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Sign in with your Google account
3. Click "Get API key" → "Create API key"
4. Copy the API key

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | (required) | Your Google Gemini API key |
| `GEMINI_MODEL` | `gemini-3-pro-preview` | Model to use (see available models below) |
| `LLM_ARTIFACTS_DIR` | `~/.secgen/llm_artifacts` | Directory for cached artifacts |
| `LLM_CACHE_ENABLED` | `true` | Enable/disable artifact caching |

### Setting Up

**Option 1: Environment variables**

```bash
export GEMINI_API_KEY="your-api-key-here"
export GEMINI_MODEL="gemini-2.0-flash"  # Optional: use a different model
```

**Option 2: .env file**

Create a `.env` file in your project root:

```bash
GEMINI_API_KEY=your-api-key-here
GEMINI_MODEL=gemini-2.0-flash
LLM_ARTIFACTS_DIR=~/.secgen/llm_artifacts
LLM_CACHE_ENABLED=true
```

### Available Models

| Model | Description | Best For |
|-------|-------------|----------|
| `gemini-3-pro-preview` | Latest, most capable (default) | Complex campaigns, high-quality output |
| `gemini-2.0-flash` | Fast, cost-effective | Quick generation, development |
| `gemini-2.0-flash-lite` | Fastest, lowest cost | Simple tasks, high volume |

---

## Features

### Command Library Generator

Generates realistic attack commands organized by MITRE ATT&CK tactics.

#### Supported Tactics

| Tactic | Description |
|--------|-------------|
| `reconnaissance` | Network scanning, user enumeration, service discovery |
| `initial_access` | Phishing payloads, exploitation, credential stuffing |
| `execution` | PowerShell, WMI, CMD, scripting, scheduled tasks |
| `persistence` | Registry, scheduled tasks, services, startup items |
| `privilege_escalation` | Token manipulation, UAC bypass, credential theft |
| `defense_evasion` | Obfuscation, disable security, indicator removal |
| `credential_access` | Credential dumping, keylogging, brute force |
| `discovery` | System info, network info, process/file discovery |
| `lateral_movement` | WMI, PSRemoting, RDP, SMB, SSH |
| `collection` | Data staging, clipboard, screen capture |
| `exfiltration` | HTTP, DNS, cloud storage, encrypted channels |
| `command_and_control` | HTTP beacon, DNS tunnel, encrypted channel |

#### Threat Actor Styles

Commands can be styled after specific threat actors:

- `APT29` - Russian state-sponsored, stealthy, long-term access
- `APT28` - Russian military intelligence, aggressive, zero-days
- `APT41` - Chinese state-sponsored with criminal sideline
- `FIN7` - Financial crime group, POS malware
- `Lazarus` - North Korean state-sponsored, cryptocurrency theft
- `REvil` - Ransomware-as-a-service, double extortion
- `Conti` - Ransomware group, affiliate model
- `generic_apt` - Generic APT with state-level resources
- `generic_criminal` - Generic financially motivated group

#### Python API

```python
from secgen.config.settings import get_settings
from secgen.llm.client import GeminiClient
from secgen.llm.cache import ArtifactCache
from secgen.llm.generators.commands import CommandLibraryGenerator

# Setup
settings = get_settings()
client = GeminiClient(api_key=settings.gemini_api_key, model=settings.gemini_model)
cache = ArtifactCache(base_dir=settings.llm_artifacts_path)

# Create generator
cmd_gen = CommandLibraryGenerator(client=client, cache=cache)

# Generate commands for a specific tactic
data = cmd_gen.generate(
    tactic="lateral_movement",
    count=30,
    threat_actor_style="APT29",
    os_family="windows",
)

print(f"Generated {data['count_generated']} commands")
for category, commands in data['commands'].items():
    print(f"\n{category}:")
    for cmd in commands[:3]:  # Show first 3
        print(f"  - {cmd}")

# Get a random command
cmd = cmd_gen.get_random_command(
    tactic="execution",
    category="powershell",
    threat_actor_style="generic_apt",
    os_family="windows",
)
print(f"Random command: {cmd}")

# Generate for all tactics (uses caching)
all_commands = cmd_gen.generate_all_tactics(
    count_per_tactic=20,
    threat_actor_style="FIN7",
    os_family="windows",
)
```

---

### Campaign Narrative Generator

Creates complete, multi-day attack campaign narratives with realistic phases.

#### Campaign Objectives

| Objective | Description |
|-----------|-------------|
| `data_theft` | Exfiltrate sensitive data (PII, IP, financial) |
| `ransomware` | Deploy ransomware for financial extortion |
| `espionage` | Long-term access for intelligence gathering |
| `destruction` | Destroy or disrupt target operations |
| `cryptomining` | Deploy cryptocurrency miners |
| `supply_chain` | Compromise for downstream targeting |

#### Target Sectors

Healthcare, finance, technology, retail, manufacturing, government, education, legal

#### Python API

```python
from secgen.llm.generators.campaigns import CampaignNarrativeGenerator

# Create generator (reuse client/cache from above)
campaign_gen = CampaignNarrativeGenerator(client=client, cache=cache)

# Generate a campaign narrative
data = campaign_gen.generate(
    threat_actor="APT29",
    target_sector="technology",
    dwell_time_days=14,
    objective="data_theft",
    org_size="medium",
    target_os="windows",
)

campaign = data["campaign"]
print(f"Campaign: {campaign['name']}")
print(f"Threat Actor: {campaign['threat_actor']}")
print(f"Duration: {campaign['dwell_time_days']} days")

# List phases
for phase in campaign.get("phases", []):
    print(f"\nDay {phase.get('day')}: {phase.get('name')}")
    print(f"  TTP: {phase.get('ttp')}")
    print(f"  Story: {phase.get('story', '')[:100]}...")

# Get infrastructure details
infra = campaign_gen.get_infrastructure(
    threat_actor="APT29",
    target_sector="technology",
)
print(f"\nC2 Domains: {infra.get('c2_domains', [])}")
print(f"Malware Family: {infra.get('malware_family')}")

# Get all indicators of compromise
iocs = campaign_gen.get_indicators(
    threat_actor="APT29",
    target_sector="technology",
)
for ioc in iocs[:5]:
    print(f"IOC: {ioc['type']} = {ioc['value']} (phase: {ioc['phase']})")

# Convert to scenario format for use with generators
scenarios = campaign_gen.convert_to_scenarios(
    threat_actor="APT29",
    target_sector="technology",
)
print(f"\nGenerated {len(scenarios)} scenarios from campaign phases")
```

---

### Entity Profile Generator

Creates realistic user behavior profiles for specific industry verticals.

#### Industries

| Industry | Context |
|----------|---------|
| `healthcare` | HIPAA compliance, PHI access, medical devices, shift work |
| `finance` | PCI-DSS compliance, trading systems, strict access controls |
| `technology` | Developer access, CI/CD pipelines, cloud infrastructure, remote work |
| `retail` | POS systems, inventory management, seasonal workers |
| `manufacturing` | OT/ICS systems, shift workers, limited IT access |
| `government` | Classified information, strict access controls, compliance |
| `education` | Student/faculty access, research data, FERPA compliance |
| `legal` | Client privilege, document management, remote attorney access |

#### Python API

```python
from secgen.llm.generators.profiles import EntityProfileGenerator

# Create generator
profile_gen = EntityProfileGenerator(client=client, cache=cache)

# Generate profiles for an industry
data = profile_gen.generate(
    industry="healthcare",
    role_count=10,
    org_size="large",
)

print(f"Generated {data['role_count_generated']} personas for {data['industry']}")

# Get personas
personas = profile_gen.get_personas(industry="healthcare", org_size="large")
for persona in personas[:3]:
    print(f"\nRole: {persona.get('role')}")
    print(f"  Department: {persona.get('department')}")
    print(f"  Privilege: {persona.get('privilege_level')}")
    print(f"  Working hours: {persona.get('typical_behavior', {}).get('working_hours')}")

# Get a random persona by privilege level
admin = profile_gen.get_random_persona(
    industry="finance",
    org_size="medium",
    privilege_level="admin",
)
print(f"\nRandom admin: {admin.get('role')}")

# Get anomaly indicators for threat detection
anomalies = profile_gen.get_anomaly_indicators(
    industry="technology",
    org_size="medium",
)
for anomaly in anomalies[:5]:
    print(f"Anomaly: {anomaly.get('indicator')} (severity: {anomaly.get('severity')})")

# Get typical applications for a role
apps = profile_gen.get_typical_applications(
    industry="finance",
    org_size="large",
    role="Trader",
)
print(f"\nTypical apps for Trader: {apps}")

# Generate a concrete user from a persona template
user = profile_gen.generate_user_from_persona(
    persona=personas[0],
    first_name="Alice",
    last_name="Smith",
)
print(f"\nGenerated user: {user['username']} ({user['role']})")
```

---

### Scenario Variation Generator

Generates variations of base attack scenarios with different techniques and tools.

#### Python API

```python
from secgen.llm.generators.scenarios import ScenarioVariationGenerator

# Create generator
scenario_gen = ScenarioVariationGenerator(client=client, cache=cache)

# Generate variations from a base scenario
data = scenario_gen.generate(
    base_name="Ransomware Attack",
    base_description="Ransomware deployment via phishing",
    base_severity="critical",
    base_process_chain=[
        {"name": "OUTLOOK.EXE", "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"},
        {"name": "powershell.exe", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        {"name": "ransomware.exe", "executable": "C:\\Temp\\ransomware.exe"},
    ],
    variation_count=5,
    target_os="windows",
)

print(f"Generated {data['variation_count_generated']} variations of '{data['base_scenario']}'")

# List variations
for var in data.get("scenarios", []):
    print(f"\n{var.get('name')}")
    print(f"  Description: {var.get('description', '')[:80]}...")
    print(f"  TTPs: {var.get('ttps', [])}")
    print(f"  Threat Actor Style: {var.get('threat_actor_style')}")

# Convert to Scenario objects for use with generators
scenario_objects = scenario_gen.convert_to_scenario_objects(data)
print(f"\nConverted to {len(scenario_objects)} Scenario objects")

# Generate variations for multiple base scenarios
from secgen.config.loader import load_scenarios

base_scenarios = load_scenarios("alert_scenarios.yaml")
all_variations = scenario_gen.generate_for_multiple_bases(
    base_scenarios=base_scenarios[:3],  # First 3 scenarios
    variations_per_base=3,
    target_os="windows",
)
print(f"Generated {len(all_variations)} total variations")
```

---

## CLI Commands

SecGen provides CLI commands for generating and managing LLM artifacts.

### Generate Command Libraries

```bash
# Generate execution commands (PowerShell, WMI, etc.)
secgen llm commands --tactic execution --count 30 --actor APT29 --os windows

# Generate lateral movement commands
secgen llm commands --tactic lateral_movement --count 20 --actor FIN7

# List available tactics
secgen llm commands --list-tactics

# Force regeneration (bypass cache)
secgen llm commands --tactic discovery --force
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--tactic` | `execution` | MITRE ATT&CK tactic |
| `--count` | `30` | Number of commands to generate |
| `--actor` | `generic_apt` | Threat actor style |
| `--os` | `windows` | Target OS (windows, linux, macos) |
| `--force` | `false` | Force regeneration |
| `--list-tactics` | - | List available tactics |

### Generate Scenario Variations

```bash
# Generate ransomware variations
secgen llm scenarios --base "Ransomware" --variations 5 --os windows

# Generate phishing variations
secgen llm scenarios --base "Phishing Attack" --variations 3

# Force regeneration
secgen llm scenarios --base "Web Shell" --force
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--base` | `Ransomware` | Base scenario name |
| `--variations` | `5` | Number of variations |
| `--os` | `windows` | Target OS |
| `--force` | `false` | Force regeneration |

### Generate Entity Profiles

```bash
# Generate healthcare profiles
secgen llm profiles --industry healthcare --roles 15 --org-size large

# Generate finance profiles
secgen llm profiles --industry finance --roles 10

# List available industries
secgen llm profiles --list-industries

# Force regeneration
secgen llm profiles --industry technology --force
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--industry` | `technology` | Industry vertical |
| `--roles` | `10` | Number of roles/personas |
| `--org-size` | `medium` | Organization size (small, medium, large) |
| `--force` | `false` | Force regeneration |
| `--list-industries` | - | List available industries |

### Generate Campaign Narratives

```bash
# Generate APT29 campaign
secgen llm campaign --actor APT29 --target technology --days 14 --objective data_theft

# Generate ransomware campaign
secgen llm campaign --actor REvil --target healthcare --objective ransomware --days 7

# List available threat actors
secgen llm campaign --list-actors

# List available objectives
secgen llm campaign --list-objectives

# Force regeneration
secgen llm campaign --actor FIN7 --target retail --force
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--actor` | `APT29` | Threat actor to emulate |
| `--target` | `technology` | Target sector |
| `--days` | `14` | Campaign duration in days |
| `--objective` | `data_theft` | Campaign objective |
| `--org-size` | `medium` | Organization size |
| `--os` | `windows` | Target OS |
| `--force` | `false` | Force regeneration |
| `--list-actors` | - | List threat actors |
| `--list-objectives` | - | List objectives |

### Manage Artifact Cache

```bash
# View cache statistics
secgen llm cache stats

# List all cached artifacts
secgen llm cache list

# List artifacts by type
secgen llm cache list --type commands
secgen llm cache list --type scenarios
secgen llm cache list --type profiles
secgen llm cache list --type campaigns

# Clear all artifacts
secgen llm cache clear

# Clear specific type
secgen llm cache clear --type commands
```

### Using LLM with Event Generation

The `generate` command supports LLM integration for enhanced event generation:

```bash
# Use LLM-generated artifacts when generating events
secgen generate --count 50 --use-world --use-llm-artifacts --industry healthcare

# Full LLM mode: generate ALL artifacts first, then events
secgen generate --count 100 --use-world --full-llm \
  --industry technology --threat-actor APT29

# Force LLM artifact regeneration
secgen generate --count 50 --full-llm --force-regenerate
```

**LLM Options for `generate`:**

| Option | Description |
|--------|-------------|
| `--use-llm-artifacts` | Use LLM-generated artifacts in event generation |
| `--full-llm` | Full LLM mode: generate all artifact types first |
| `--industry` | Industry for LLM profiles (default: technology) |
| `--threat-actor` | Threat actor for LLM campaign (default: APT29) |
| `--force-regenerate` | Force LLM artifact regeneration |

---

## Artifact Caching

LLM-generated artifacts are cached locally to minimize API calls and costs.

### Cache Structure

```
~/.secgen/llm_artifacts/
├── commands/              # Command libraries (JSON)
│   ├── execution_apt29_windows.json
│   ├── lateral_movement_fin7_windows.json
│   └── ...
├── scenarios/             # Scenario variations (YAML)
│   ├── ransomware_variations_windows.yaml
│   └── ...
├── profiles/              # Entity profiles (YAML)
│   ├── healthcare_large.yaml
│   ├── finance_medium.yaml
│   └── ...
└── campaigns/             # Campaign narratives (YAML)
    ├── apt29_technology_data_theft.yaml
    └── ...
```

### Cache Management

```python
from secgen.llm.cache import ArtifactCache

cache = ArtifactCache(base_dir="~/.secgen/llm_artifacts")

# List cached artifacts
commands = cache.list_artifacts("commands")
for artifact in commands:
    print(f"{artifact['name']}: {artifact['size_bytes']} bytes")

# Get cache statistics
stats = cache.get_stats()
print(f"Total artifacts: {stats['total_artifacts']}")
print(f"Total size: {stats['total_size_bytes']} bytes")
print(f"By type: {stats['by_type']}")

# Delete specific artifact
cache.delete("commands", "execution_apt29_windows")

# Clear all artifacts of a type
cache.clear("commands")

# Clear entire cache
cache.clear()
```

### Force Regeneration

To bypass the cache and regenerate artifacts:

```python
# Force regenerate specific artifact
data = cmd_gen.generate_or_load(
    force_regenerate=True,
    tactic="execution",
    threat_actor_style="APT29",
)

# Or delete from cache first
cache.delete("commands", "execution_apt29_windows")
data = cmd_gen.generate_or_load(tactic="execution", threat_actor_style="APT29")
```

---

## Python API Examples

### Complete Example: AI-Enhanced Campaign Generation

```python
"""
Complete example: Generate a realistic attack campaign using AI features.
"""
from secgen.config.settings import get_settings
from secgen.core.world import World
from secgen.indexers.elasticsearch import ElasticsearchIndexer
from secgen.llm.cache import ArtifactCache
from secgen.llm.client import GeminiClient
from secgen.llm.generators.campaigns import CampaignNarrativeGenerator
from secgen.llm.generators.commands import CommandLibraryGenerator
from secgen.llm.generators.profiles import EntityProfileGenerator

# Setup
settings = get_settings()

# Check if LLM is available
if not settings.gemini_api_key:
    print("GEMINI_API_KEY not set. Set it to enable AI features.")
    exit(1)

# Initialize LLM components
client = GeminiClient(api_key=settings.gemini_api_key, model=settings.gemini_model)
cache = ArtifactCache(base_dir=settings.llm_artifacts_path)

# Create generators
campaign_gen = CampaignNarrativeGenerator(client=client, cache=cache)
cmd_gen = CommandLibraryGenerator(client=client, cache=cache)
profile_gen = EntityProfileGenerator(client=client, cache=cache)

# Step 1: Generate entity profiles for target industry
print("Generating entity profiles...")
profiles = profile_gen.generate(
    industry="technology",
    role_count=15,
    org_size="medium",
)
print(f"  Created {profiles['role_count_generated']} user personas")

# Step 2: Generate campaign narrative
print("\nGenerating campaign narrative...")
campaign_data = campaign_gen.generate(
    threat_actor="APT41",
    target_sector="technology",
    dwell_time_days=21,
    objective="data_theft",
    org_size="medium",
)
campaign = campaign_data["campaign"]
print(f"  Campaign: {campaign['name']}")
print(f"  Phases: {len(campaign.get('phases', []))}")

# Step 3: Generate commands for each attack phase
print("\nGenerating attack commands...")
for phase in campaign.get("phases", [])[:3]:  # First 3 phases
    ttp = phase.get("ttp", "")
    # Map TTP to tactic (simplified)
    tactic = "execution"
    if "T1021" in ttp:
        tactic = "lateral_movement"
    elif "T1048" in ttp:
        tactic = "exfiltration"
    elif "T1110" in ttp:
        tactic = "credential_access"
    
    commands = cmd_gen.generate(
        tactic=tactic,
        count=10,
        threat_actor_style="APT41",
        os_family="windows",
    )
    print(f"  Phase '{phase.get('name')}': {commands['count_generated']} commands")

# Step 4: Create World state from profiles
print("\nCreating World state...")
world = World()
world.populate(num_hosts=20, num_users=30)

# Step 5: Get IOCs from campaign for threat intelligence
iocs = campaign_gen.get_indicators(
    threat_actor="APT41",
    target_sector="technology",
)
print(f"\nExtracted {len(iocs)} IOCs from campaign:")
for ioc in iocs[:5]:
    print(f"  - {ioc['type']}: {ioc['value']}")

# Step 6: Convert campaign to scenarios
scenarios = campaign_gen.convert_to_scenarios(
    threat_actor="APT41",
    target_sector="technology",
)
print(f"\nConverted to {len(scenarios)} executable scenarios")

# Print token usage
print(f"\nToken usage: {client.total_tokens_used}")
```

### Example: Integrating AI Commands with Event Generation

```python
"""
Use AI-generated commands in process events.
"""
from secgen.generators.process import ProcessEventGenerator
from secgen.llm.generators.commands import CommandLibraryGenerator

# Setup (client and cache from previous example)
cmd_gen = CommandLibraryGenerator(client=client, cache=cache)
process_gen = ProcessEventGenerator()

# Get AI-generated commands for lateral movement
commands = cmd_gen.get_commands_for_tactic(
    tactic="lateral_movement",
    threat_actor_style="APT29",
    os_family="windows",
)

# Use in process event generation
for category, cmd_list in commands.items():
    for cmd in cmd_list[:2]:  # First 2 commands per category
        # Parse command for process event
        parts = cmd.split()
        process_name = parts[0] if parts else "cmd.exe"
        args = parts[1:] if len(parts) > 1 else []
        
        event = process_gen.generate(
            host=world.get_random_host(),
            user=world.get_random_user(),
            process_name=process_name,
            args=args,
        )
        print(f"Generated process event: {process_name} {' '.join(args[:3])}...")
```

---

## Cost Considerations

### API Pricing

Google Gemini pricing varies by model and usage. Check the [Google AI pricing page](https://ai.google.dev/pricing) for current rates.

### Minimizing Costs

1. **Enable Caching**: Caching is enabled by default (`LLM_CACHE_ENABLED=true`)
2. **Use Faster Models**: `gemini-2.0-flash` is cheaper than `gemini-3-pro-preview`
3. **Generate Once, Use Many**: Generate artifacts once, then use cached versions
4. **Batch Generation**: Generate for all tactics/industries at once, then use cached
5. **Monitor Usage**: Check `client.total_tokens_used` to track consumption

### Token Usage Estimates

| Operation | Estimated Tokens |
|-----------|-----------------|
| Command library (30 commands) | ~2,000-3,000 |
| Campaign narrative (14 days) | ~4,000-8,000 |
| Entity profiles (10 personas) | ~3,000-5,000 |
| Scenario variations (5) | ~2,000-4,000 |

---

## Troubleshooting

### ImportError: google-genai not installed

```
ImportError: google-genai is not installed. Install with: pip install google-genai
```

**Solution**: Install the package:
```bash
pip install google-genai
# or
uv pip install google-genai
```

### ValueError: Gemini API key is required

```
ValueError: Gemini API key is required. Set GEMINI_API_KEY environment variable...
```

**Solution**: Set your API key:
```bash
export GEMINI_API_KEY="your-api-key-here"
```

### RuntimeError: Failed to generate after N attempts

```
RuntimeError: Failed to generate after 3 attempts. Last error: ...
```

**Possible causes**:
- Rate limiting: Wait and retry
- Invalid API key: Verify your key at [Google AI Studio](https://aistudio.google.com/)
- Network issues: Check connectivity
- Model unavailable: Try a different model

### JSONDecodeError / YAMLError

The LLM sometimes returns malformed output.

**Solutions**:
- Retry the generation (transient issue)
- Use a more capable model (`gemini-3-pro-preview`)
- Delete cached artifact and regenerate

### Cache Directory Permission Error

```
PermissionError: [Errno 13] Permission denied: '/root/.secgen/llm_artifacts'
```

**Solution**: Set a writable cache directory:
```bash
export LLM_ARTIFACTS_DIR="/tmp/secgen_cache"
```

---

## Related Documentation

- [DATA_GENERATION.md](DATA_GENERATION.md) - Core data generation architecture
- [FEATURES.md](FEATURES.md) - All SecGen features
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) - Claude Desktop integration
- [COMMANDS.md](COMMANDS.md) - CLI command reference
