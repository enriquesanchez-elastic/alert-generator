"""Prompt templates for LLM-based artifact generation."""

# =============================================================================
# COMMAND LIBRARY PROMPTS
# =============================================================================

COMMAND_LIBRARY_PROMPT = """You are a cybersecurity expert specializing in threat actor TTPs (Tactics, Techniques, and Procedures). Generate realistic command-line commands that would be used by attackers during the "{tactic}" phase of an attack.

Requirements:
- Generate exactly {count} unique commands
- Style the commands after {threat_actor_style} threat actor techniques
- Target {os_family} systems
- Commands should be realistic and technically accurate
- Include variations in syntax and approach
- Use placeholders like {{target}}, {{username}}, {{domain}}, {{file_path}} for dynamic values

Tactic: {tactic}
Description: {tactic_description}

Categories to include:
{categories}

Output as JSON with this structure:
{{
  "tactic": "{tactic}",
  "threat_actor_style": "{threat_actor_style}",
  "os_family": "{os_family}",
  "commands": {{
    "category_name": [
      "command 1",
      "command 2"
    ]
  }}
}}
"""

TACTIC_DESCRIPTIONS = {
    "reconnaissance": "Gathering information about the target environment, including network topology, user accounts, and system configurations",
    "initial_access": "Gaining initial foothold through phishing, exploitation, or credential theft",
    "execution": "Running malicious code through various execution mechanisms like PowerShell, WMI, or scripting interpreters",
    "persistence": "Maintaining access through scheduled tasks, registry modifications, or service installation",
    "privilege_escalation": "Elevating privileges through exploitation, token manipulation, or credential access",
    "defense_evasion": "Avoiding detection through obfuscation, disabling security tools, or indicator removal",
    "credential_access": "Obtaining credentials through dumping, keylogging, or brute forcing",
    "discovery": "Exploring the environment to understand network, system, and user configurations",
    "lateral_movement": "Moving through the network using stolen credentials or exploitation",
    "collection": "Gathering data of interest for exfiltration",
    "exfiltration": "Stealing data through various channels like HTTP, DNS, or cloud services",
    "command_and_control": "Establishing and maintaining communication with compromised systems",
}

TACTIC_CATEGORIES = {
    "reconnaissance": [
        "network_scanning",
        "user_enumeration",
        "service_discovery",
        "share_enumeration",
    ],
    "initial_access": ["phishing_payloads", "exploitation", "credential_stuffing"],
    "execution": ["powershell", "wmi", "cmd", "scripting", "scheduled_tasks"],
    "persistence": ["registry", "scheduled_tasks", "services", "startup_items"],
    "privilege_escalation": ["token_manipulation", "uac_bypass", "exploit", "credential_theft"],
    "defense_evasion": ["obfuscation", "disable_security", "indicator_removal", "masquerading"],
    "credential_access": ["dumping", "keylogging", "brute_force", "credential_harvesting"],
    "discovery": ["system_info", "network_info", "process_discovery", "file_discovery"],
    "lateral_movement": ["wmi", "psremoting", "rdp", "smb", "ssh"],
    "collection": ["data_staging", "clipboard", "screen_capture", "email_collection"],
    "exfiltration": ["http", "dns", "cloud_storage", "encrypted_channel"],
    "command_and_control": ["http_beacon", "dns_tunnel", "encrypted_channel", "proxy"],
}


# =============================================================================
# SCENARIO VARIATION PROMPTS
# =============================================================================

SCENARIO_VARIATION_PROMPT = """You are a cybersecurity expert creating attack scenario variations for security testing. Given a base attack scenario, generate {variation_count} realistic variations.

Base Scenario:
Name: {base_name}
Description: {base_description}
Severity: {base_severity}
Process Chain: {base_process_chain}
Target OS: {target_os}

Requirements for each variation:
- Change the initial access vector (different entry points)
- Use different tools/techniques for similar goals
- Vary the malware family or tooling
- Maintain realistic attack flow and TTPs
- Include MITRE ATT&CK technique IDs
- Keep process chains between 3-5 processes

Generate variations as YAML with this structure:
scenarios:
  - name: "Variation Name"
    description: "Description of the attack variation"
    severity: "{base_severity}"
    threat_actor_style: "APT group or criminal group style"
    ttps:
      - "T1566.001"
      - "T1059.001"
    processes:
      - name: "process.exe"
        executable: "full/path/to/process.exe"
        args: ["arg1", "arg2"]
        working_dir: "working/directory"
        user: "username"
    malware_file:
      name: "filename.exe"
      path: "full/path/to/malware"
      extension: ".exe"
"""


# =============================================================================
# ENTITY PROFILE PROMPTS
# =============================================================================

ENTITY_PROFILE_PROMPT = """You are a cybersecurity expert creating realistic user behavior profiles for a {industry} organization. Generate {role_count} distinct user personas that would exist in this environment.

Industry: {industry}
Organization Size: {org_size}
Additional Context: {context}

For each persona, provide:
1. Role/job title
2. Username pattern (use {{firstname}}, {{lastname}}, {{dept}} as placeholders)
3. Typical applications they use
4. Normal working hours
5. Data access patterns (what systems/data they typically access)
6. Network behavior (internal/external access patterns)
7. Anomaly indicators (what would be suspicious for this role)

Output as YAML with this structure:
personas:
  - role: "Job Title"
    department: "Department Name"
    username_pattern: "pattern_{{lastname}}"
    typical_behavior:
      applications:
        - "app1.exe"
        - "app2.exe"
      working_hours: "8am-5pm weekdays"
      data_access:
        - "resource_type_1"
        - "resource_type_2"
      network:
        internal_only: false
        typical_destinations:
          - "internal_servers"
          - "cloud_services"
    anomaly_indicators:
      - indicator: "process or behavior"
        severity: "low|medium|high|critical"
        reason: "Why this is anomalous for this role"
    privilege_level: "standard|elevated|admin"
"""

INDUSTRY_CONTEXTS = {
    "healthcare": "HIPAA compliance required, access to PHI, medical devices on network, shift work common",
    "finance": "PCI-DSS compliance, trading systems, high-value targets, strict access controls",
    "technology": "Developer access to production, CI/CD pipelines, cloud infrastructure, remote work",
    "retail": "POS systems, inventory management, seasonal workers, multiple locations",
    "manufacturing": "OT/ICS systems, shift workers, limited IT access for floor workers",
    "government": "Classified information handling, strict access controls, compliance requirements",
    "education": "Student and faculty access, research data, FERPA compliance, open network policies",
    "legal": "Client privilege, document management, remote access for attorneys",
}


# =============================================================================
# CAMPAIGN NARRATIVE PROMPTS
# =============================================================================

CAMPAIGN_NARRATIVE_PROMPT = """You are a cybersecurity threat intelligence analyst creating a detailed attack campaign narrative for security testing. Generate a realistic, multi-day attack campaign.

Campaign Parameters:
- Threat Actor Style: {threat_actor}
- Target Sector: {target_sector}
- Target Organization Size: {org_size}
- Campaign Duration: {dwell_time_days} days
- Primary Objective: {objective}
- Target OS Environment: {target_os}

Requirements:
1. Create a realistic day-by-day attack progression
2. Include specific TTPs with MITRE ATT&CK IDs
3. Describe attacker decisions and adaptations
4. Include realistic dwell time between phases
5. Reference realistic tools and malware families
6. Include process chains for key attack steps
7. Add C2 infrastructure details

Output as YAML with this structure:
campaign:
  name: "Operation Name"
  threat_actor: "{threat_actor}"
  target_sector: "{target_sector}"
  objective: "{objective}"
  dwell_time_days: {dwell_time_days}
  
  infrastructure:
    c2_domains:
      - "domain1.com"
    c2_ips:
      - "1.2.3.4"
    malware_family: "Malware Name"
    tools:
      - "Tool 1"
      - "Tool 2"
  
  phases:
    - day: 1
      name: "phase_name"
      ttp: "T1566.001"
      description: "What happens in this phase"
      story: "Narrative description of attacker actions"
      targets:
        - "target_type"
      process_chain:
        - name: "process.exe"
          executable: "/path/to/process"
          args: ["arg1"]
          working_dir: "/working/dir"
          user: "username"
      indicators:
        - type: "domain|ip|hash|file"
          value: "indicator_value"
      expected_alerts:
        - "Alert name or rule that might fire"
"""

THREAT_ACTOR_PROFILES = {
    "APT29": "Russian state-sponsored, stealthy, long-term access, targets government and technology",
    "APT28": "Russian military intelligence, aggressive, uses zero-days, targets government and media",
    "APT41": "Chinese state-sponsored with criminal sideline, supply chain attacks, ransomware",
    "FIN7": "Financial crime group, targets retail and hospitality, point-of-sale malware",
    "Lazarus": "North Korean state-sponsored, cryptocurrency theft, destructive attacks",
    "REvil": "Ransomware-as-a-service, double extortion, targets large enterprises",
    "Conti": "Ransomware group, affiliate model, healthcare and critical infrastructure",
    "generic_apt": "Generic advanced persistent threat with state-level resources",
    "generic_criminal": "Generic financially motivated criminal group",
}

CAMPAIGN_OBJECTIVES = {
    "data_theft": "Exfiltrate sensitive data (PII, IP, financial)",
    "ransomware": "Deploy ransomware for financial extortion",
    "espionage": "Long-term access for intelligence gathering",
    "destruction": "Destroy or disrupt target operations",
    "cryptomining": "Deploy cryptocurrency miners",
    "supply_chain": "Compromise for downstream targeting",
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_command_library_prompt(
    tactic: str,
    count: int = 30,
    threat_actor_style: str = "generic_apt",
    os_family: str = "windows",
) -> str:
    """
    Generate a command library prompt.

    Args:
        tactic: MITRE ATT&CK tactic name
        count: Number of commands to generate
        threat_actor_style: Threat actor to emulate
        os_family: Target OS (windows, linux, macos)

    Returns:
        Formatted prompt string
    """
    tactic_lower = tactic.lower().replace(" ", "_")
    description = TACTIC_DESCRIPTIONS.get(tactic_lower, "Attack technique")
    categories = TACTIC_CATEGORIES.get(tactic_lower, ["general"])

    return COMMAND_LIBRARY_PROMPT.format(
        tactic=tactic_lower,
        count=count,
        threat_actor_style=threat_actor_style,
        os_family=os_family,
        tactic_description=description,
        categories="\n".join(f"- {cat}" for cat in categories),
    )


def get_scenario_variation_prompt(
    base_name: str,
    base_description: str,
    base_severity: str,
    base_process_chain: list[dict],
    variation_count: int = 5,
    target_os: str = "windows",
) -> str:
    """
    Generate a scenario variation prompt.

    Args:
        base_name: Name of base scenario
        base_description: Description of base scenario
        base_severity: Severity level
        base_process_chain: List of process info dicts
        variation_count: Number of variations to generate
        target_os: Target operating system

    Returns:
        Formatted prompt string
    """
    # Format process chain for prompt
    chain_str = " -> ".join(p.get("name", "unknown") for p in base_process_chain)

    return SCENARIO_VARIATION_PROMPT.format(
        base_name=base_name,
        base_description=base_description,
        base_severity=base_severity,
        base_process_chain=chain_str,
        variation_count=variation_count,
        target_os=target_os,
    )


def get_entity_profile_prompt(
    industry: str,
    role_count: int = 10,
    org_size: str = "medium",
    context: str = "",
) -> str:
    """
    Generate an entity profile prompt.

    Args:
        industry: Industry vertical
        role_count: Number of personas to generate
        org_size: Organization size (small, medium, large)
        context: Additional context

    Returns:
        Formatted prompt string
    """
    industry_context = INDUSTRY_CONTEXTS.get(industry.lower(), "Standard corporate environment")

    full_context = f"{industry_context}. {context}".strip()

    return ENTITY_PROFILE_PROMPT.format(
        industry=industry,
        role_count=role_count,
        org_size=org_size,
        context=full_context,
    )


def get_campaign_narrative_prompt(
    threat_actor: str,
    target_sector: str,
    dwell_time_days: int = 14,
    objective: str = "data_theft",
    org_size: str = "medium",
    target_os: str = "windows",
) -> str:
    """
    Generate a campaign narrative prompt.

    Args:
        threat_actor: Threat actor to emulate
        target_sector: Target industry sector
        dwell_time_days: Campaign duration in days
        objective: Primary campaign objective
        org_size: Target organization size
        target_os: Primary target OS

    Returns:
        Formatted prompt string
    """
    actor_profile = THREAT_ACTOR_PROFILES.get(threat_actor, THREAT_ACTOR_PROFILES["generic_apt"])
    objective_desc = CAMPAIGN_OBJECTIVES.get(objective, objective)

    return CAMPAIGN_NARRATIVE_PROMPT.format(
        threat_actor=f"{threat_actor} - {actor_profile}",
        target_sector=target_sector,
        dwell_time_days=dwell_time_days,
        objective=objective_desc,
        org_size=org_size,
        target_os=target_os,
    )
