"""MITRE ATT&CK reference data for threat mapping in alerts."""

from typing import Any

# MITRE ATT&CK Tactics (Enterprise)
# Reference: https://attack.mitre.org/tactics/enterprise/
MITRE_TACTICS: dict[str, dict[str, str]] = {
    "TA0001": {
        "name": "Initial Access",
        "reference": "https://attack.mitre.org/tactics/TA0001/",
        "description": "The adversary is trying to get into your network.",
    },
    "TA0002": {
        "name": "Execution",
        "reference": "https://attack.mitre.org/tactics/TA0002/",
        "description": "The adversary is trying to run malicious code.",
    },
    "TA0003": {
        "name": "Persistence",
        "reference": "https://attack.mitre.org/tactics/TA0003/",
        "description": "The adversary is trying to maintain their foothold.",
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "reference": "https://attack.mitre.org/tactics/TA0004/",
        "description": "The adversary is trying to gain higher-level permissions.",
    },
    "TA0005": {
        "name": "Defense Evasion",
        "reference": "https://attack.mitre.org/tactics/TA0005/",
        "description": "The adversary is trying to avoid being detected.",
    },
    "TA0006": {
        "name": "Credential Access",
        "reference": "https://attack.mitre.org/tactics/TA0006/",
        "description": "The adversary is trying to steal account names and passwords.",
    },
    "TA0007": {
        "name": "Discovery",
        "reference": "https://attack.mitre.org/tactics/TA0007/",
        "description": "The adversary is trying to figure out your environment.",
    },
    "TA0008": {
        "name": "Lateral Movement",
        "reference": "https://attack.mitre.org/tactics/TA0008/",
        "description": "The adversary is trying to move through your environment.",
    },
    "TA0009": {
        "name": "Collection",
        "reference": "https://attack.mitre.org/tactics/TA0009/",
        "description": "The adversary is trying to gather data of interest.",
    },
    "TA0010": {
        "name": "Exfiltration",
        "reference": "https://attack.mitre.org/tactics/TA0010/",
        "description": "The adversary is trying to steal data.",
    },
    "TA0011": {
        "name": "Command and Control",
        "reference": "https://attack.mitre.org/tactics/TA0011/",
        "description": "The adversary is trying to communicate with compromised systems.",
    },
    "TA0040": {
        "name": "Impact",
        "reference": "https://attack.mitre.org/tactics/TA0040/",
        "description": "The adversary is trying to manipulate, interrupt, or destroy systems and data.",
    },
    "TA0042": {
        "name": "Resource Development",
        "reference": "https://attack.mitre.org/tactics/TA0042/",
        "description": "The adversary is trying to establish resources to support operations.",
    },
    "TA0043": {
        "name": "Reconnaissance",
        "reference": "https://attack.mitre.org/tactics/TA0043/",
        "description": "The adversary is trying to gather information to plan future operations.",
    },
}

# MITRE ATT&CK Techniques (subset of most commonly used)
# Reference: https://attack.mitre.org/techniques/enterprise/
MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    # Initial Access
    "T1566": {
        "name": "Phishing",
        "tactic_ids": ["TA0001"],
        "reference": "https://attack.mitre.org/techniques/T1566/",
        "subtechniques": {
            "T1566.001": {
                "name": "Spearphishing Attachment",
                "reference": "https://attack.mitre.org/techniques/T1566/001/",
            },
            "T1566.002": {
                "name": "Spearphishing Link",
                "reference": "https://attack.mitre.org/techniques/T1566/002/",
            },
            "T1566.003": {
                "name": "Spearphishing via Service",
                "reference": "https://attack.mitre.org/techniques/T1566/003/",
            },
        },
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic_ids": ["TA0001"],
        "reference": "https://attack.mitre.org/techniques/T1190/",
        "subtechniques": {},
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic_ids": ["TA0001", "TA0003"],
        "reference": "https://attack.mitre.org/techniques/T1133/",
        "subtechniques": {},
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "reference": "https://attack.mitre.org/techniques/T1078/",
        "subtechniques": {
            "T1078.001": {
                "name": "Default Accounts",
                "reference": "https://attack.mitre.org/techniques/T1078/001/",
            },
            "T1078.002": {
                "name": "Domain Accounts",
                "reference": "https://attack.mitre.org/techniques/T1078/002/",
            },
            "T1078.003": {
                "name": "Local Accounts",
                "reference": "https://attack.mitre.org/techniques/T1078/003/",
            },
            "T1078.004": {
                "name": "Cloud Accounts",
                "reference": "https://attack.mitre.org/techniques/T1078/004/",
            },
        },
    },
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic_ids": ["TA0002"],
        "reference": "https://attack.mitre.org/techniques/T1059/",
        "subtechniques": {
            "T1059.001": {
                "name": "PowerShell",
                "reference": "https://attack.mitre.org/techniques/T1059/001/",
            },
            "T1059.003": {
                "name": "Windows Command Shell",
                "reference": "https://attack.mitre.org/techniques/T1059/003/",
            },
            "T1059.004": {
                "name": "Unix Shell",
                "reference": "https://attack.mitre.org/techniques/T1059/004/",
            },
            "T1059.005": {
                "name": "Visual Basic",
                "reference": "https://attack.mitre.org/techniques/T1059/005/",
            },
            "T1059.006": {
                "name": "Python",
                "reference": "https://attack.mitre.org/techniques/T1059/006/",
            },
            "T1059.007": {
                "name": "JavaScript",
                "reference": "https://attack.mitre.org/techniques/T1059/007/",
            },
        },
    },
    "T1204": {
        "name": "User Execution",
        "tactic_ids": ["TA0002"],
        "reference": "https://attack.mitre.org/techniques/T1204/",
        "subtechniques": {
            "T1204.001": {
                "name": "Malicious Link",
                "reference": "https://attack.mitre.org/techniques/T1204/001/",
            },
            "T1204.002": {
                "name": "Malicious File",
                "reference": "https://attack.mitre.org/techniques/T1204/002/",
            },
        },
    },
    # Persistence
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic_ids": ["TA0003", "TA0004"],
        "reference": "https://attack.mitre.org/techniques/T1547/",
        "subtechniques": {
            "T1547.001": {
                "name": "Registry Run Keys / Startup Folder",
                "reference": "https://attack.mitre.org/techniques/T1547/001/",
            },
            "T1547.004": {
                "name": "Winlogon Helper DLL",
                "reference": "https://attack.mitre.org/techniques/T1547/004/",
            },
        },
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic_ids": ["TA0002", "TA0003", "TA0004"],
        "reference": "https://attack.mitre.org/techniques/T1053/",
        "subtechniques": {
            "T1053.002": {
                "name": "At",
                "reference": "https://attack.mitre.org/techniques/T1053/002/",
            },
            "T1053.003": {
                "name": "Cron",
                "reference": "https://attack.mitre.org/techniques/T1053/003/",
            },
            "T1053.005": {
                "name": "Scheduled Task",
                "reference": "https://attack.mitre.org/techniques/T1053/005/",
            },
        },
    },
    "T1136": {
        "name": "Create Account",
        "tactic_ids": ["TA0003"],
        "reference": "https://attack.mitre.org/techniques/T1136/",
        "subtechniques": {
            "T1136.001": {
                "name": "Local Account",
                "reference": "https://attack.mitre.org/techniques/T1136/001/",
            },
            "T1136.002": {
                "name": "Domain Account",
                "reference": "https://attack.mitre.org/techniques/T1136/002/",
            },
            "T1136.003": {
                "name": "Cloud Account",
                "reference": "https://attack.mitre.org/techniques/T1136/003/",
            },
        },
    },
    # Privilege Escalation
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic_ids": ["TA0004", "TA0005"],
        "reference": "https://attack.mitre.org/techniques/T1548/",
        "subtechniques": {
            "T1548.001": {
                "name": "Setuid and Setgid",
                "reference": "https://attack.mitre.org/techniques/T1548/001/",
            },
            "T1548.002": {
                "name": "Bypass User Account Control",
                "reference": "https://attack.mitre.org/techniques/T1548/002/",
            },
            "T1548.003": {
                "name": "Sudo and Sudo Caching",
                "reference": "https://attack.mitre.org/techniques/T1548/003/",
            },
        },
    },
    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactic_ids": ["TA0005"],
        "reference": "https://attack.mitre.org/techniques/T1070/",
        "subtechniques": {
            "T1070.001": {
                "name": "Clear Windows Event Logs",
                "reference": "https://attack.mitre.org/techniques/T1070/001/",
            },
            "T1070.002": {
                "name": "Clear Linux or Mac System Logs",
                "reference": "https://attack.mitre.org/techniques/T1070/002/",
            },
            "T1070.003": {
                "name": "Clear Command History",
                "reference": "https://attack.mitre.org/techniques/T1070/003/",
            },
            "T1070.004": {
                "name": "File Deletion",
                "reference": "https://attack.mitre.org/techniques/T1070/004/",
            },
        },
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic_ids": ["TA0005"],
        "reference": "https://attack.mitre.org/techniques/T1027/",
        "subtechniques": {
            "T1027.001": {
                "name": "Binary Padding",
                "reference": "https://attack.mitre.org/techniques/T1027/001/",
            },
            "T1027.002": {
                "name": "Software Packing",
                "reference": "https://attack.mitre.org/techniques/T1027/002/",
            },
            "T1027.010": {
                "name": "Command Obfuscation",
                "reference": "https://attack.mitre.org/techniques/T1027/010/",
            },
        },
    },
    # Credential Access
    "T1110": {
        "name": "Brute Force",
        "tactic_ids": ["TA0006"],
        "reference": "https://attack.mitre.org/techniques/T1110/",
        "subtechniques": {
            "T1110.001": {
                "name": "Password Guessing",
                "reference": "https://attack.mitre.org/techniques/T1110/001/",
            },
            "T1110.002": {
                "name": "Password Cracking",
                "reference": "https://attack.mitre.org/techniques/T1110/002/",
            },
            "T1110.003": {
                "name": "Password Spraying",
                "reference": "https://attack.mitre.org/techniques/T1110/003/",
            },
            "T1110.004": {
                "name": "Credential Stuffing",
                "reference": "https://attack.mitre.org/techniques/T1110/004/",
            },
        },
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic_ids": ["TA0006"],
        "reference": "https://attack.mitre.org/techniques/T1003/",
        "subtechniques": {
            "T1003.001": {
                "name": "LSASS Memory",
                "reference": "https://attack.mitre.org/techniques/T1003/001/",
            },
            "T1003.002": {
                "name": "Security Account Manager",
                "reference": "https://attack.mitre.org/techniques/T1003/002/",
            },
            "T1003.003": {
                "name": "NTDS",
                "reference": "https://attack.mitre.org/techniques/T1003/003/",
            },
            "T1003.004": {
                "name": "LSA Secrets",
                "reference": "https://attack.mitre.org/techniques/T1003/004/",
            },
            "T1003.006": {
                "name": "DCSync",
                "reference": "https://attack.mitre.org/techniques/T1003/006/",
            },
            "T1003.007": {
                "name": "Proc Filesystem",
                "reference": "https://attack.mitre.org/techniques/T1003/007/",
            },
            "T1003.008": {
                "name": "/etc/passwd and /etc/shadow",
                "reference": "https://attack.mitre.org/techniques/T1003/008/",
            },
        },
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic_ids": ["TA0006"],
        "reference": "https://attack.mitre.org/techniques/T1558/",
        "subtechniques": {
            "T1558.001": {
                "name": "Golden Ticket",
                "reference": "https://attack.mitre.org/techniques/T1558/001/",
            },
            "T1558.003": {
                "name": "Kerberoasting",
                "reference": "https://attack.mitre.org/techniques/T1558/003/",
            },
        },
    },
    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "tactic_ids": ["TA0007"],
        "reference": "https://attack.mitre.org/techniques/T1087/",
        "subtechniques": {
            "T1087.001": {
                "name": "Local Account",
                "reference": "https://attack.mitre.org/techniques/T1087/001/",
            },
            "T1087.002": {
                "name": "Domain Account",
                "reference": "https://attack.mitre.org/techniques/T1087/002/",
            },
        },
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_ids": ["TA0007"],
        "reference": "https://attack.mitre.org/techniques/T1046/",
        "subtechniques": {},
    },
    "T1135": {
        "name": "Network Share Discovery",
        "tactic_ids": ["TA0007"],
        "reference": "https://attack.mitre.org/techniques/T1135/",
        "subtechniques": {},
    },
    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic_ids": ["TA0008"],
        "reference": "https://attack.mitre.org/techniques/T1021/",
        "subtechniques": {
            "T1021.001": {
                "name": "Remote Desktop Protocol",
                "reference": "https://attack.mitre.org/techniques/T1021/001/",
            },
            "T1021.002": {
                "name": "SMB/Windows Admin Shares",
                "reference": "https://attack.mitre.org/techniques/T1021/002/",
            },
            "T1021.004": {
                "name": "SSH",
                "reference": "https://attack.mitre.org/techniques/T1021/004/",
            },
            "T1021.006": {
                "name": "Windows Remote Management",
                "reference": "https://attack.mitre.org/techniques/T1021/006/",
            },
        },
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic_ids": ["TA0008"],
        "reference": "https://attack.mitre.org/techniques/T1570/",
        "subtechniques": {},
    },
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic_ids": ["TA0009"],
        "reference": "https://attack.mitre.org/techniques/T1005/",
        "subtechniques": {},
    },
    "T1114": {
        "name": "Email Collection",
        "tactic_ids": ["TA0009"],
        "reference": "https://attack.mitre.org/techniques/T1114/",
        "subtechniques": {
            "T1114.001": {
                "name": "Local Email Collection",
                "reference": "https://attack.mitre.org/techniques/T1114/001/",
            },
            "T1114.002": {
                "name": "Remote Email Collection",
                "reference": "https://attack.mitre.org/techniques/T1114/002/",
            },
            "T1114.003": {
                "name": "Email Forwarding Rule",
                "reference": "https://attack.mitre.org/techniques/T1114/003/",
            },
        },
    },
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic_ids": ["TA0010"],
        "reference": "https://attack.mitre.org/techniques/T1041/",
        "subtechniques": {},
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic_ids": ["TA0010"],
        "reference": "https://attack.mitre.org/techniques/T1048/",
        "subtechniques": {
            "T1048.001": {
                "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                "reference": "https://attack.mitre.org/techniques/T1048/001/",
            },
            "T1048.002": {
                "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                "reference": "https://attack.mitre.org/techniques/T1048/002/",
            },
            "T1048.003": {
                "name": "Exfiltration Over Unencrypted Non-C2 Protocol",
                "reference": "https://attack.mitre.org/techniques/T1048/003/",
            },
        },
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic_ids": ["TA0010"],
        "reference": "https://attack.mitre.org/techniques/T1567/",
        "subtechniques": {
            "T1567.002": {
                "name": "Exfiltration to Cloud Storage",
                "reference": "https://attack.mitre.org/techniques/T1567/002/",
            },
        },
    },
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic_ids": ["TA0011"],
        "reference": "https://attack.mitre.org/techniques/T1071/",
        "subtechniques": {
            "T1071.001": {
                "name": "Web Protocols",
                "reference": "https://attack.mitre.org/techniques/T1071/001/",
            },
            "T1071.002": {
                "name": "File Transfer Protocols",
                "reference": "https://attack.mitre.org/techniques/T1071/002/",
            },
            "T1071.004": {
                "name": "DNS",
                "reference": "https://attack.mitre.org/techniques/T1071/004/",
            },
        },
    },
    "T1568": {
        "name": "Dynamic Resolution",
        "tactic_ids": ["TA0011"],
        "reference": "https://attack.mitre.org/techniques/T1568/",
        "subtechniques": {
            "T1568.001": {
                "name": "Fast Flux DNS",
                "reference": "https://attack.mitre.org/techniques/T1568/001/",
            },
            "T1568.002": {
                "name": "Domain Generation Algorithms",
                "reference": "https://attack.mitre.org/techniques/T1568/002/",
            },
        },
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic_ids": ["TA0011"],
        "reference": "https://attack.mitre.org/techniques/T1573/",
        "subtechniques": {
            "T1573.001": {
                "name": "Symmetric Cryptography",
                "reference": "https://attack.mitre.org/techniques/T1573/001/",
            },
            "T1573.002": {
                "name": "Asymmetric Cryptography",
                "reference": "https://attack.mitre.org/techniques/T1573/002/",
            },
        },
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic_ids": ["TA0011"],
        "reference": "https://attack.mitre.org/techniques/T1105/",
        "subtechniques": {},
    },
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic_ids": ["TA0040"],
        "reference": "https://attack.mitre.org/techniques/T1486/",
        "subtechniques": {},
    },
    "T1489": {
        "name": "Service Stop",
        "tactic_ids": ["TA0040"],
        "reference": "https://attack.mitre.org/techniques/T1489/",
        "subtechniques": {},
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic_ids": ["TA0040"],
        "reference": "https://attack.mitre.org/techniques/T1490/",
        "subtechniques": {},
    },
}


def get_tactic(tactic_id: str) -> dict[str, str] | None:
    """
    Get tactic information by ID.

    Args:
        tactic_id: MITRE tactic ID (e.g., "TA0001")

    Returns:
        Tactic dictionary or None if not found
    """
    return MITRE_TACTICS.get(tactic_id)


def get_technique(technique_id: str) -> dict[str, Any] | None:
    """
    Get technique information by ID.

    Args:
        technique_id: MITRE technique ID (e.g., "T1110" or "T1110.001")

    Returns:
        Technique dictionary or None if not found
    """
    # Check if it's a subtechnique
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        parent = MITRE_TECHNIQUES.get(parent_id)
        if parent and "subtechniques" in parent:
            subtechnique = parent["subtechniques"].get(technique_id)
            if subtechnique:
                # Return subtechnique with parent info
                return {
                    **subtechnique,
                    "parent_id": parent_id,
                    "parent_name": parent["name"],
                    "tactic_ids": parent["tactic_ids"],
                }
    return MITRE_TECHNIQUES.get(technique_id)


def get_techniques_for_tactic(tactic_id: str) -> list[dict[str, Any]]:
    """
    Get all techniques for a given tactic.

    Args:
        tactic_id: MITRE tactic ID (e.g., "TA0006")

    Returns:
        List of technique dictionaries
    """
    techniques = []
    for tech_id, tech in MITRE_TECHNIQUES.items():
        if tactic_id in tech.get("tactic_ids", []):
            techniques.append({"id": tech_id, **tech})
    return techniques


def build_threat_mapping(technique_ids: list[str]) -> list[dict[str, Any]]:
    """
    Build a threat mapping array for Elastic Security alerts.

    This generates the proper `kibana.alert.rule.threat` structure
    used by Elastic Security detection rules.

    Args:
        technique_ids: List of MITRE technique IDs (e.g., ["T1110", "T1110.001"])

    Returns:
        List of threat mapping dictionaries in Elastic format
    """
    # Group techniques by tactic
    tactic_techniques: dict[str, list[dict[str, Any]]] = {}

    for tech_id in technique_ids:
        technique = get_technique(tech_id)
        if not technique:
            continue

        # Get tactic IDs for this technique
        tactic_ids = technique.get("tactic_ids", [])
        if "parent_id" in technique:
            # It's a subtechnique, get parent tactic IDs
            parent = MITRE_TECHNIQUES.get(technique["parent_id"])
            if parent:
                tactic_ids = parent.get("tactic_ids", [])

        # Add to each relevant tactic
        for tactic_id in tactic_ids:
            if tactic_id not in tactic_techniques:
                tactic_techniques[tactic_id] = []

            # Build technique entry
            tech_entry: dict[str, Any] = {
                "id": tech_id if "." not in tech_id else tech_id.split(".")[0],
                "name": technique.get("parent_name", technique.get("name", "")),
                "reference": MITRE_TECHNIQUES.get(
                    tech_id.split(".")[0], {}
                ).get("reference", f"https://attack.mitre.org/techniques/{tech_id.split('.')[0]}/"),
            }

            # Add subtechnique if applicable
            if "." in tech_id:
                tech_entry["subtechnique"] = [
                    {
                        "id": tech_id,
                        "name": technique.get("name", ""),
                        "reference": technique.get(
                            "reference",
                            f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                        ),
                    }
                ]

            # Avoid duplicates
            existing_ids = [t["id"] for t in tactic_techniques[tactic_id]]
            if tech_entry["id"] not in existing_ids:
                tactic_techniques[tactic_id].append(tech_entry)
            else:
                # Merge subtechniques
                for existing in tactic_techniques[tactic_id]:
                    if existing["id"] == tech_entry["id"] and "subtechnique" in tech_entry:
                        if "subtechnique" not in existing:
                            existing["subtechnique"] = []
                        for sub in tech_entry["subtechnique"]:
                            if sub not in existing["subtechnique"]:
                                existing["subtechnique"].append(sub)

    # Build final threat array
    threat_array = []
    for tactic_id, techniques in tactic_techniques.items():
        tactic = get_tactic(tactic_id)
        if not tactic:
            continue

        threat_entry = {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic_id,
                "name": tactic["name"],
                "reference": tactic["reference"],
            },
            "technique": techniques,
        }
        threat_array.append(threat_entry)

    return threat_array


# Mapping from attack pattern names to their TTPs
ATTACK_PATTERN_TTPS: dict[str, list[str]] = {
    "brute-force": ["T1110", "T1110.001", "T1110.003"],
    "password-spray": ["T1110", "T1110.003"],
    "credential-stuffing": ["T1110", "T1110.004"],
    "kerberoasting": ["T1558", "T1558.003"],
    "golden-ticket": ["T1558", "T1558.001"],
    "dcsync": ["T1003", "T1003.006"],
    "lsass-dump": ["T1003", "T1003.001"],
    "mimikatz": ["T1003", "T1003.001", "T1558.003"],
    "c2-beacon": ["T1071", "T1071.001", "T1573"],
    "dga": ["T1568", "T1568.002"],
    "dns-tunneling": ["T1071", "T1071.004"],
    "data-exfiltration": ["T1041", "T1048"],
    "malware-drop": ["T1204", "T1204.002", "T1105"],
    "ransomware": ["T1486", "T1490"],
    "lateral-movement": ["T1021", "T1021.002", "T1570"],
    "rdp-lateral": ["T1021", "T1021.001"],
    "ssh-lateral": ["T1021", "T1021.004"],
    "psexec": ["T1021", "T1021.002", "T1569"],
    "registry-persistence": ["T1547", "T1547.001"],
    "scheduled-task": ["T1053", "T1053.005"],
    "cron-persistence": ["T1053", "T1053.003"],
    "webshell": ["T1505", "T1505.003"],
    "phishing": ["T1566", "T1566.001"],
    "spearphishing": ["T1566", "T1566.001", "T1566.002"],
}


def get_ttps_for_attack_pattern(pattern_name: str) -> list[str]:
    """
    Get MITRE TTPs for an attack pattern.

    Args:
        pattern_name: Attack pattern name (e.g., "brute-force")

    Returns:
        List of technique IDs
    """
    return ATTACK_PATTERN_TTPS.get(pattern_name, [])

