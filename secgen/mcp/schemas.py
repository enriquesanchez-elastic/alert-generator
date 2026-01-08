"""JSON schemas for MCP tool arguments.

This module defines JSON schemas for input validation of all MCP tools.
Schemas follow the JSON Schema specification and are used by the MCP server
to validate tool arguments before execution.
"""

from typing import Any

# ============================================================================
# DISCOVERY TOOLS
# ============================================================================

LIST_EVENT_TYPES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {
            "type": "string",
            "enum": [
                "endpoint",
                "network",
                "identity",
                "cloud",
                "threat_intel",
                "security",
                "analytics",
            ],
            "description": "Filter by category (optional)",
        }
    },
}

LIST_ATTACK_PATTERNS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {
            "type": "string",
            "enum": [
                "endpoint",
                "network",
                "identity",
                "cloud",
                "threat_intel",
                "security",
                "analytics",
            ],
            "description": "Filter by category (optional)",
        },
        "ttp": {
            "type": "string",
            "description": "Filter by MITRE ATT&CK TTP (e.g., 'T1110') (optional)",
        },
    },
}

DESCRIBE_EVENT_TYPE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Event type name (e.g., 'dns', 'file', 'process')",
        }
    },
    "required": ["name"],
}

DESCRIBE_ATTACK_PATTERN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Attack pattern name (e.g., 'brute-force', 'c2-beacon')",
        }
    },
    "required": ["name"],
}

# ============================================================================
# GENERATION TOOLS
# ============================================================================

GENERATE_EVENTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "event_type": {
            "type": "string",
            "description": "Event type to generate (e.g., 'dns', 'file', 'process')",
        },
        "count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 10000,
            "default": 10,
            "description": "Number of events to generate",
        },
        "use_world": {
            "type": "boolean",
            "default": True,
            "description": "Use World state for entity correlation (recommended)",
        },
        "params": {
            "type": "object",
            "description": "Generator-specific parameters (e.g., {'is_malicious': true})",
        },
    },
    "required": ["event_type"],
}

EXECUTE_ATTACK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "pattern": {
            "type": "string",
            "description": "Attack pattern name (e.g., 'brute-force', 'c2-beacon')",
        },
        "count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 1,
            "description": "Number of attack iterations",
        },
        "use_world": {
            "type": "boolean",
            "default": True,
            "description": "Use World state (recommended for attack patterns)",
        },
    },
    "required": ["pattern"],
}

GENERATE_CAMPAIGN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "num_hosts": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 5,
            "description": "Number of hosts to target in campaign",
        },
        "num_alerts": {
            "type": "integer",
            "minimum": 5,
            "maximum": 1000,
            "default": 20,
            "description": "Number of alerts to generate",
        },
        "attack_speed": {
            "type": "string",
            "enum": ["fast", "medium", "slow"],
            "default": "medium",
            "description": "Campaign speed (affects time distribution)",
        },
        "time_spread": {
            "type": "string",
            "enum": ["minutes", "hours", "days", "weeks"],
            "default": "hours",
            "description": "Time distribution for campaign events",
        },
    },
}

# ============================================================================
# WORLD STATE TOOLS
# ============================================================================

CREATE_WORLD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "num_hosts": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1000,
            "default": 10,
            "description": "Number of hosts to generate",
        },
        "num_users": {
            "type": "integer",
            "minimum": 1,
            "maximum": 5000,
            "default": 20,
            "description": "Number of users to generate",
        },
        "reset": {
            "type": "boolean",
            "default": False,
            "description": "Reset existing World if present",
        },
    },
}

GET_WORLD_INFO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
}

SAVE_WORLD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "file_path": {
            "type": "string",
            "description": "Path to save World state (e.g., 'world.json')",
        }
    },
    "required": ["file_path"],
}

LOAD_WORLD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "file_path": {
            "type": "string",
            "description": "Path to load World state from (e.g., 'world.json')",
        }
    },
    "required": ["file_path"],
}

# ============================================================================
# TESTING TOOLS
# ============================================================================

TEST_ELASTIC_FEATURE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "feature": {
            "type": "string",
            "enum": [
                "network-map",
                "timeline",
                "analyzer",
                "entity-analytics",
                "detection-rule",
                "vulnerability-management",
                "cloud-posture",
            ],
            "description": "Elastic Security feature to test",
        },
        "count": {
            "type": "integer",
            "minimum": 10,
            "maximum": 10000,
            "description": "Override default event count (optional)",
        },
    },
    "required": ["feature"],
}

# ============================================================================
# UTILITY TOOLS
# ============================================================================

VALIDATE_ELASTICSEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
}

GET_CAPABILITIES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
}

INDEX_EVENTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "enable_indexing": {
            "type": "boolean",
            "description": "Explicitly enable Elasticsearch indexing (required=true)",
        },
        "confirm": {
            "type": "boolean",
            "description": "Confirmation flag (required=true)",
        },
    },
    "required": ["enable_indexing", "confirm"],
}

# ============================================================================
# CORRELATED ATTACK TOOLS
# ============================================================================

GENERATE_CORRELATED_ATTACK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "attack_type": {
            "type": "string",
            "enum": [
                "brute-force",
                "c2-beacon",
                "dga",
                "lateral-movement",
                "data-exfiltration",
                "malware-drop",
                "ransomware",
                "webshell",
            ],
            "description": "Type of attack to simulate",
        },
        "source_event_count": {
            "type": "integer",
            "minimum": 5,
            "maximum": 100,
            "default": 20,
            "description": "Number of source Beat events to generate",
        },
        "generate_discovery": {
            "type": "boolean",
            "default": True,
            "description": "Generate Attack Discovery document",
        },
        "generate_case": {
            "type": "boolean",
            "default": True,
            "description": "Generate Security Case",
        },
    },
    "required": ["attack_type"],
}

GENERATE_ATTACK_DISCOVERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "attack_pattern": {
            "type": "string",
            "description": "Attack pattern name (e.g., 'brute-force', 'c2-beacon')",
        },
        "alert_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of alert UUIDs to link to this discovery",
        },
    },
    "required": ["attack_pattern"],
}

GENERATE_CASE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "template": {
            "type": "string",
            "enum": [
                "brute-force-investigation",
                "malware-incident",
                "data-exfiltration-investigation",
                "lateral-movement-investigation",
                "ransomware-incident",
                "c2-investigation",
            ],
            "description": "Case template to use",
        },
        "title": {
            "type": "string",
            "description": "Custom case title (optional, overrides template)",
        },
        "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
            "default": "medium",
            "description": "Case severity",
        },
        "alert_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of alert UUIDs to attach",
        },
        "attack_discovery_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of attack discovery IDs to link",
        },
    },
}

GENERATE_BEAT_EVENTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "beat_type": {
            "type": "string",
            "enum": ["auditbeat", "packetbeat", "filebeat"],
            "description": "Type of Beat events to generate",
        },
        "count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1000,
            "default": 20,
            "description": "Number of events to generate",
        },
        "is_malicious": {
            "type": "boolean",
            "default": False,
            "description": "Generate malicious/suspicious events",
        },
        "dataset": {
            "type": "string",
            "description": "Specific dataset (e.g., 'auditd', 'dns', 'system.auth')",
        },
    },
    "required": ["beat_type"],
}
