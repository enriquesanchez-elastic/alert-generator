"""Risk score generator for Entity Analytics."""

import random
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from secgen.generators.randomizers import RandomDataGenerator
from secgen.registry import GeneratorCategory, register_event_type

if TYPE_CHECKING:
    from secgen.models.entities import Host, User

RiskLevel = Literal["Low", "Medium", "High", "Critical"]


@register_event_type(
    name="risk-score",
    category=GeneratorCategory.ANALYTICS,
    description="Entity Analytics risk scores for hosts and users",
    ecs_fields=[
        "host.risk.calculated_score_norm",
        "host.risk.calculated_level",
        "user.risk.calculated_score_norm",
        "user.risk.calculated_level",
    ],
    index_pattern="logs-entity_analytics.risk-default",
    example_params={"entity_type": "host", "risk_level": "High"},
)
class RiskScoreGenerator:
    """
    Generator for creating Entity Analytics risk score events.

    Risk scores are critical for:
    - Entity Analytics dashboards
    - Prioritizing investigation
    - Identifying compromised accounts/hosts
    - Correlating alerts with entity risk
    """

    # Risk inputs by category
    RISK_INPUTS = {
        "alert": [
            {"name": "Malware Detection", "weight": 80},
            {"name": "Suspicious PowerShell", "weight": 60},
            {"name": "Credential Access", "weight": 70},
            {"name": "Lateral Movement", "weight": 75},
            {"name": "Data Exfiltration", "weight": 85},
            {"name": "Privilege Escalation", "weight": 70},
        ],
        "behavior": [
            {"name": "Unusual Login Hours", "weight": 30},
            {"name": "Unusual Location", "weight": 40},
            {"name": "High Volume File Access", "weight": 35},
            {"name": "Multiple Failed Logins", "weight": 45},
            {"name": "Unusual Process Execution", "weight": 50},
        ],
        "context": [
            {"name": "Asset Criticality", "weight": 20},
            {"name": "User Privilege Level", "weight": 25},
            {"name": "Recent Security Training", "weight": -10},
            {"name": "VPN Connection", "weight": 5},
        ],
    }

    # Risk level thresholds
    RISK_THRESHOLDS = {
        "Low": (0, 20),
        "Medium": (21, 50),
        "High": (51, 75),
        "Critical": (76, 100),
    }

    def __init__(self, randomizer: RandomDataGenerator | None = None) -> None:
        """Initialize risk score generator."""
        self.randomizer = randomizer or RandomDataGenerator()

    def generate(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        risk_level: RiskLevel | None = None,
        entity_type: str = "host",
        timestamp_offset: int = 0,
    ) -> dict[str, Any]:
        """
        Generate a risk score event.

        Args:
            host: Optional Host entity
            user: Optional User entity
            risk_level: Target risk level (or random)
            entity_type: Type of entity ("host" or "user")
            timestamp_offset: Minutes to offset timestamp

        Returns:
            ECS-compliant risk score event dictionary
        """
        now = datetime.now(timezone.utc) - timedelta(minutes=timestamp_offset)
        timestamp = now.isoformat()

        # Calculate risk score based on level
        if risk_level:
            min_score, max_score = self.RISK_THRESHOLDS[risk_level]
            score = random.randint(min_score, max_score)
        else:
            score = random.randint(0, 100)

        # Determine risk level from score
        calculated_level = self._score_to_level(score)

        # Generate risk inputs
        risk_inputs = self._generate_risk_inputs(score)

        # Build event
        event: dict[str, Any] = {
            "@timestamp": timestamp,
            "event": {
                "kind": "enrichment",
                "category": ["threat"],
                "type": ["indicator"],
                "action": "risk-score-calculated",
                "id": self.randomizer.generate_uuid(),
            },
            "ecs": {"version": "8.11.0"},
            "data_stream": {
                "type": "logs",
                "dataset": "entity_analytics.risk",
                "namespace": "default",
            },
        }

        # Add entity-specific fields
        if entity_type == "host":
            if host:
                event["host"] = {
                    "id": host.id,
                    "name": host.name,
                    "risk": {
                        "calculated_score_norm": score,
                        "calculated_level": calculated_level,
                        "static_score": random.randint(0, 30),
                        "static_score_norm": random.randint(0, 30),
                        "inputs": risk_inputs,
                    },
                }
            else:
                host_id = self.randomizer.generate_uuid()
                hostname = self.randomizer.generate_hostname()
                event["host"] = {
                    "id": host_id,
                    "name": hostname,
                    "risk": {
                        "calculated_score_norm": score,
                        "calculated_level": calculated_level,
                        "static_score": random.randint(0, 30),
                        "static_score_norm": random.randint(0, 30),
                        "inputs": risk_inputs,
                    },
                }
        else:  # user
            if user:
                event["user"] = {
                    "id": user.id,
                    "name": user.name,
                    "risk": {
                        "calculated_score_norm": score,
                        "calculated_level": calculated_level,
                        "static_score": random.randint(0, 30),
                        "static_score_norm": random.randint(0, 30),
                        "inputs": risk_inputs,
                    },
                }
            else:
                user_id = str(random.randint(1000, 65000))
                username = self.randomizer.generate_username()
                event["user"] = {
                    "id": user_id,
                    "name": username,
                    "risk": {
                        "calculated_score_norm": score,
                        "calculated_level": calculated_level,
                        "static_score": random.randint(0, 30),
                        "static_score_norm": random.randint(0, 30),
                        "inputs": risk_inputs,
                    },
                }

        return event

    def _score_to_level(self, score: int) -> RiskLevel:
        """Convert numeric score to risk level."""
        for level, (min_s, max_s) in self.RISK_THRESHOLDS.items():
            if min_s <= score <= max_s:
                return level
        return "Low"

    def _generate_risk_inputs(self, target_score: int) -> list[dict[str, Any]]:
        """Generate risk inputs that roughly sum to target score."""
        inputs = []
        remaining_score = target_score

        # Select random inputs from each category
        categories = ["alert", "behavior", "context"]
        random.shuffle(categories)

        for category in categories:
            if remaining_score <= 0:
                break

            available_inputs = self.RISK_INPUTS[category]
            num_inputs = random.randint(0, min(2, len(available_inputs)))

            for _ in range(num_inputs):
                if remaining_score <= 0:
                    break

                risk_input = random.choice(available_inputs)
                contribution = min(remaining_score, risk_input["weight"])

                inputs.append(
                    {
                        "id": self.randomizer.generate_uuid()[:8],
                        "index": ".alerts-security.alerts-default",
                        "category": category,
                        "description": risk_input["name"],
                        "risk_score": contribution,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

                remaining_score -= contribution

        return inputs

    def generate_batch(
        self,
        count: int,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        entity_type: str = "host",
        timestamp_spread_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """
        Generate a batch of risk score events.

        Args:
            count: Number of events to generate
            host: Optional Host entity (same for all if provided)
            user: Optional User entity (same for all if provided)
            entity_type: Type of entities to generate
            timestamp_spread_minutes: Time spread for events

        Returns:
            List of risk score event dictionaries
        """
        events = []

        for i in range(count):
            timestamp_offset = int((i / count) * timestamp_spread_minutes)

            event = self.generate(
                host=host if entity_type == "host" else None,
                user=user if entity_type == "user" else None,
                entity_type=entity_type,
                timestamp_offset=timestamp_offset,
            )
            events.append(event)

        return events

    def generate_high_risk_entity(
        self,
        host: Optional["Host"] = None,
        user: Optional["User"] = None,
        entity_type: str = "host",
    ) -> dict[str, Any]:
        """
        Generate a high-risk entity score event.

        Args:
            host: Optional Host entity
            user: Optional User entity
            entity_type: Type of entity

        Returns:
            Risk score event with High or Critical level
        """
        risk_level = random.choice(["High", "Critical"])
        return self.generate(
            host=host,
            user=user,
            risk_level=risk_level,
            entity_type=entity_type,
        )

