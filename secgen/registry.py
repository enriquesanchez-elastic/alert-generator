"""Generator registry for event types and attack patterns.

This module provides a decorator-based registration system for generators,
enabling discovery and documentation of available event types and attack patterns
via the CLI.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TypeVar

# Type variable for decorated classes/functions
T = TypeVar("T")


class GeneratorCategory(Enum):
    """Categories for organizing generators."""

    ENDPOINT = "endpoint"
    NETWORK = "network"
    IDENTITY = "identity"
    CLOUD = "cloud"
    THREAT_INTEL = "threat_intel"
    SECURITY = "security"
    ANALYTICS = "analytics"


@dataclass
class EventTypeMetadata:
    """Metadata for a registered event type."""

    name: str
    category: GeneratorCategory
    description: str
    generator_class: type
    ecs_fields: list[str] = field(default_factory=list)
    index_pattern: str = ""
    example_params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for display."""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "ecs_fields": self.ecs_fields,
            "index_pattern": self.index_pattern,
            "example_params": self.example_params,
        }


@dataclass
class AttackPatternMetadata:
    """Metadata for a registered attack pattern."""

    name: str
    description: str
    ttps: list[str]  # MITRE ATT&CK TTPs
    generator_class: type
    method_name: str
    category: GeneratorCategory
    required_params: list[str] = field(default_factory=list)
    optional_params: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)
    detection_recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for display."""
        return {
            "name": self.name,
            "description": self.description,
            "ttps": self.ttps,
            "category": self.category.value,
            "method_name": self.method_name,
            "required_params": self.required_params,
            "optional_params": self.optional_params,
            "event_types": self.event_types,
            "detection_recommendations": self.detection_recommendations,
        }


class GeneratorRegistry:
    """Central registry for event type and attack pattern generators."""

    _instance: "GeneratorRegistry | None" = None
    _initialized: bool = False

    def __new__(cls) -> "GeneratorRegistry":
        """Singleton pattern to ensure single registry instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize registry (only once due to singleton)."""
        if not GeneratorRegistry._initialized:
            self._event_types: dict[str, EventTypeMetadata] = {}
            self._attack_patterns: dict[str, AttackPatternMetadata] = {}
            GeneratorRegistry._initialized = True

    def register_event_type(self, metadata: EventTypeMetadata) -> None:
        """Register an event type."""
        self._event_types[metadata.name] = metadata

    def register_attack_pattern(self, metadata: AttackPatternMetadata) -> None:
        """Register an attack pattern."""
        self._attack_patterns[metadata.name] = metadata

    def get_event_type(self, name: str) -> EventTypeMetadata | None:
        """Get event type metadata by name."""
        return self._event_types.get(name)

    def get_attack_pattern(self, name: str) -> AttackPatternMetadata | None:
        """Get attack pattern metadata by name."""
        return self._attack_patterns.get(name)

    def list_event_types(
        self, category: GeneratorCategory | None = None
    ) -> list[EventTypeMetadata]:
        """List all registered event types, optionally filtered by category."""
        types = list(self._event_types.values())
        if category:
            types = [t for t in types if t.category == category]
        return sorted(types, key=lambda t: (t.category.value, t.name))

    def list_attack_patterns(
        self,
        category: GeneratorCategory | None = None,
        ttp: str | None = None,
    ) -> list[AttackPatternMetadata]:
        """List all registered attack patterns, optionally filtered."""
        patterns = list(self._attack_patterns.values())
        if category:
            patterns = [p for p in patterns if p.category == category]
        if ttp:
            patterns = [p for p in patterns if ttp.upper() in [t.upper() for t in p.ttps]]
        return sorted(patterns, key=lambda p: (p.category.value, p.name))

    def list_categories(self) -> list[GeneratorCategory]:
        """List all categories that have registered generators."""
        categories = set()
        for evt in self._event_types.values():
            categories.add(evt.category)
        for atk in self._attack_patterns.values():
            categories.add(atk.category)
        return sorted(categories, key=lambda c: c.value)

    def get_generators_by_category(
        self, category: GeneratorCategory
    ) -> dict[str, list[str]]:
        """Get all generators for a category, grouped by type."""
        return {
            "event_types": [
                t.name for t in self._event_types.values() if t.category == category
            ],
            "attack_patterns": [
                p.name for p in self._attack_patterns.values() if p.category == category
            ],
        }

    def clear(self) -> None:
        """Clear all registrations (useful for testing)."""
        self._event_types.clear()
        self._attack_patterns.clear()


# Global registry instance
_registry = GeneratorRegistry()


def get_registry() -> GeneratorRegistry:
    """Get the global generator registry instance."""
    return _registry


def register_event_type(
    name: str,
    category: GeneratorCategory,
    description: str,
    ecs_fields: list[str] | None = None,
    index_pattern: str = "",
    example_params: dict[str, Any] | None = None,
) -> Callable[[type[T]], type[T]]:
    """
    Decorator to register an event type generator class.

    Args:
        name: Event type name (e.g., "dns", "process", "file")
        category: Generator category
        description: Human-readable description
        ecs_fields: List of primary ECS fields generated
        index_pattern: Elasticsearch index pattern
        example_params: Example parameters for generate()

    Returns:
        Class decorator

    Example:
        @register_event_type(
            name="dns",
            category=GeneratorCategory.NETWORK,
            description="DNS query events",
            ecs_fields=["dns.question.name", "dns.resolved_ip"],
            index_pattern="logs-dns.query-default",
        )
        class DNSEventGenerator:
            pass
    """

    def decorator(cls: type[T]) -> type[T]:
        metadata = EventTypeMetadata(
            name=name,
            category=category,
            description=description,
            generator_class=cls,
            ecs_fields=ecs_fields or [],
            index_pattern=index_pattern,
            example_params=example_params or {},
        )
        _registry.register_event_type(metadata)
        # Store metadata on class for introspection
        cls._event_type_metadata = metadata  # type: ignore
        return cls

    return decorator


def register_attack_pattern(
    name: str,
    description: str,
    ttps: list[str],
    category: GeneratorCategory,
    required_params: list[str] | None = None,
    optional_params: list[str] | None = None,
    event_types: list[str] | None = None,
    detection_recommendations: list[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to register an attack pattern method.

    Args:
        name: Attack pattern name (e.g., "brute-force", "dga-activity")
        description: Human-readable description
        ttps: List of MITRE ATT&CK TTPs (e.g., ["T1110.001", "T1110.003"])
        category: Generator category
        required_params: Required method parameters
        optional_params: Optional method parameters
        event_types: Event types generated by this pattern
        detection_recommendations: Detection rule recommendations

    Returns:
        Method decorator

    Example:
        @register_attack_pattern(
            name="brute-force",
            description="Password brute force attack",
            ttps=["T1110.001", "T1110.003"],
            category=GeneratorCategory.IDENTITY,
            required_params=["target_user", "host", "source_ip"],
        )
        def generate_brute_force(self, target_user, host, source_ip, ...):
            pass
    """

    def decorator(method: Callable[..., Any]) -> Callable[..., Any]:
        # We'll set generator_class later during bootstrap
        # when we can access the class that owns this method
        metadata = AttackPatternMetadata(
            name=name,
            description=description,
            ttps=ttps,
            generator_class=type(None),  # Placeholder, set during bootstrap
            method_name=method.__name__,
            category=category,
            required_params=required_params or [],
            optional_params=optional_params or [],
            event_types=event_types or [],
            detection_recommendations=detection_recommendations or [],
        )
        # Store metadata on method for later registration
        method._attack_pattern_metadata = metadata  # type: ignore
        return method

    return decorator


def finalize_attack_patterns(cls: type) -> None:
    """
    Finalize attack pattern registration for a class.

    Call this after defining a class to register all attack patterns
    with the correct generator_class reference.

    Args:
        cls: The generator class to scan for attack patterns
    """
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name, None)
        if attr and hasattr(attr, "_attack_pattern_metadata"):
            metadata: AttackPatternMetadata = attr._attack_pattern_metadata
            # Update with correct class reference
            metadata.generator_class = cls
            _registry.register_attack_pattern(metadata)


