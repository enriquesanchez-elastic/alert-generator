"""Tests for the generator registry system."""

import pytest

from secgen.registry import (
    GeneratorCategory,
    GeneratorRegistry,
    register_event_type,
    register_attack_pattern,
    finalize_attack_patterns,
    get_registry,
)


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset registry before each test."""
    registry = get_registry()
    registry.clear()
    yield
    registry.clear()


class TestGeneratorRegistry:
    """Tests for GeneratorRegistry class."""

    def test_singleton_pattern(self):
        """Registry should be a singleton."""
        registry1 = GeneratorRegistry()
        registry2 = GeneratorRegistry()
        assert registry1 is registry2

    def test_register_event_type(self):
        """Should register event types."""
        @register_event_type(
            name="test-event",
            category=GeneratorCategory.ENDPOINT,
            description="Test event type",
            ecs_fields=["field1", "field2"],
        )
        class TestGenerator:
            pass

        registry = get_registry()
        metadata = registry.get_event_type("test-event")

        assert metadata is not None
        assert metadata.name == "test-event"
        assert metadata.category == GeneratorCategory.ENDPOINT
        assert metadata.description == "Test event type"
        assert "field1" in metadata.ecs_fields

    def test_register_attack_pattern(self):
        """Should register attack patterns."""
        class TestGenerator:
            @register_attack_pattern(
                name="test-attack",
                description="Test attack pattern",
                ttps=["T1234"],
                category=GeneratorCategory.ENDPOINT,
            )
            def generate_attack(self):
                pass

        finalize_attack_patterns(TestGenerator)

        registry = get_registry()
        metadata = registry.get_attack_pattern("test-attack")

        assert metadata is not None
        assert metadata.name == "test-attack"
        assert "T1234" in metadata.ttps

    def test_list_event_types(self):
        """Should list all event types."""
        @register_event_type(
            name="test-event-1",
            category=GeneratorCategory.ENDPOINT,
            description="Test 1",
        )
        class TestGenerator1:
            pass

        @register_event_type(
            name="test-event-2",
            category=GeneratorCategory.NETWORK,
            description="Test 2",
        )
        class TestGenerator2:
            pass

        registry = get_registry()
        event_types = registry.list_event_types()

        assert len(event_types) == 2
        names = [e.name for e in event_types]
        assert "test-event-1" in names
        assert "test-event-2" in names

    def test_list_event_types_by_category(self):
        """Should filter event types by category."""
        @register_event_type(
            name="endpoint-event",
            category=GeneratorCategory.ENDPOINT,
            description="Endpoint",
        )
        class EndpointGen:
            pass

        @register_event_type(
            name="network-event",
            category=GeneratorCategory.NETWORK,
            description="Network",
        )
        class NetworkGen:
            pass

        registry = get_registry()
        endpoint_types = registry.list_event_types(category=GeneratorCategory.ENDPOINT)

        assert len(endpoint_types) == 1
        assert endpoint_types[0].name == "endpoint-event"

    def test_list_attack_patterns_by_ttp(self):
        """Should filter attack patterns by TTP."""
        class TestGenerator:
            @register_attack_pattern(
                name="attack-1",
                description="Attack 1",
                ttps=["T1110.001"],
                category=GeneratorCategory.IDENTITY,
            )
            def attack1(self):
                pass

            @register_attack_pattern(
                name="attack-2",
                description="Attack 2",
                ttps=["T1078"],
                category=GeneratorCategory.IDENTITY,
            )
            def attack2(self):
                pass

        finalize_attack_patterns(TestGenerator)

        registry = get_registry()
        # Filter by exact TTP
        patterns = registry.list_attack_patterns(ttp="T1110.001")

        assert len(patterns) == 1
        assert patterns[0].name == "attack-1"


class TestEventTypeDecorator:
    """Tests for @register_event_type decorator."""

    def test_decorator_preserves_class(self):
        """Decorator should return the original class unchanged."""
        @register_event_type(
            name="preserve-test",
            category=GeneratorCategory.ENDPOINT,
            description="Test",
        )
        class TestClass:
            def method(self):
                return "works"

        instance = TestClass()
        assert instance.method() == "works"

    def test_metadata_stored_on_class(self):
        """Metadata should be stored on class for introspection."""
        @register_event_type(
            name="meta-test",
            category=GeneratorCategory.ENDPOINT,
            description="Meta test",
        )
        class TestClass:
            pass

        assert hasattr(TestClass, "_event_type_metadata")
        assert TestClass._event_type_metadata.name == "meta-test"


class TestAttackPatternDecorator:
    """Tests for @register_attack_pattern decorator."""

    def test_decorator_preserves_method(self):
        """Decorator should preserve method functionality."""
        class TestGenerator:
            @register_attack_pattern(
                name="method-test",
                description="Test",
                ttps=["T1234"],
                category=GeneratorCategory.ENDPOINT,
            )
            def generate_attack(self, param):
                return f"executed with {param}"

        gen = TestGenerator()
        result = gen.generate_attack("test")
        assert result == "executed with test"

    def test_metadata_stored_on_method(self):
        """Metadata should be stored on method."""
        class TestGenerator:
            @register_attack_pattern(
                name="stored-test",
                description="Stored test",
                ttps=["T1234"],
                category=GeneratorCategory.ENDPOINT,
            )
            def generate_attack(self):
                pass

        assert hasattr(TestGenerator.generate_attack, "_attack_pattern_metadata")
        assert TestGenerator.generate_attack._attack_pattern_metadata.name == "stored-test"

