"""CLI command handlers."""

from secgen.handlers.attack_handler import handle_attack
from secgen.handlers.describe_handler import handle_describe
from secgen.handlers.generate_handler import handle_generate
from secgen.handlers.list_handler import handle_list
from secgen.handlers.preset_handler import handle_preset
from secgen.handlers.test_handler import handle_test

__all__ = [
    "handle_list",
    "handle_describe",
    "handle_generate",
    "handle_attack",
    "handle_test",
    "handle_preset",
]
