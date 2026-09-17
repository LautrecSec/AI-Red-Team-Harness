from __future__ import annotations

from redteam_harness.plugins.garak import GarakPlugin
from redteam_harness.plugins.mock import MockPlugin
from redteam_harness.plugins.promptfoo import PromptfooPlugin
from redteam_harness.plugins.pyrit import PyRITPlugin

from .plugin import AttackPlugin


def plugin_registry() -> dict[str, type[AttackPlugin]]:
    return {
        "mock": MockPlugin,
        "promptfoo": PromptfooPlugin,
        "garak": GarakPlugin,
        "pyrit": PyRITPlugin,
    }


def get_plugin(name: str) -> AttackPlugin:
    cls = plugin_registry().get(name)
    if cls is None:
        raise ValueError(f"Unknown plugin {name!r}. Available: {', '.join(sorted(plugin_registry()))}")
    return cls()
