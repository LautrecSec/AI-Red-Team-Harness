from __future__ import annotations

from redteam_harness.core.models import AttackPhase
from redteam_harness.core.subprocess_plugin import SafeSubprocessPlugin


class PromptfooPlugin(SafeSubprocessPlugin):
    name = "promptfoo"
    executable = "promptfoo"
    supported_phases = {
        AttackPhase.INITIAL_ACCESS,
        AttackPhase.BENCHMARK,
        AttackPhase.EXFILTRATION,
        AttackPhase.IMPACT,
    }
