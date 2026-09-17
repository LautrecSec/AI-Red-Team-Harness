from __future__ import annotations

from redteam_harness.core.models import AttackPhase
from redteam_harness.core.subprocess_plugin import SafeSubprocessPlugin


class GarakPlugin(SafeSubprocessPlugin):
    name = "garak"
    executable = "garak"
    supported_phases = {
        AttackPhase.RECONNAISSANCE,
        AttackPhase.INITIAL_ACCESS,
        AttackPhase.PRIVILEGE_ESCALATION,
        AttackPhase.EXFILTRATION,
        AttackPhase.IMPACT,
    }
