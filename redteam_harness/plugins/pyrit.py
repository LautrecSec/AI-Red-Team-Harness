from __future__ import annotations

from redteam_harness.core.models import AttackPhase
from redteam_harness.core.subprocess_plugin import SafeSubprocessPlugin


class PyRITPlugin(SafeSubprocessPlugin):
    name = "pyrit"
    executable = "pyrit"
    supported_phases = {
        AttackPhase.PRIVILEGE_ESCALATION,
        AttackPhase.PERSISTENCE,
        AttackPhase.EXFILTRATION,
    }
