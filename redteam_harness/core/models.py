from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class AttackPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    BENCHMARK = "benchmark"


@dataclass(frozen=True)
class Target:
    name: str
    type: str
    endpoint: str
    auth_env: str | None = None
    allow_private_networks: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackCase:
    id: str
    name: str
    phase: AttackPhase
    prompt: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    attack_id: str
    plugin: str
    phase: AttackPhase
    target: str
    success: bool
    score: float | None = None
    severity: str = "informational"
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        return data


@dataclass
class RunResult:
    plugin: str
    phase: AttackPhase
    target: str
    results: list[AttackResult]
    raw: dict[str, Any] = field(default_factory=dict)
