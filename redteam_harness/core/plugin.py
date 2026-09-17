from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import AttackCase, AttackPhase, RunResult, Target


class AttackPlugin(ABC):
    name: str
    supported_phases: set[AttackPhase]

    @abstractmethod
    def generate_attacks(self, phase: AttackPhase, config: dict[str, Any]) -> list[AttackCase]:
        """Generate attack cases for a phase."""

    @abstractmethod
    def execute(
        self,
        attacks: list[AttackCase],
        target: Target,
        config: dict[str, Any],
    ) -> RunResult:
        """Execute attack cases and return normalized results."""
