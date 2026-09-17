from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import get_target
from .models import AttackPhase, AttackResult
from .registry import get_plugin
from .security import validate_target_url


@dataclass
class CampaignOutcome:
    name: str
    results: list[AttackResult]

    @property
    def attack_success_rate(self) -> float:
        if not self.results:
            return 0.0
        return round(sum(result.success for result in self.results) / len(self.results) * 100, 2)


def run_campaign(
    campaign: dict[str, Any],
    target_override: str | None = None,
    phase_filter: str | None = None,
) -> CampaignOutcome:
    results: list[AttackResult] = []

    for phase_config in campaign.get("phases", []):
        if phase_filter and phase_config["phase"] != phase_filter:
            continue

        phase = AttackPhase(phase_config["phase"])
        plugin = get_plugin(phase_config["plugin"])
        if phase not in plugin.supported_phases:
            raise ValueError(f"Plugin {plugin.name} does not support phase {phase.value}")

        target_name = target_override or phase_config["target"]
        target = get_target(campaign, target_name)
        validate_target_url(target.endpoint, target.allow_private_networks)

        config = phase_config.get("plugin_config", {})
        attacks = plugin.generate_attacks(phase, config)
        run = plugin.execute(attacks, target, config)
        results.extend(run.results)

    return CampaignOutcome(campaign.get("name", "unnamed"), results)
