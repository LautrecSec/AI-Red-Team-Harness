from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .models import Target

_ENV = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
_SENSITIVE_ENV = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|SESSION|AUTH)", re.IGNORECASE)


def _expand_env(obj: Any) -> Any:
    """Expand non-secret environment references while keeping credentials out of campaign data."""
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env(v) for v in obj]
    if isinstance(obj, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if _SENSITIVE_ENV.search(name):
                raise ValueError(
                    f"Sensitive environment variable {name!r} must not be expanded into campaign data; "
                    "use auth_env or plugin pass_env instead"
                )
            return os.environ.get(name, match.group(0))

        return _ENV.sub(replace, obj)
    return obj


def load_campaign(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Campaign configuration must be a YAML mapping")
    return _expand_env(data)


def get_target(campaign: dict[str, Any], name: str) -> Target:
    targets = campaign.get("targets", {})
    raw = targets.get(name)
    if not isinstance(raw, dict):
        raise ValueError(f"Unknown target: {name}")
    return Target(
        name=raw.get("name", name),
        type=raw.get("type", "http"),
        endpoint=raw["endpoint"],
        auth_env=raw.get("auth_env"),
        allow_private_networks=bool(raw.get("allow_private_networks", False)),
        metadata=raw.get("metadata", {}),
    )


def validate_campaign(campaign: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not campaign.get("name"):
        errors.append("missing campaign name")
    targets = campaign.get("targets")
    if not isinstance(targets, dict) or not targets:
        errors.append("at least one target is required")

    phases = campaign.get("phases")
    if not isinstance(phases, list) or not phases:
        errors.append("at least one phase is required")
    else:
        for i, phase in enumerate(phases):
            if not isinstance(phase, dict):
                errors.append(f"phases[{i}] must be a mapping")
                continue
            for key in ("name", "phase", "plugin", "target"):
                if key not in phase:
                    errors.append(f"phases[{i}] missing {key}")
            target = phase.get("target")
            if isinstance(targets, dict) and target and target not in targets:
                errors.append(f"phases[{i}] references unknown target {target!r}")
    return errors
