from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import AttackCase, AttackPhase, AttackResult, RunResult, Target
from .plugin import AttackPlugin
from .security import redact_data, redact_text

_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_BASE_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
)


class SafeSubprocessPlugin(AttackPlugin):
    executable: str

    def generate_attacks(self, phase: AttackPhase, config: dict[str, Any]) -> list[AttackCase]:
        prompts = config.get("prompts", [])
        return [
            AttackCase(
                id=f"{self.name}-{phase.value}-{i}",
                name=item.get("name", f"case-{i}"),
                phase=phase,
                prompt=item.get("prompt", ""),
                metadata=item.get("metadata", {}),
            )
            for i, item in enumerate(prompts, start=1)
        ]

    def build_command(
        self,
        attacks: list[AttackCase],
        target: Target,
        config: dict[str, Any],
        output_file: Path,
    ) -> list[str]:
        command = config.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError(
                f"{self.name} requires plugin_config.command as a non-empty argv list. "
                "Shell strings are intentionally rejected."
            )
        if command[0] != self.executable:
            raise ValueError(f"Command must start with the literal executable {self.executable!r}")
        substitutions = {
            "{endpoint}": target.endpoint,
            "{output}": str(output_file),
        }
        return [substitutions.get(arg, arg) for arg in command]

    def _subprocess_env(self, config: dict[str, Any]) -> dict[str, str]:
        env = {name: os.environ[name] for name in _BASE_ENV if name in os.environ}
        requested = config.get("pass_env", [])
        if not isinstance(requested, list) or not all(isinstance(name, str) for name in requested):
            raise ValueError("plugin_config.pass_env must be a list of environment-variable names")
        for name in requested:
            if not _ENV_NAME.fullmatch(name):
                raise ValueError(f"Invalid environment variable name in pass_env: {name!r}")
            if name in os.environ:
                env[name] = os.environ[name]
        return env

    def execute(
        self,
        attacks: list[AttackCase],
        target: Target,
        config: dict[str, Any],
    ) -> RunResult:
        executable_path = shutil.which(self.executable)
        if executable_path is None:
            raise RuntimeError(
                f"Required executable {self.executable!r} is not installed. "
                f"See docs/TOOLS.md for {self.name} setup."
            )

        timeout = int(config.get("timeout_seconds", 600))
        max_output_bytes = int(config.get("max_output_bytes", 5_000_000))
        if not 1 <= timeout <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        if not 1024 <= max_output_bytes <= 50_000_000:
            raise ValueError("max_output_bytes must be between 1024 and 50000000")

        with tempfile.TemporaryDirectory(prefix=f"redteam-{self.name}-") as tmp:
            output_file = Path(tmp) / "result.json"
            command = self.build_command(attacks, target, config, output_file)
            # Execute the binary resolved from PATH, never an attacker-controlled path with the same basename.
            command[0] = executable_path

            completed = subprocess.run(  # noqa: S603
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                env=self._subprocess_env(config),
            )
            stdout = redact_text(completed.stdout[:max_output_bytes])
            stderr = redact_text(completed.stderr[:max_output_bytes])
            raw: dict[str, Any] = {
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }
            if output_file.exists() and output_file.stat().st_size <= max_output_bytes:
                try:
                    raw["tool_output"] = redact_data(
                        json.loads(output_file.read_text(encoding="utf-8"))
                    )
                except json.JSONDecodeError:
                    raw["tool_output_text"] = redact_text(output_file.read_text(encoding="utf-8"))

            success = completed.returncode == 0
            results = [
                AttackResult(
                    attack_id=attack.id,
                    plugin=self.name,
                    phase=attack.phase,
                    target=target.name,
                    success=success,
                    severity="informational" if success else "medium",
                    summary=(
                        f"{self.name} completed successfully"
                        if success
                        else f"{self.name} exited with {completed.returncode}"
                    ),
                )
                for attack in attacks
            ]
            phase = attacks[0].phase if attacks else AttackPhase.BENCHMARK
            return RunResult(self.name, phase, target.name, results, raw=raw)
