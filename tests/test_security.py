from __future__ import annotations

import os
from pathlib import Path

import pytest

from redteam_harness.core.config import load_campaign
from redteam_harness.core.models import AttackCase, AttackPhase, Target
from redteam_harness.core.security import redact_data, resolve_env_reference, validate_target_url
from redteam_harness.plugins.promptfoo import PromptfooPlugin


def test_inline_secret_rejected() -> None:
    with pytest.raises(ValueError):
        resolve_env_reference("not-a-reference")


def test_private_target_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError):
        validate_target_url("http://127.0.0.1:8080")
    with pytest.raises(ValueError):
        validate_target_url("http://127.0.0.1:8080", allow_private_networks=True)
    monkeypatch.setenv("REDTEAM_ALLOW_PRIVATE_NETWORKS", "1")
    validate_target_url("http://127.0.0.1:8080", allow_private_networks=True)


def test_metadata_endpoint_blocked_even_with_private_opt_in() -> None:
    with pytest.raises(ValueError):
        validate_target_url("http://169.254.169.254/latest/meta-data/", allow_private_networks=True)


def test_sensitive_env_not_expanded_into_campaign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_API_KEY", "do-not-inline")
    config = tmp_path / "campaign.yaml"
    config.write_text(
        "name: test\ntargets:\n  x:\n    endpoint: https://example.com/${MODEL_API_KEY}\n"
        "phases:\n  - {name: p, phase: benchmark, plugin: mock, target: x}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_campaign(config)


def test_recursive_redaction() -> None:
    value = {"nested": ["token=abc123", {"credential": "Bearer aaa.bbb.ccc"}]}
    redacted = redact_data(value)
    assert "abc123" not in str(redacted)
    assert "aaa.bbb.ccc" not in str(redacted)


def test_subprocess_command_rejects_path_alias(tmp_path: Path) -> None:
    plugin = PromptfooPlugin()
    target = Target(name="lab", type="http", endpoint="https://example.com")
    attacks = [AttackCase("1", "test", AttackPhase.BENCHMARK, "test")]
    with pytest.raises(ValueError):
        plugin.build_command(
            attacks,
            target,
            {"command": ["/tmp/promptfoo", "eval"]},
            tmp_path / "result.json",
        )


def test_subprocess_environment_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = PromptfooPlugin()
    monkeypatch.setenv("OPENAI_API_KEY", "secret-value")
    monkeypatch.setenv("UNRELATED_SECRET", "should-not-pass")
    env = plugin._subprocess_env({"pass_env": ["OPENAI_API_KEY"]})
    assert env["OPENAI_API_KEY"] == "secret-value"
    assert "UNRELATED_SECRET" not in env
    assert os.environ["UNRELATED_SECRET"] == "should-not-pass"
