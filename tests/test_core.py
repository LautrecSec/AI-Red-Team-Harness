from pathlib import Path

import pytest

from redteam_harness.core.config import load_campaign, validate_campaign
from redteam_harness.core.models import AttackPhase, AttackResult
from redteam_harness.core.orchestrator import CampaignOutcome, run_campaign
from redteam_harness.core.reporting import write_html, write_json, write_sarif
from redteam_harness.core.security import redact_text, safe_output_path


def test_demo_campaign_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDTEAM_ALLOW_PRIVATE_NETWORKS", "1")
    campaign = load_campaign("config/campaign.example.yaml")
    assert validate_campaign(campaign) == []
    outcome = run_campaign(campaign)
    assert outcome.results
    assert outcome.attack_success_rate > 0
    assert write_json(outcome, tmp_path).exists()
    assert write_sarif(outcome, tmp_path).exists()
    assert write_html(outcome, tmp_path).exists()


def test_redaction() -> None:
    text = "api_key=supersecret Authorization: Bearer abc.def.ghi"
    redacted = redact_text(text)
    assert "supersecret" not in redacted
    assert "abc.def.ghi" not in redacted


def test_report_redacts_result_evidence(tmp_path: Path) -> None:
    outcome = CampaignOutcome(
        "redaction-test",
        [
            AttackResult(
                attack_id="case-1",
                plugin="mock",
                phase=AttackPhase.BENCHMARK,
                target="test",
                success=True,
                summary="token=summary-secret",
                evidence={"authorization": "Bearer evidence.secret.value"},
            )
        ],
    )
    json_path = write_json(outcome, tmp_path)
    html_path = write_html(outcome, tmp_path)
    sarif_path = write_sarif(outcome, tmp_path)
    combined = json_path.read_text() + html_path.read_text() + sarif_path.read_text()
    assert "summary-secret" not in combined
    assert "evidence.secret.value" not in combined


def test_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        safe_output_path(tmp_path, "../escape.txt")
