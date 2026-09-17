from __future__ import annotations

import argparse
import json
from pathlib import Path

from redteam_harness.core.config import load_campaign, validate_campaign
from redteam_harness.core.orchestrator import run_campaign
from redteam_harness.core.registry import plugin_registry
from redteam_harness.core.reporting import write_html, write_json, write_sarif


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redteam", description="AI Red Team Harness")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run a campaign")
    run.add_argument("config")
    run.add_argument("--phase")
    run.add_argument("--target")
    run.add_argument("--output-dir", default="results")

    validate = sub.add_parser("validate", help="Validate a campaign YAML")
    validate.add_argument("config")

    list_plugins = sub.add_parser("list-plugins", help="List available plugins")
    list_plugins.add_argument("--phase")

    generate = sub.add_parser("generate-config", help="Write a safe starter campaign")
    generate.add_argument("-o", "--output", default="campaign.yaml")

    benchmark = sub.add_parser("benchmark", help="Run one campaign against multiple targets")
    benchmark.add_argument("config")
    benchmark.add_argument("--target", action="append", required=True)
    benchmark.add_argument("--output-dir", default="results")
    return parser


def _generate_config(path: Path) -> None:
    starter = """name: local-demo\ndescription: Safe local demonstration campaign\ntargets:\n  development:\n    name: mock-guardrail\n    type: http\n    endpoint: http://127.0.0.1:8080/v1/chat/completions\n    allow_private_networks: true\nphases:\n  - name: injection-demo\n    phase: initial_access\n    plugin: mock\n    target: development\n    plugin_config:\n      finding_contains: CANARY\n"""
    path.write_text(starter, encoding="utf-8")


def main() -> None:
    args = _parser().parse_args()
    if args.command == "validate":
        campaign = load_campaign(args.config)
        errors = validate_campaign(campaign)
        if errors:
            raise SystemExit("Invalid campaign:\n- " + "\n- ".join(errors))
        print("Campaign is valid")
        return

    if args.command == "list-plugins":
        items = plugin_registry()
        for name, cls in sorted(items.items()):
            phases = ", ".join(sorted(p.value for p in cls.supported_phases))
            if args.phase and args.phase not in phases:
                continue
            print(f"{name}: {phases}")
        return

    if args.command == "generate-config":
        _generate_config(Path(args.output))
        print(args.output)
        return

    campaign = load_campaign(args.config)
    errors = validate_campaign(campaign)
    if errors:
        raise SystemExit("Invalid campaign:\n- " + "\n- ".join(errors))

    if args.command == "run":
        outcome = run_campaign(campaign, target_override=args.target, phase_filter=args.phase)
        out = Path(args.output_dir)
        paths = [write_json(outcome, out), write_sarif(outcome, out), write_html(outcome, out)]
        print(json.dumps({"asr": outcome.attack_success_rate, "reports": [str(p) for p in paths]}, indent=2))
        return

    if args.command == "benchmark":
        summary = {}
        for target in args.target:
            outcome = run_campaign(campaign, target_override=target)
            target_dir = Path(args.output_dir) / target
            write_json(outcome, target_dir)
            write_sarif(outcome, target_dir)
            write_html(outcome, target_dir)
            summary[target] = outcome.attack_success_rate
        print(json.dumps(summary, indent=2))
