#!/usr/bin/env python3
"""Dependency-free security sanity checks for the public reference repository."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "results"}
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
}
DANGEROUS_CALLS = {"eval", "exec"}


def python_files() -> list[Path]:
    return [
        p
        for p in ROOT.rglob("*.py")
        if not any(part in SKIP_PARTS for part in p.relative_to(ROOT).parts)
    ]


def scan_ast() -> list[str]:
    findings: list[str] = []
    for path in python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: use of {node.func.id}()")
            if isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if isinstance(owner, ast.Name) and owner.id == "os" and node.func.attr == "system":
                    findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: use of os.system()")
                if isinstance(owner, ast.Name) and owner.id == "subprocess" and node.func.attr in {
                    "run", "Popen", "call", "check_call", "check_output"
                }:
                    shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
                    if shell_kw is None or not isinstance(shell_kw.value, ast.Constant) or shell_kw.value.value is not False:
                        findings.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: subprocess call must set shell=False explicitly"
                        )
    return findings


def scan_secrets() -> list[str]:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    return findings


def scan_repo_controls() -> list[str]:
    findings: list[str] = []
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required in (".env", "*.tfstate", "results/", ".venv/"):
        if required not in gitignore:
            findings.append(f".gitignore missing {required!r}")

    terraform_vars = (ROOT / "deploy/terraform/variables.tf").read_text(encoding="utf-8")
    if 'variable "allowed_egress_cidrs"' not in terraform_vars or "default     = []" not in terraform_vars:
        findings.append("Terraform scanner egress is not deny-by-default")

    security_workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    if "persist-credentials: false" not in security_workflow:
        findings.append("Security workflow checkout persists credentials")
    return findings


def main() -> int:
    findings = scan_ast() + scan_secrets() + scan_repo_controls()
    if findings:
        print("Security sanity checks FAILED:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("Security sanity checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
