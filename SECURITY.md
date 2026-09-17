# Security Policy

PromptStrike-style payloads and red-team scanners can create dangerous execution paths if orchestration is treated as trusted glue. This reference implementation therefore treats target selection, scanner processes, and scanner output as security boundaries.

## Reporting a vulnerability

Please report security issues privately to the repository owner rather than opening a public issue containing exploit details or credentials.

## Built-in controls

- no shell-based scanner execution
- exact scanner executable enforcement
- minimal subprocess environment with explicit `pass_env`
- cloud metadata and link-local target blocking
- two-part private-network authorization gate
- HTTP redirect denial
- bounded scanner runtime and output size
- recursive result redaction
- report path confinement
- deny-by-default Terraform scanner egress
- S3 public-access blocking and TLS enforcement
- least-privilege GitHub Actions permissions

## Continuous scanning

The repository workflow runs Bandit, pip-audit and Trivy, with SARIF uploaded to GitHub code scanning where available. A dependency-free local sanity scanner is also provided at `scripts/security_sanity.py`.

## Scope

This is a public reference implementation. Do not commit real customer data, private prompts, production endpoints, cloud account identifiers, API credentials, or internal findings.
