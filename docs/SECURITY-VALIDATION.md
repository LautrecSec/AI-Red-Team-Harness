# Security Validation

The harness treats campaign configuration, target endpoints, scanner processes, and scanner output as separate trust boundaries.

## Local validation performed

The public reference implementation is checked for:

- unit and security regression tests
- Python syntax/bytecode compilation
- unsafe shell execution patterns (`shell=True`, `os.system`, `eval`, `exec`)
- hard-coded credential signatures
- path traversal in report output
- cloud metadata access
- private-network authorization bypass
- scanner executable path substitution
- inherited environment-variable leakage
- recursive secret redaction
- Terraform IAM wildcard allows and public egress defaults
- GitHub Actions token scope

## Continuous CI security scanning

The GitHub security workflow adds:

- Bandit Python static analysis
- pip-audit dependency vulnerability scanning
- Trivy filesystem and IaC scanning
- SARIF upload to GitHub code scanning

## Residual considerations

- DNS validation is re-run immediately before HTTP requests, but application-layer validation cannot fully eliminate every DNS rebinding race. Production deployments should combine this control with network egress restrictions.
- Pattern-based output redaction is defense in depth, not a substitute for preventing secrets from entering scanner output.
- External red-team tools execute third-party code. Run them in isolated tasks/containers with least privilege, explicit network policy, and only the credentials required by that scan.
