# Threat Model

## Assets

- Model/guardrail credentials
- Production and staging endpoints
- Red-team findings and transcripts
- CI/CD identity and cloud deployment permissions
- Attack-tool containers and dependencies

## Primary threats

| Threat | Example | Control |
|---|---|---|
| SSRF / internal target abuse | Campaign points to cloud metadata or localhost | Public IP validation by default, explicit private-network opt-in |
| Secret leakage | Tool output prints bearer token | Redaction before persistence, runtime secret injection |
| Command injection | Config contains `; curl ...` | No shell execution, argv list only, executable allow-list |
| Unbounded scans | Plugin hangs or produces GBs of logs | Timeout and output-size limits |
| Dependency compromise | Malicious package or image | CI dependency audit, Trivy, immutable ECR tags, image scanning |
| Over-privileged cloud task | Harness can mutate unrelated resources | Dedicated ECS task role, least privilege, no static cloud keys |
| Finding data exposure | Public result bucket | S3 public access block, server-side encryption, versioning |

## Deliberate non-goals

This repository is a reference implementation. It does not include production credentials, proprietary prompts, internal endpoints, customer data, or organization-specific detection content.
