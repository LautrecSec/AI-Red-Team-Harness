# Changelog

## 1.0.1

- Added visual reference architecture and HTML report dashboard assets
- Upgraded HTML reporting with campaign metrics, phase coverage, severity, and normalized findings
- Added operator-controlled private-network authorization gate
- Blocked cloud metadata destinations and HTTP redirects
- Isolated scanner subprocess environments with explicit `pass_env`
- Hardened scanner executable resolution and runtime bounds
- Added recursive result and evidence redaction
- Changed Terraform scanner egress to deny by default and enforced S3 TLS
- Reduced GitHub Actions token scope and disabled checkout credential persistence
- Added dependency-free repository security sanity scanner and expanded regression coverage

## 1.0.0

- Unified campaign CLI and normalized result model
- Promptfoo, Garak and PyRIT adapter interfaces
- Built-in deterministic mock plugin for end-to-end testing
- JSON, SARIF and HTML reports
- Target URL validation, output redaction and subprocess hardening
- Docker reference runtime
- AWS ECS Fargate Terraform reference deployment
- CI, dependency auditing, Bandit and Trivy security scanning
