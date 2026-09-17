# Security Audit

Date: 2026-09-17

This review covered the public reference implementation, its Python execution boundaries, HTTP target handling, result persistence, Terraform defaults, container posture, and GitHub Actions permissions.

## Validation completed

- 11 unit and security regression tests passed
- Python compile validation passed for application, tests, and security scripts
- dependency-free repository security sanity scan passed
- hard-coded credential signature scan passed
- unsafe shell/eval/exec pattern scan passed
- demo campaign validation passed
- end-to-end demo run produced JSON, SARIF, and HTML output successfully

## Issues identified and remediated

### 1. Scanner executable path substitution

**Risk:** A plugin command using a path such as `/tmp/promptfoo` could previously pass a basename check and execute an attacker-controlled binary.

**Remediation:** Plugin commands must now begin with the literal expected executable name, and execution is replaced with the binary resolved from `PATH`.

### 2. Excessive subprocess environment inheritance

**Risk:** Third-party scanner processes could inherit unrelated parent-process credentials such as cloud tokens.

**Remediation:** Scanner processes now receive a minimal base environment. Additional variables must be explicitly named in `plugin_config.pass_env`.

### 3. Redirect-based SSRF pivoting

**Risk:** An initially valid HTTP target could redirect the harness into a private or link-local trust zone.

**Remediation:** HTTP redirects are disabled for security-sensitive target requests.

### 4. Cloud metadata access with private-network opt-in

**Risk:** A private-network testing flag could also permit access to cloud instance metadata services.

**Remediation:** Known metadata destinations and link-local addresses are blocked regardless of private-network authorization.

### 5. Campaign-controlled private network access

**Risk:** If campaign YAML is treated as untrusted input, a YAML-only `allow_private_networks` flag is not a sufficient trust boundary.

**Remediation:** Private and loopback targets now require two independent conditions: `allow_private_networks: true` in the campaign and operator-controlled `REDTEAM_ALLOW_PRIVATE_NETWORKS=1` at runtime.

### 6. Sensitive environment expansion into campaign data

**Risk:** Secret-like environment variables could be interpolated into the in-memory campaign configuration and later surface in logs or downstream tool arguments.

**Remediation:** Secret-like environment variable names are rejected during campaign interpolation. Authentication belongs in `auth_env`, explicit scanner `pass_env`, or a cloud secret store.

### 7. Incomplete nested-result redaction

**Risk:** Result evidence or nested scanner output could contain credentials even when top-level process output was redacted.

**Remediation:** JSON, SARIF, HTML, scanner output, and nested result structures now use recursive redaction before persistence.

### 8. Broad Terraform egress default

**Risk:** The example scanner task previously defaulted HTTPS egress to `0.0.0.0/0`.

**Remediation:** Scanner egress now defaults to no rule. Authorized destination CIDRs must be provided explicitly.

### 9. S3 transport enforcement

**Risk:** Bucket encryption at rest did not itself require TLS for object access.

**Remediation:** The results bucket now has an explicit deny policy for insecure transport.

### 10. GitHub Actions token scope

**Risk:** Security workflow permissions were broader than required for every job, and checkout retained repository credentials.

**Remediation:** Default workflow permissions are read-only, SARIF write permission is scoped to the Trivy job, and checkout uses `persist-credentials: false`.

## Residual considerations

- DNS validation is repeated immediately before outbound HTTP requests, but application-layer validation cannot fully remove every DNS rebinding race. Production deployments should enforce network egress controls independently of the application.
- Pattern-based redaction is defense in depth. Sensitive material should not be sent to scanners unless it is required for the authorized assessment.
- Third-party scanner dependencies remain part of the supply-chain threat model. CI runs Bandit, pip-audit, and Trivy to catch code, dependency, filesystem, and IaC issues as the project evolves.
- GitHub Action release tags are used for maintainability. Higher-assurance deployments can pin actions to reviewed commit SHAs and update them through controlled dependency automation.
