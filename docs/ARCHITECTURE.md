# Architecture

The harness separates orchestration from individual attack engines. Tool adapters are untrusted execution boundaries: they run with explicit argv arrays, bounded runtime, bounded output, a minimal inherited environment, and report redaction.

![AI Red Team Harness architecture](images/architecture.png)

## Security boundaries

1. **Campaign config**: parsed with `yaml.safe_load`. Secret-like environment variables are not expanded into campaign data.
2. **Target endpoints**: metadata, link-local, multicast and reserved ranges are blocked. Private/loopback destinations require both campaign opt-in and the operator-controlled `REDTEAM_ALLOW_PRIVATE_NETWORKS=1` runtime gate.
3. **HTTP redirects**: disabled so an initially validated target cannot redirect the harness into another trust zone.
4. **Plugin execution**: shell invocation is prohibited. Commands are argv arrays, must start with the expected binary name, and execute the binary resolved from `PATH`.
5. **Plugin environment**: child processes receive a minimal base environment plus only variables named in `plugin_config.pass_env`.
6. **Secrets**: API secrets are expected through adapter `auth_env`, explicit plugin `pass_env`, or a runtime secret store, never inline campaign YAML.
7. **Results**: nested result data and common secret/token patterns are recursively redacted before persistence.
8. **Reports**: generated into a constrained output directory to prevent path traversal.
9. **Cloud controls**: reference Terraform defaults task egress to deny, enforces S3 TLS, blocks public bucket access, and uses separate ECS execution/task roles.

## Residual network consideration

Target DNS is revalidated immediately before each HTTP request, but application-layer checks cannot eliminate every possible DNS-rebinding race. Production use should pair application checks with private subnets, explicit security-group egress, NAT/proxy policy, DNS controls, or VPC endpoints appropriate to the environment.
