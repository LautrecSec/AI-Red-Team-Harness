from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[^\s,;]+"),
]

_BLOCKED_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.google.internal.",
}
_BLOCKED_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/Azure/GCP-compatible metadata endpoint
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata endpoint
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS IPv6 endpoint
}


def resolve_env_reference(value: str | None) -> str | None:
    if value is None:
        return None
    if value.startswith("${") and value.endswith("}"):
        name = value[2:-1]
        if not name or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            raise ValueError(f"Invalid environment variable reference: {value}")
        return os.environ.get(name)
    raise ValueError("Secrets must be referenced as ${ENV_VAR}; inline secret values are rejected")


def redact_text(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_data(value: Any) -> Any:
    """Recursively redact string values before writing untrusted scanner data to disk."""
    if isinstance(value, dict):
        return {str(k): redact_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def safe_output_path(base: Path, name: str) -> Path:
    base = base.resolve()
    candidate = (base / name).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError("Refusing path traversal outside output directory")
    return candidate


def validate_target_url(url: str, allow_private_networks: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https targets are supported")
    if not parsed.hostname:
        raise ValueError("Target URL must contain a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in target URLs")
    if parsed.hostname.lower() in _BLOCKED_METADATA_HOSTS:
        raise ValueError("Cloud metadata endpoints are never valid red-team targets")

    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target host: {parsed.hostname}") from exc

    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if ip in _BLOCKED_METADATA_IPS:
            raise ValueError("Cloud metadata endpoints are never valid red-team targets")
        if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError(f"Target resolves to prohibited address {ip}")
        if ip.is_private or ip.is_loopback:
            runtime_opt_in = os.environ.get("REDTEAM_ALLOW_PRIVATE_NETWORKS") == "1"
            if not (allow_private_networks and runtime_opt_in):
                raise ValueError(
                    f"Target resolves to non-public address {ip}. Private targets require both "
                    "allow_private_networks: true in campaign YAML and the operator-controlled "
                    "REDTEAM_ALLOW_PRIVATE_NETWORKS=1 runtime opt-in."
                )
