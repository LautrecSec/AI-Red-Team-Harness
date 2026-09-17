from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from .models import Target
from .security import redact_data, redact_text, validate_target_url


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "Redirects are disabled for security-sensitive target requests",
            headers,
            fp,
        )


_OPENER = urllib.request.build_opener(_NoRedirectHandler())


class TargetAdapter(ABC):
    def __init__(self, target: Target) -> None:
        self.target = target
        validate_target_url(target.endpoint, target.allow_private_networks)

    @abstractmethod
    def send(self, prompt: str, timeout_seconds: int = 30) -> dict[str, Any]:
        """Send one lab-safe test prompt to the authorized target."""

    def _open(self, request: urllib.request.Request, timeout_seconds: int):
        # Re-resolve immediately before each request to narrow DNS-rebinding/TOCTOU exposure.
        # Redirects are disabled to prevent a validated endpoint from pivoting into another trust zone.
        validate_target_url(self.target.endpoint, self.target.allow_private_networks)
        return _OPENER.open(request, timeout=timeout_seconds)  # noqa: S310


class HttpJsonAdapter(TargetAdapter):
    def send(self, prompt: str, timeout_seconds: int = 30) -> dict[str, Any]:
        headers = {"content-type": "application/json", "user-agent": "ai-redteam-harness/1.0"}
        if self.target.auth_env:
            token = os.environ.get(self.target.auth_env)
            if not token:
                raise RuntimeError(f"Required auth environment variable {self.target.auth_env!r} is unset")
            headers["authorization"] = f"Bearer {token}"

        body = json.dumps({"prompt": prompt}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - URL validated before request
            self.target.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with self._open(request, timeout_seconds) as response:
                raw = response.read(1_000_001)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Target request failed: {redact_text(str(exc))}") from exc

        if len(raw) > 1_000_000:
            raise RuntimeError("Target response exceeded 1 MB limit")
        try:
            return redact_data(json.loads(raw.decode("utf-8")))
        except json.JSONDecodeError:
            return {"text": redact_text(raw.decode("utf-8", errors="replace"))}


class OpenAICompatibleAdapter(HttpJsonAdapter):
    def send(self, prompt: str, timeout_seconds: int = 30) -> dict[str, Any]:
        headers = {"content-type": "application/json", "user-agent": "ai-redteam-harness/1.0"}
        if self.target.auth_env:
            token = os.environ.get(self.target.auth_env)
            if not token:
                raise RuntimeError(f"Required auth environment variable {self.target.auth_env!r} is unset")
            headers["authorization"] = f"Bearer {token}"

        payload = {
            "model": self.target.metadata.get("model", "security-test-target"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        request = urllib.request.Request(  # noqa: S310 - URL validated before request
            self.target.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with self._open(request, timeout_seconds) as response:
                raw = response.read(1_000_001)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Target request failed: {redact_text(str(exc))}") from exc
        if len(raw) > 1_000_000:
            raise RuntimeError("Target response exceeded 1 MB limit")
        return redact_data(json.loads(raw.decode("utf-8")))


class GrpcAdapter(TargetAdapter):
    def send(self, prompt: str, timeout_seconds: int = 30) -> dict[str, Any]:
        raise NotImplementedError(
            "gRPC transport is intentionally interface-only in the public reference implementation. "
            "Add your generated client in a private/environment-specific adapter."
        )


def get_target_adapter(target: Target) -> TargetAdapter:
    adapters: dict[str, type[TargetAdapter]] = {
        "http": HttpJsonAdapter,
        "openai_compatible": OpenAICompatibleAdapter,
        "grpc": GrpcAdapter,
    }
    adapter = adapters.get(target.type)
    if adapter is None:
        raise ValueError(f"Unsupported target adapter type: {target.type}")
    return adapter(target)
