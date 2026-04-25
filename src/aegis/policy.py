from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


class PolicyError(ValueError):
    """Raised when an operation violates ethical targeting policy."""


def load_authorized_targets(path: str | Path) -> set[str]:
    """Load a minimal YAML-style allowlist with lines like `- example.com`."""
    raw = Path(path).read_text().splitlines()
    allowed: set[str] = set()
    for line in raw:
        stripped = line.strip()
        if stripped.startswith("-"):
            host = stripped[1:].strip().lower()
            if host:
                allowed.add(host)
    if not allowed:
        raise PolicyError("No authorized targets found in allowlist file")
    return allowed


def assert_target_authorized(target_url: str, allowed_hosts: set[str]) -> None:
    host = (urlparse(target_url).hostname or "").lower()
    if not host or host not in allowed_hosts:
        raise PolicyError(
            f"Target '{target_url}' is not authorized. Add hostname '{host}' to ethical_targets.yaml first."
        )
