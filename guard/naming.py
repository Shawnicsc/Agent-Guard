"""TraceShield names with read compatibility for existing deployments and archives."""

from __future__ import annotations

import os
from pathlib import Path

ENV_PREFIX = "TRACESHIELD_"
LEGACY_ENV_PREFIX = "AGENT_GUARD_"
LEGACY_ARMS = {
    "traceshield": "agent_guard",
    "traceshield_monitor": "agent_guard_monitor",
}


def env_value(name: str, default: str | None = None) -> str | None:
    """The new variable wins, including an explicitly empty value."""
    if name.startswith(LEGACY_ENV_PREFIX):
        name = ENV_PREFIX + name[len(LEGACY_ENV_PREFIX):]
    if name in os.environ:
        return os.environ[name]
    if name.startswith(ENV_PREFIX):
        legacy = LEGACY_ENV_PREFIX + name[len(ENV_PREFIX):]
        return os.environ.get(legacy, default)
    return os.environ.get(name, default)


def default_db_path(root: Path) -> Path:
    """New installs use the new filename; existing audit data remains discoverable."""
    current = root / "traceshield.db"
    legacy = root / "agent-guard.db"
    return legacy if not current.exists() and legacy.is_file() else current


def canonical_arm(name: str) -> str:
    return next((current for current, legacy in LEGACY_ARMS.items() if name == legacy), name)


def archive_shards(directory: Path, arm: str) -> list[Path]:
    """Read either naming scheme, preferring the new file for the same shard."""
    arm = canonical_arm(arm)
    names = [LEGACY_ARMS[arm], arm] if arm in LEGACY_ARMS else [arm]
    selected: dict[str, Path] = {}
    for name in names:
        for path in sorted(directory.glob(f"bankfull_{name}_shard*.json")):
            selected[path.name.split("_shard", 1)[1]] = path
    return [selected[key] for key in sorted(selected)]
