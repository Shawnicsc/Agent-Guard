"""Configuration migration must preserve protection modes and archived evidence."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from guard.config import Settings
from guard.contracts import ProtectionMode
from guard.llm.config import ProviderConfig, load_providers, resolve_provider
from guard.naming import archive_shards, canonical_arm, default_db_path, env_value


@pytest.fixture(autouse=True)
def clean_config_env(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith(("TRACESHIELD_", "AGENT_GUARD_")):
            monkeypatch.delenv(name)


def test_new_roles_mode_and_paths_override_legacy(monkeypatch, tmp_path):
    for prefix, task, semantic, mode in [
        ("AGENT_GUARD_", "local", "ark", "off"),
        ("TRACESHIELD_", "kimi", "auditor", "enforce"),
    ]:
        monkeypatch.setenv(prefix + "TASK_PROVIDER", task)
        monkeypatch.setenv(prefix + "SEMANTIC_PROVIDER", semantic)
        monkeypatch.setenv(prefix + "PROTECTION_MODE", mode)
        monkeypatch.setenv(prefix + "DB_PATH", str(tmp_path / (prefix + "audit.db")))
    settings = Settings()
    assert (settings.task_provider, settings.semantic_provider) == ("kimi", "auditor")
    assert settings.protection_mode is ProtectionMode.ENFORCE
    assert settings.db_path == tmp_path / "TRACESHIELD_audit.db"
    assert Settings(protection_mode="monitor").protection_mode is ProtectionMode.MONITOR


def test_legacy_settings_remain_usable_and_mode_is_validated(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_TASK_PROVIDER", "local")
    monkeypatch.setenv("AGENT_GUARD_PROTECTION_MODE", "monitor")
    monkeypatch.setenv("AGENT_GUARD_REHEARSAL_ENABLED", "true")
    settings = Settings()
    assert settings.task_provider == "local"
    assert settings.protection_mode is ProtectionMode.MONITOR
    assert settings.rehearsal_enabled is True
    monkeypatch.setenv("TRACESHIELD_PROTECTION_MODE", "invalid")
    with pytest.raises(ValidationError):
        Settings()


def test_key_lookup_prefers_new_name_even_when_empty(monkeypatch):
    monkeypatch.setenv("AGENT_GUARD_LOCAL_API_KEY", "legacy-test-value")
    provider = ProviderConfig(base_url="http://localhost", model="test",
                              api_key_env="TRACESHIELD_LOCAL_API_KEY")
    assert provider.api_key() == "legacy-test-value"
    monkeypatch.setenv("TRACESHIELD_LOCAL_API_KEY", "")
    assert provider.api_key() == ""
    assert env_value("AGENT_GUARD_LOCAL_API_KEY") == ""


def test_existing_database_is_discovered_without_copying(tmp_path):
    assert default_db_path(tmp_path) == tmp_path / "traceshield.db"
    legacy = tmp_path / "agent-guard.db"
    legacy.write_bytes(b"existing-audit-test")
    assert default_db_path(tmp_path) == legacy
    assert not (tmp_path / "traceshield.db").exists()
    current = tmp_path / "traceshield.db"
    current.write_bytes(b"new-audit-test")
    assert default_db_path(tmp_path) == current
    assert legacy.read_bytes() == b"existing-audit-test"


def test_archives_support_both_names_without_double_counting(tmp_path):
    for filename in ["bankfull_agent_guard_shard0.json",
                     "bankfull_agent_guard_shard1.json",
                     "bankfull_traceshield_shard0.json",
                     "bankfull_agent_guard_monitor_shard0.json"]:
        (tmp_path / filename).write_text("{}")
    expected = [tmp_path / "bankfull_traceshield_shard0.json",
                tmp_path / "bankfull_agent_guard_shard1.json"]
    assert archive_shards(tmp_path, "traceshield") == expected
    assert archive_shards(tmp_path, "agent_guard") == expected
    assert canonical_arm("agent_guard_monitor") == "traceshield_monitor"
    assert archive_shards(tmp_path, "traceshield_monitor") == [
        tmp_path / "bankfull_agent_guard_monitor_shard0.json"]


def test_provider_example_and_dependency_names_are_consistent():
    import json
    import tomllib

    root = Path(__file__).resolve().parents[1]
    providers = load_providers(root / "configs/providers.yaml")
    assert resolve_provider(providers, "deepseek")[0] == "deepseek"
    with pytest.raises(ValueError, match="auditor"):
        resolve_provider(providers, "auditor")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    assert project["project"]["name"] == "traceshield"
    assert next(p["name"] for p in lock["package"] if p.get("source") == {
        "editable": "."}) == "traceshield"
    package = json.loads((root / "console/package.json").read_text(encoding="utf-8"))
    npm_lock = json.loads((root / "console/package-lock.json").read_text(encoding="utf-8"))
    assert package["name"] == npm_lock["name"] == "traceshield-console"
    assert npm_lock["packages"][""]["name"] == package["name"]
