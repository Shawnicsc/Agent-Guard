"""CVE 复现场景确定性验收（独立工作场景）。

每个 YAML 场景使用 policies/cve_repro.yaml 专用策略与临时工作区，
不影响默认策略下的其他测试。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "examples" / "scenarios"))

from runner import run_direct_scenario  # noqa: E402

from guard.config import settings  # noqa: E402

SCENARIOS = sorted((PROJECT_ROOT / "examples" / "cve_scenarios").glob("*.yaml"))


def test_cve_scenarios_present() -> None:
    assert len(SCENARIOS) >= 5, "赛题要求至少复现 5 个 CVE 场景"


@pytest.mark.parametrize("scenario_path", SCENARIOS, ids=lambda p: p.stem)
def test_cve_scenario(scenario_path: Path, store, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "workspaces_root", tmp_path / "workspaces")
    scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    assert scenario["policy"] == "policies/cve_repro.yaml"
    rc, info = run_direct_scenario(scenario, store)
    assert rc == 0, f"场景验收失败: {info['failures']}"
    # 每个攻击场景必须产生完整的审计链与溯源 DAG
    assert not info["failures"]
