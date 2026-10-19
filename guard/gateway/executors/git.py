"""受控 Git 执行器：git.push 只经本通道执行（DESIGN.md 第 8 节）。

推送目标与授权由策略引擎裁决；执行器只负责在受控环境内调起 git，
不解析凭证、不放开额外网络。
"""

from __future__ import annotations

import subprocess

from guard.contracts import ToolResult

GIT_TIMEOUT_S = 30


class GitExecutor:
    def __init__(self, workspace_root) -> None:
        self.workspace_root = workspace_root

    def push(self, remote: str, branch: str) -> ToolResult:
        if not self._is_repo():
            return ToolResult(ok=False, error="工作区不是 Git 仓库")
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.workspace_root), "push", remote, branch],
                capture_output=True, timeout=GIT_TIMEOUT_S, text=True,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, error="git push 超时")
        output = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return ToolResult(ok=(proc.returncode == 0), output=output[:4000],
                         error=f"exit={proc.returncode}")

    def _is_repo(self) -> bool:
        proc = subprocess.run(
            ["git", "-C", str(self.workspace_root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, timeout=10, text=True,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "true"
