"""独立确认：批准记录绑定工具、参数摘要、用户与有效期。

批准按 (tool, arguments_hash) 精确绑定：Agent 重试同一调用（新 call_id）
仍有效；参数变化 -> 哈希不一致 -> 立即失效并重新裁决。
call_id 保留为签发来源，仅用于审计溯源。
"""

from __future__ import annotations

from datetime import timedelta

from guard.audit.store import AuditStore
from guard.contracts import new_id, utcnow

APPROVAL_TTL_S = 300


class ApprovalRecord:
    def __init__(self, approval_id: str, call_id: str, arguments_hash: str,
                 target: str, user_id: str) -> None:
        self.approval_id = approval_id or new_id("appr")
        self.call_id = call_id
        self.arguments_hash = arguments_hash
        self.target = target
        self.user_id = user_id
        self.status = "pending"
        self.created_at = utcnow()
        self.expires_at = self.created_at + timedelta(seconds=APPROVAL_TTL_S)

    @property
    def expired(self) -> bool:
        return utcnow() > self.expires_at

    def tool(self) -> str:
        """签发时的目标工具名（target 格式为 '<tool> {参数...}'）。"""
        return self.target.split(" ", 1)[0] if self.target else ""

    def is_valid_for(self, tool: str, arguments_hash: str, user_id: str) -> bool:
        return (
            self.status == "approved"
            and not self.expired
            and self.tool() == tool
            and self.arguments_hash == arguments_hash
            and self.user_id == user_id
        )

    def to_row(self) -> tuple:
        return (self.approval_id, self.call_id, self.arguments_hash, self.target,
                self.user_id, self.status, self.created_at.isoformat(),
                self.expires_at.isoformat())


def create_approval(store: AuditStore, call_id: str, arguments_hash: str,
                    target: str, user_id: str = "pending-user") -> ApprovalRecord:
    record = ApprovalRecord("", call_id, arguments_hash, target, user_id)
    store.save_approval(record)
    return record


def decide_approval(store: AuditStore, approval_id: str, user_id: str,
                    approve: bool) -> ApprovalRecord | None:
    """已认证用户在独立入口批准或拒绝。返回更新后的记录。"""
    record = store.get_approval(approval_id)
    if record is None:
        return None
    if record.status != "pending":
        return record
    if user_id != record.user_id:
        raise PermissionError("只有发起任务的用户可以确认")
    record.status = "approved" if approve else "denied"
    store.update_approval(record)
    return record


def valid_approval(store: AuditStore, tool: str, arguments_hash: str,
                   user_id: str, session_id: str | None = None) -> ApprovalRecord | None:
    """找到对当前 (tool, 参数摘要, 用户) 仍有效的批准；参数不一致返回 None。"""
    for record in store.approvals_for_hash(arguments_hash):
        if record.is_valid_for(tool, arguments_hash, user_id) and (
            session_id is None or store.call_session(record.call_id) == session_id
        ):
            return record
    return None
