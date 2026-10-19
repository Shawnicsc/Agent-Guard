"""独立确认闭环测试：绑定参数摘要、本人限定、有效期、批准后放行（无外部依赖）。"""

from __future__ import annotations

import pytest

from guard.contracts import DecisionAction
from guard.policy.approval import (
    APPROVAL_TTL_S,
    create_approval,
    decide_approval,
    valid_approval,
)


def _write_args(content: str = "hello") -> dict:
    return {"path": "workspace://notes.txt", "content": content}


# ---- 记录级 ----


def test_approval_record_basics(store):

    record = create_approval(store, "call-1", "hash-1", "fs.write {...}", "u1")
    assert record.status == "pending"
    assert record.call_id == "call-1"
    assert record.user_id == "u1"
    assert (record.expires_at - record.created_at).total_seconds() == APPROVAL_TTL_S
    # 未批准时对任何参数都无效
    assert not record.is_valid_for("fs.write {...}"[:9], "hash-1", "u1")


def test_decide_approval_user_bound(store):
    record = create_approval(store, "c", "h", "fs.write x", "u1")
    with pytest.raises(PermissionError):
        decide_approval(store, record.approval_id, "attacker", True)
    approved = decide_approval(store, record.approval_id, "u1", True)
    assert approved.status == "approved"
    # 二次决议幂等：pending -> decided 后不再变化
    again = decide_approval(store, record.approval_id, "u1", False)
    assert again.status == "approved"
    assert decide_approval(store, "no-such", "u1", True) is None


def test_valid_approval_hash_and_ttl(store):
    record = create_approval(store, "c", "hash-1", "fs.write x", "u1")
    decide_approval(store, record.approval_id, "u1", True)
    # (tool, hash, user) 全一致才有效
    assert valid_approval(store, "fs.write", "hash-1", "u1") is not None
    assert valid_approval(store, "fs.write", "hash-2", "u1") is None
    assert valid_approval(store, "fs.write", "hash-1", "someone-else") is None
    assert valid_approval(store, "git.push", "hash-1", "u1") is None
    # 过期失效
    record.expires_at = record.created_at
    store.update_approval(record)
    assert valid_approval(store, "fs.write", "hash-1", "u1") is None


# ---- 会话级闭环 ----


def test_confirm_then_approve_then_allow(session):
    envelope = session.make_envelope("fs.write", _write_args())
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.CONFIRM
    assert decision.approval_id

    # 批准前重试（新 call_id）依然 CONFIRM，且未执行
    retry = session.make_envelope("fs.write", _write_args())
    d2 = session.decide(retry)
    assert d2.action == DecisionAction.CONFIRM

    # 本人批准后，参数一致的调用直接放行并真正执行
    from guard.policy.approval import decide_approval
    decide_approval(session.store, decision.approval_id, session.mission.user_id, True)
    after = session.make_envelope("fs.write", _write_args())
    d3 = session.decide(after)
    assert d3.action == DecisionAction.ALLOW
    assert "approved_call" in d3.rule_ids
    result, _ = session.try_execute(after, d3)
    assert result.ok


def test_approval_invalidated_by_param_change(session):
    envelope = session.make_envelope("fs.write", _write_args("original"))
    decision = session.decide(envelope)
    assert decision.action == DecisionAction.CONFIRM

    from guard.policy.approval import decide_approval
    decide_approval(session.store, decision.approval_id, session.mission.user_id, True)

    # 参数变化 -> 哈希不一致 -> 重新裁决为 CONFIRM
    changed = session.make_envelope("fs.write", _write_args("tampered"))
    d2 = session.decide(changed)
    assert d2.action == DecisionAction.CONFIRM
    assert changed.arguments_hash != envelope.arguments_hash


def test_denied_approval_never_executes(session):
    envelope = session.make_envelope("fs.write", _write_args())
    decision = session.decide(envelope)
    from guard.policy.approval import decide_approval
    decide_approval(session.store, decision.approval_id, session.mission.user_id, False)
    retry = session.make_envelope("fs.write", _write_args())
    d2 = session.decide(retry)
    # 拒绝后不会凭 approved_call 放行（政策层重新裁决）
    assert d2.action == DecisionAction.CONFIRM
    result, _ = session.try_execute(retry, d2)
    assert not result.ok


def test_hard_block_not_overridable_by_approval(session):
    """硬性禁令优先于任何批准：敏感路径即使有历史批准也必须 BLOCK。"""
    # 先为敏感路径的精确参数造一个"已批准"记录（模拟历史批准/异常数据）
    args = {"path": "~/.ssh/authorized_keys", "content": "k"}
    envelope = session.make_envelope("fs.write", args)
    create_approval(session.store, "old-call", envelope.arguments_hash,
                    f"fs.write {args}", session.mission.user_id)

    # 历史 pending 记录直接置为 approved（绕过 decide_approval 的 pending 限制用于构造）
    record = session.store.approvals_for_hash(envelope.arguments_hash)[0]
    record.status = "approved"
    session.store.update_approval(record)

    decision = session.decide(envelope)
    assert decision.action == DecisionAction.BLOCK
    assert "deny_sensitive_write" in decision.rule_ids
