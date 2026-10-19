"""审计脱敏与受控 Git 执行器测试（B 阶段交付，无外部依赖）。"""

from __future__ import annotations

from guard.audit.redact import redact_payload, redact_text

# ---- 脱敏 ----


def test_redact_private_key():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    assert redact_text(pem) == "[REDACTED:PRIVATE_KEY]"


def test_redact_aws_key():
    assert redact_text("key=AKIAIOSFODNN7EXAMPLE") == "key=[REDACTED:AWS_KEY]"


def test_redact_secret_assignments():
    out = redact_text("api_key = sk-abcdefghijklmnop123456")
    assert "sk-abcdefghijklmnop123456" not in out
    assert "[REDACTED:SECRET]" in out
    # 大小写不敏感（Password=...）
    out = redact_text("Password: hunter2supersecret")
    assert "hunter2supersecret" not in out


def test_redact_payload_recursive_and_preserves_structure():
    payload = {
        "messages": [
            {"role": "tool", "content": "token: ghp_0123456789abcdef"},
        ],
        "nested": {"secret": "s3cr3tvalue0123456789"},
        "count": 3,
    }
    out = redact_payload(payload)
    assert out["count"] == 3
    assert out["messages"][0]["role"] == "tool"
    assert "[REDACTED:SECRET]" in out["messages"][0]["content"]
    assert "[REDACTED:SECRET]" in out["nested"]["secret"]


def test_store_auto_redacts_event_payload(session):
    """append_event 的审计正文自动存脱敏副本（DESIGN.md 第 9 节）。"""
    import json

    from guard.contracts import AuditEvent, EventType

    session.store.append_event(AuditEvent(
        trace_id=session.trace_id, type=EventType.LLM_RESPONSE,
        session_id=session.mission.session_id,
        payload={"content": "AKIAIOSFODNN7EXAMPLE"},
    ))
    rows = session.store.events_by_trace(session.trace_id)
    row = [r for r in rows if r["type"] == "llm_response"][-1]
    redacted = json.loads(row["redacted_payload_json"])
    assert "AKIA" not in row["redacted_payload_json"]
    assert redacted["content"] == "[REDACTED:AWS_KEY]"


# ---- Git 执行器 ----


def test_git_push_requires_repo(session):
    """非 Git 仓库的工作区直接拒绝，不调起 git 子进程推送。"""
    result = session.git.push("origin", "main")
    assert not result.ok and "不是 Git 仓库" in result.error
