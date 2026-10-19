"""对外接口（DESIGN.md 第 10 节）。

阶段 A 交付：POST /sessions、POST /tool-calls/decide、GET /health。
阶段 B 追加 /approvals/{id}、GET /policies、POST /policies/validate；阶段 D 追加 /incidents。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from guard.config import settings
from guard.contracts import Decision
from guard.gateway.session import MAIN_AGENT_ID, GatewaySession
from guard.policy.approval import decide_approval
from guard.policy.dsl import compile_policy_text

router = APIRouter()


class CreateSessionBody(BaseModel):
    user_id: str
    goal: str
    goal_category: str = "general"
    allowed_resources: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allow_exfiltration: bool = False
    allow_push: bool = False


class DecideBody(BaseModel):
    session_id: str
    agent_id: str = MAIN_AGENT_ID
    tool: str
    arguments: dict[str, Any]
    parent_call_id: str | None = None


@router.get("/health")
def health(request: Request) -> dict:
    return {
        "status": "ok",
        "provider": request.app.state.llm.provider_name,
        "model": request.app.state.llm.provider.model,
        "sessions": len(request.app.state.sessions),
    }


@router.post("/sessions")
def create_session(body: CreateSessionBody, request: Request) -> dict:
    session = GatewaySession.create(
        request.app.state.store,
        settings.workspaces_root,
        user_id=body.user_id,
        goal=body.goal,
        goal_category=body.goal_category,
        policy_engine=request.app.state.sessions_engine,
        allowed_resources=body.allowed_resources or None,
        allowed_actions=body.allowed_actions or None,
        allow_exfiltration=body.allow_exfiltration,
        allow_push=body.allow_push,
    )
    request.app.state.sessions[session.mission.session_id] = session
    return {
        "session_id": session.mission.session_id,
        "trace_id": session.trace_id,
        "mission": session.mission.model_dump(mode="json"),
    }


@router.post("/tool-calls/decide")
def decide_tool_call(body: DecideBody, request: Request) -> Decision:
    """执行前三态裁决。真实参数与身份由网关状态签发，不信任调用方声明。"""
    session: GatewaySession | None = request.app.state.sessions.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"会话不存在: {body.session_id}")
    try:
        envelope = session.make_envelope(body.tool, body.arguments, body.parent_call_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return session.decide(envelope)


class ApprovalBody(BaseModel):
    user_id: str
    approve: bool


@router.post("/approvals/{approval_id}")
def resolve_approval(approval_id: str, body: ApprovalBody, request: Request) -> dict:
    """独立确认入口：已认证用户批准或拒绝与参数摘要绑定的调用。"""
    try:
        record = decide_approval(request.app.state.store, approval_id,
                                 body.user_id, body.approve)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail=f"批准记录不存在: {approval_id}")
    return {
        "approval_id": record.approval_id, "call_id": record.call_id,
        "status": record.status, "expired": record.expired,
    }


@router.get("/policies")
def get_policy(request: Request) -> dict:
    engine = request.app.state.sessions_engine  # 延后注入见 create_app
    return _policy_summary(engine)


@router.post("/policies/validate")
def validate_policy(body: dict, request: Request) -> dict:
    """校验策略文本；返回编译结果或错误，不改变当前生效版本。"""
    content = body.get("content", "")
    try:
        compiled = compile_policy_text(content)
        return {"valid": True, "version": compiled.version,
                "rules": [r.id for r in compiled.rules]}
    except Exception as exc:  # PolicyError 与 pydantic 校验错误一并返回
        return {"valid": False, "error": str(exc)}


def _policy_summary(engine) -> dict:
    policy = engine.policy
    return {
        "version": policy.version,
        "trusted_domains": sorted(policy.trusted_domains),
        "default_decision": policy.default_decision.value,
        "rules": [
            {"id": r.id, "priority": r.priority, "decision": r.decision.value,
             "reason": r.reason}
            for r in sorted(policy.rules, key=lambda x: -x.priority)
        ],
    }
