"""API 层测试：第三方 Agent 经 HTTP 接入网关的路径。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from guard.api.app import create_app


def make_client(tmp_path, monkeypatch):
    import guard.api.app as appmod

    monkeypatch.setattr(appmod.settings, "db_path", tmp_path / "api.db")
    monkeypatch.setattr(appmod.settings, "workspaces_root", tmp_path / "ws")
    app = create_app()
    return TestClient(app)


def test_health(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_session_and_decide(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.post("/sessions", json={
        "user_id": "u1",
        "goal": "读取 README 并总结",
        "goal_category": "read_document",
    })
    assert resp.status_code == 200
    body = resp.json()
    session_id = body["session_id"]
    assert body["mission"]["goal"] == "读取 README 并总结"

    resp = client.post("/tool-calls/decide", json={
        "session_id": session_id,
        "tool": "fs.read",
        "arguments": {"path": "README.md"},
    })
    assert resp.status_code == 200
    assert resp.json()["action"] == "ALLOW"


def test_decide_unknown_session_404(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    resp = client.post("/tool-calls/decide", json={
        "session_id": "sess_missing",
        "tool": "fs.read",
        "arguments": {},
    })
    assert resp.status_code == 404


def test_decide_unregistered_tool(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)
    session_id = client.post("/sessions", json={
        "user_id": "u1", "goal": "g",
    }).json()["session_id"]
    resp = client.post("/tool-calls/decide", json={
        "session_id": session_id,
        "tool": "not.a.tool",
        "arguments": {},
    })
    # 网关构造 envelope 时即拒绝未注册工具（400）
    assert resp.status_code == 400
