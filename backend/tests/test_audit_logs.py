import asyncio
from types import SimpleNamespace

from fastapi.responses import JSONResponse
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.main as main


def test_audit_logs_store_response_and_exclude_sensitive_data(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    with Session(engine) as session:
        data = asyncio.run(main.register(main.RegisterRequest(name="Analyst", email="analyst@example.test", password="secret-password"), session))
        token = data["token"]

    async def success(request):
        return JSONResponse({"ok": True}, status_code=200)

    async def failure(request):
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    request = SimpleNamespace(url=SimpleNamespace(path="/api/auth/profile"), method="PUT",
                              headers={"authorization": f"Bearer {token}"}, state=SimpleNamespace(),
                              scope={"route": SimpleNamespace(path="/api/auth/profile")})
    assert asyncio.run(main.require_authentication(request, success)).status_code == 200
    request = SimpleNamespace(url=SimpleNamespace(path="/api/auth/login"), method="POST", headers={},
                              state=SimpleNamespace(), scope={"route": SimpleNamespace(path="/api/auth/login")})
    assert asyncio.run(main.require_authentication(request, failure)).status_code == 401

    with Session(engine) as session:
        logs = asyncio.run(main.get_audit_logs(session))["logs"]
        assert len(logs) == 2
        assert logs[0]["user"] == "Unauthenticated" and logs[0]["status"] == "Failure"
        assert logs[0]["action"] == "POST /api/auth/login" and logs[0]["status_code"] == 401
        assert logs[1]["user"] == "analyst@example.test" and logs[1]["status"] == "Success"
        assert logs[1]["action"] == "PUT /api/auth/profile" and logs[1]["status_code"] == 200
        assert token not in str(logs) and "secret-password" not in str(logs)
    engine.dispose()


def test_http_requests_appear_in_audit_logs(monkeypatch, tmp_path):
    import httpx
    from app.database import get_session

    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)

    async def get_test_session():
        with Session(engine) as session:
            yield session

    main.app.dependency_overrides[get_session] = get_test_session

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
            registration = await client.post("/api/auth/register", json={"name": "Analyst", "email": "analyst@example.test", "password": "secret-password"})
            assert registration.status_code == 200
            token = registration.json()["token"]
            failure = await client.post("/api/auth/login?private=secret-query", json={"email": "analyst@example.test", "password": "wrong-password"})
            assert failure.status_code == 401
            profile = await client.put("/api/auth/profile", headers={"Authorization": f"Bearer {token}"}, json={"name": "Updated"})
            assert profile.status_code == 200
            response = await client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
            logs = response.json()["logs"]
            assert len(logs) == 3
            assert logs[0]["user"] == "analyst@example.test" and logs[0]["action"] == "PUT /api/auth/profile"
            assert logs[1]["action"] == "POST /api/auth/login" and logs[1]["status_code"] == 401
            assert "secret-query" not in response.text and "wrong-password" not in response.text and token not in response.text

    try:
        asyncio.run(asyncio.wait_for(exercise(), timeout=10))
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()
