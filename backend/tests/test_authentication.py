import asyncio
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.main as main
from app.models.core import AuthSession, User


@pytest.fixture
def database(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    yield engine
    engine.dispose()


def test_sessions_protect_api_and_logout(database):
    with Session(database) as session:
        data = asyncio.run(main.register(main.RegisterRequest(name="Analyst", email="a@example.test", password="password"), session))
        token = data["token"]
        user = session.get(User, data["user"]["id"])
        assert user.hashed_password.startswith("pbkdf2_sha256$")
        assert main.authenticated_user(token, session).id == user.id
        request = SimpleNamespace(url=SimpleNamespace(path="/api/overview"), method="GET",
                                  headers={"authorization": "Bearer " + token}, state=SimpleNamespace())
        async def next_handler(req):
            return "permitted"
        assert asyncio.run(main.require_authentication(request, next_handler)) == "permitted"
        asyncio.run(main.logout(request, session))
        assert main.authenticated_user(token, session) is None
        assert asyncio.run(main.require_authentication(request, next_handler)).status_code == 401
        with pytest.raises(HTTPException) as exc:
            asyncio.run(main.register(main.RegisterRequest(name="Other", email="b@example.test", password="password"), session))
        assert exc.value.status_code == 403


def test_expiration_and_legacy_password_migration(database):
    with Session(database) as session:
        session.add(User(email="old@example.test", name="Old", hashed_password=hashlib.sha256(b"oldpass").hexdigest()))
        session.commit()
        result = asyncio.run(main.login(main.LoginRequest(email="old@example.test", password="oldpass"), session))
        user = session.get(User, result["user"]["id"])
        assert user.hashed_password.startswith("pbkdf2_sha256$")
        record = session.get(AuthSession, hashlib.sha256(result["token"].encode()).hexdigest())
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.add(record)
        session.commit()
        assert main.authenticated_user(result["token"], session) is None


def test_webhook_requires_valid_github_signature_or_session(database, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    body = b'{"ref":"refs/heads/main"}'
    signature = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    async def read_body():
        return body
    async def next_handler(req):
        return "permitted"
    request = SimpleNamespace(url=SimpleNamespace(path="/api/devsecops/webhook"), method="POST",
                              headers={"x-hub-signature-256": signature}, state=SimpleNamespace(), body=read_body)
    assert asyncio.run(main.authenticate_request(request, next_handler)) == "permitted"
    request.headers["x-hub-signature-256"] = "sha256=invalid"
    assert asyncio.run(main.authenticate_request(request, next_handler)).status_code == 401


def test_http_middleware_and_signed_webhook_preserve_body(database, monkeypatch):
    import httpx
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    captured = {}
    def fake_scan(**kwargs):
        captured.update(kwargs)
        return {"run": {}, "sast_details": {}, "secret_details": {}, "dependency_details": {}, "container_details": {}}
    monkeypatch.setattr(main, "trigger_pipeline_scan", fake_scan)
    body = b'{"ref":"refs/heads/feature"}'
    signature = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
            denied = await client.get("/api/overview", headers={"Origin": "http://localhost:3000"})
            assert denied.status_code == 401
            assert denied.headers["access-control-allow-origin"] == "http://localhost:3000"
            result = await client.post("/api/devsecops/webhook", content=body,
                                       headers={"X-Hub-Signature-256": signature, "Content-Type": "application/json"})
            assert result.status_code == 200
    asyncio.run(run())
    assert captured["branch"] == "feature"
