import asyncio
from types import SimpleNamespace

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.main as main
from app.models.core import ThreatEvent
from app.devsecops.crew_tools.tools.deep_endpoint_directory_discovery_tool import (
    DeepEndpointDirectoryDiscoveryTool,
    _validate_content_signature,
)


def test_soft_404_spa_catch_all_not_marked_exposed(monkeypatch):
    spa_html = "<!DOCTYPE html><html><body><div id='root'></div><script src='/main.js'></script></body></html>"

    def fake_get(url, **kwargs):
        if "/api/health" in url:
            return SimpleNamespace(
                status_code=200,
                text='{"status":"ok"}',
                content=b'{"status":"ok"}',
                headers={"Content-Type": "application/json"},
            )
        return SimpleNamespace(
            status_code=200,
            text=spa_html,
            content=spa_html.encode(),
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

    monkeypatch.setattr("requests.get", fake_get)
    report, findings = DeepEndpointDirectoryDiscoveryTool().inspect("https://spa.example.test", depth="standard")
    assert "Soft-404 / Catch-All Filtered" in report
    assert not any(".env" in f["title"] or ".git" in f["title"] for f in findings)


def test_content_signature_validator_rejects_html_for_env_and_json():
    assert _validate_content_signature("/.env", 200, "text/html", "<!doctype html><html></html>") is False
    assert _validate_content_signature("/.env", 200, "text/plain", "DB_PASSWORD=secret\nAPP_ENV=prod") is True
    assert _validate_content_signature("/.git/HEAD", 200, "text/plain", "ref: refs/heads/main\n") is True
    assert _validate_content_signature("/openapi.json", 200, "text/html", "<html>404</html>") is False
    assert _validate_content_signature("/openapi.json", 200, "application/json", '{"openapi": "3.0.0"}') is True


def test_custom_vector_simulation_and_burst():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        req = main.SimulationRequest(
            scenario="custom",
            target="edge-waf.example:443",
            burst_count=3,
            packet_size=1500,
            duration=9.0,
            failed_logins=0,
            unique_ports_accessed=1,
            bytes_sent=14000,
        )
        res = asyncio.run(main.simulate_live_traffic_burst(session, req))
        assert res["scenario_id"] == "custom"
        assert res["burst_count"] == 3
        assert res["analysis"]["prediction"] == "DoS"
        assert "probabilities" in res["analysis"]
        assert len(session.exec(select(ThreatEvent)).all()) == 3
    engine.dispose()


def test_attack_detection_benchmark_suite():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        res = asyncio.run(
            main.run_attack_detection_benchmark(
                session, main.BenchmarkRequest(target="bench-gw.internal", log_events=False)
            )
        )
        assert res["status"] == "success"
        assert res["summary"]["total_vectors"] == 10
        assert res["summary"]["accuracy_pct"] >= 80.0
        assert len(res["results"]) == 10
        # Ensure dry-run benchmark did not write ThreatEvents
        assert len(session.exec(select(ThreatEvent)).all()) == 0
    engine.dispose()


def test_assistant_intent_routing_and_enriched_context(monkeypatch):
    from types import SimpleNamespace
    import httpx
    from app.assistant.service import _build_intent_directive, query_assistant
    from app.models.core import AuditFinding

    directive = _build_intent_directive("Fix Missing CSP with Nginx config and block attacking IPs", "deep")
    assert "ACTION DIRECTIVE" in directive
    assert "THREAT DIRECTIVE" in directive
    assert "Deep Principal Engineering Analysis" in directive

    exec_directive = _build_intent_directive("Give me a security briefing", "executive")
    assert "Executive Security Briefing" in exec_directive

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    captured = {}

    def fake_post(url, **kwargs):
        captured.update(kwargs["json"])
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"candidates": [{"content": {"parts": [{"text": "## Remediation\n```nginx\nadd_header Strict-Transport-Security \"max-age=31536000\";\n```"}]}}]},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            AuditFinding(
                id="f-1",
                run_id="r-1",
                target="https://app.example.test",
                title="Missing HSTS header",
                severity="HIGH",
                evidence="Strict-Transport-Security absent",
                recommendation="Enable HSTS",
            )
        )
        session.add(
            ThreatEvent(
                id="THR-1",
                type="Brute Force",
                source="198.51.100.77",
                destination="10.0.1.50:22",
                confidence=0.98,
                severity="HIGH",
                status="Open",
                simulated=True,
            )
        )
        session.commit()

        result = query_assistant(
            "Fix Missing HSTS and check Brute Force IP",
            session=session,
            response_mode="executive",
        )
        assert "Strict-Transport-Security" in result["response"]
        assert captured["generationConfig"]["maxOutputTokens"] == 4096
        prompt_blob = captured["contents"][0]["parts"][0]["text"]
        assert "audit_findings_total" in prompt_blob
        assert "top_attacker_ips" in prompt_blob
        assert "Executive Security Briefing" in prompt_blob
    engine.dispose()


def test_assistant_multi_key_failover_and_local_fallback(monkeypatch):
    import httpx
    from sqlmodel import SQLModel, create_engine, Session
    from app.assistant import service

    monkeypatch.setattr(service, "_RUNTIME_API_KEY", "")
    monkeypatch.setattr(service, "_load_env_if_needed", lambda: None)
    monkeypatch.setattr(service, "_VALIDATED_KEYS_CACHE", {})
    for var in ("GEMINI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY", "XAI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("GEMINI_API_KEY", "AIzaInvalidKeyForFailoverTest123456")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_valid_failover_key_123456789012345678901234567890")

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict):
            self.status_code = status_code
            self._payload = payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError("err", request=None, response=None)

        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, headers=None, json=None):
            if "api.groq.com" in url and (headers or {}).get("Authorization", "").startswith("Bearer gsk_valid_"):
                return FakeResponse(
                    200,
                    {"choices": [{"message": {"content": "Groq failover response: enable HSTS and CSP."}}]},
                )
            return FakeResponse(401, {"error": "unauthorized"})

    def fake_get(url, **kwargs):
        if "api.groq.com" in url:
            return FakeResponse(200, {"data": []})
        return FakeResponse(401, {"error": "invalid"})

    def fake_post(url, **kwargs):
        return FakeResponse(401, {"error": "invalid"})

    monkeypatch.setattr(httpx, "Client", FakeClient)
    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_post)

    status = service.get_active_provider_status()
    assert status["configured"] is True
    assert status["provider"] == "Groq"

    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        result = service.query_assistant("How do I secure HTTP headers?", session=session)
        assert result["api_key_configured"] is True
        assert result["provider"] == "Groq"
        assert result["engine"].startswith("Groq ")
        assert "Groq failover response" in result["response"]

        # When all candidate providers fail, fall back cleanly to Local Summary Mode
        monkeypatch.setattr(service, "_VALIDATED_KEYS_CACHE", {})
        monkeypatch.setenv("GROQ_API_KEY", "gsk_broken_key_12345678901234567890123456789012345")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        fallback = service.query_assistant("How do I secure HTTP headers?", session=session)
        assert fallback["api_key_configured"] is False
        assert fallback["provider"] == "Local Summary Mode"
        assert fallback["engine"] == "Local recorded-data summary"
    engine.dispose()


