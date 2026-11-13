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

