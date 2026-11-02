from datetime import datetime, timezone
from threading import Lock
import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.database import get_session
from app.main import app, get_reports, get_report, get_analytics, get_risk, get_overview, get_alerts, get_audit_findings, resolve_audit_finding, analyze_threat, NetworkEvent
from app.models.core import CSPMFinding, ThreatEvent, AuditFinding, AuditReport
from app.devsecops import service
from app.assistant.service import query_assistant
from app.devsecops.crew_tools.tools.cve_owasp_intelligence_analyzer import CveOwaspIntelligenceAnalyzerTool
from app.devsecops.crew_tools.tools.http_security_headers_inspector import HttpSecurityHeadersInspectorTool
from app.devsecops.crew_tools.tools.ssl_tls_certificate_inspector import SslTlsCertificateInspectorTool
import requests


@pytest.fixture
def database(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)

    def get_test_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = get_test_session
    monkeypatch.setattr(service, "engine", engine)
    yield engine
    app.dependency_overrides.clear()
    engine.dispose()


def test_audit_report_is_saved_and_downloadable(database):
    state = {"lock": Lock(), "run_id": "audit-1", "target": "example.test",
             "reports": {"Inspection": "Observed headers"}}
    service._save_audit_report(state)
    state["reports"]["Recon"] = "Observed DNS"
    service._save_audit_report(state)
    with Session(database) as session:
        reports = asyncio.run(get_reports(session))["reports"]
        assert len(reports) == 1
        assert reports[0]["type"] == "2 stages"
        content = asyncio.run(get_report("audit-1", session))["content"]
        assert "Observed headers" in content and "Observed DNS" in content


def test_recorded_events_drive_analytics_risk_and_alerts(database, monkeypatch):
    with Session(database) as session:
        session.add(ThreatEvent(id="old", time=datetime.now(timezone.utc), type="Port Scan",
                                source="192.0.2.1", severity="HIGH", status="Open"))
        session.add(CSPMFinding(id="cloud", finding="Public bucket", severity="HIGH",
                                resource="bucket", rule_id="S3", status="Open"))
        session.commit()
    monkeypatch.setattr("app.main.analyze_event", lambda _: {"prediction": "Port Scan", "severity": "HIGH", "confidence": 0.9})
    with Session(database) as session:
        event = NetworkEvent(packet_size=1, duration=1, failed_logins=0,
            unique_ports_accessed=2, bytes_sent=1, source_ip="192.0.2.2", destination="192.0.2.3")
        assert asyncio.run(analyze_threat(event, session))["logged"]
        assert len(asyncio.run(get_alerts(session))["alerts"]) == 1
        analytics = asyncio.run(get_analytics(session))
        assert next(x["value"] for x in analytics["severity_distribution"] if x["name"] == "High") == 2
        assert analytics["trend"][-1]["high"] == 2
        risk = asyncio.run(get_risk(session))
        assert risk["overall_risk"] == 30
        assert risk["top_assets"] == [{"name": "bucket", "score": 10}]
        assert asyncio.run(get_overview(session))["stats"]["risk_score"] == 30


def test_cve_report_does_not_invent_a_technology_or_vulnerability():
    tool = CveOwaspIntelligenceAnalyzerTool()
    empty = tool._run("example.test", "")
    assert "No technology fingerprints" in empty
    assert "CVE-202" not in empty
    report = tool._run("example.test", "Server: nginx/1.25.3")
    assert "Nginx | 1.25.3" in report
    assert "No CVE applicability has been verified" in report


def test_header_observations_flow_to_alerts_and_risk(database, monkeypatch):
    response = SimpleNamespace(url="https://example.test/", status_code=200, history=[],
                               headers={"Content-Security-Policy": "default-src 'self'"})
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: response)
    _, findings = HttpSecurityHeadersInspectorTool().inspect("https://example.test")
    assert {f["title"] for f in findings} == {
        "Missing Strict-Transport-Security header", "Missing X-Content-Type-Options header"}
    service._save_audit_findings("first", findings)
    service._save_audit_findings("first", findings)
    service._save_audit_findings("second", findings)
    with Session(database) as session:
        assert len(asyncio.run(get_audit_findings(session))["findings"]) == 4
        assert len(asyncio.run(get_alerts(session))["alerts"]) == 2
        risk = asyncio.run(get_risk(session))
        assert risk["breakdown"]["audit_risk"] == 6
        assert risk["overall_risk"] == 6
        assert next(x["value"] for x in asyncio.run(get_analytics(session))["audit_distribution"] if x["name"] == "Medium") == 2
        observations = asyncio.run(get_audit_findings(session))["findings"]
        medium = next(f for f in observations if f.severity == "MEDIUM")
        assert asyncio.run(resolve_audit_finding(medium.id, session))["resolved_observations"] == 2
        assert all(alert.status == "Resolved" for alert in asyncio.run(get_alerts(session))["alerts"])
        assert asyncio.run(get_risk(session))["breakdown"]["audit_risk"] == 1


def test_failed_header_request_does_not_create_missing_header_findings(monkeypatch):
    def failed_request(*args, **kwargs):
        raise requests.ConnectionError("unreachable")
    monkeypatch.setattr(requests, "get", failed_request)
    report, findings = HttpSecurityHeadersInspectorTool().inspect("https://example.test")
    assert "Failed" in report
    assert findings == []


def test_pipeline_marks_unimplemented_checks_not_run(database, monkeypatch):
    monkeypatch.setattr(service, "run_real_sast_scan", lambda: {"status": "PASSED"})
    monkeypatch.setattr(service, "run_dependency_scan", lambda: {"status": "NOT RUN"})
    monkeypatch.setattr(service, "run_optional_scan", lambda *args: {"status": "NOT RUN"})
    result = service.trigger_pipeline_scan()["run"]
    assert result["status"] == "INCOMPLETE"
    assert result["secret_status"] == result["dependency_status"] == result["container_status"] == "NOT RUN"


def test_injection_stage_persists_candidate_observations(database, monkeypatch):
    candidate = {"target": "https://example.test", "title": "Candidate injection in GET parameter q",
                 "severity": "HIGH", "evidence": "Response requires validation",
                 "recommendation": "Review the parameter."}
    monkeypatch.setattr(service.SqlInjectionVulnerabilityTesterTool, "inspect", lambda self, url: ("Candidate report", [candidate]))
    report = service._execute_native_stage("https://example.test", 4, [], "audit-1")
    assert report == "Candidate report"
    with Session(database) as session:
        findings = asyncio.run(get_audit_findings(session))["findings"]
        assert len(findings) == 1 and findings[0].run_id == "audit-1"
        assert len(asyncio.run(get_alerts(session))["alerts"]) == 1


def test_assistant_uses_saved_records_and_conversation(database, monkeypatch):
    import httpx
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    captured = {}
    def fake_post(url, **kwargs):
        captured.update(kwargs["json"])
        return SimpleNamespace(raise_for_status=lambda: None,
            json=lambda: {"candidates": [{"content": {"parts": [{"text": "Review the finding."}]}}]})
    monkeypatch.setattr(httpx, "post", fake_post)
    with Session(database) as session:
        session.add(AuditFinding(id="finding", run_id="run", target="https://example.test", title="Missing CSP",
                                 severity="MEDIUM", evidence="Header absent", recommendation="Review CSP"))
        session.add(AuditReport(id="run", target="example.test", content="Actual scan evidence"))
        session.commit()
        result = query_assistant("How do I fix it?", session, [{"role": "user", "content": "Explain the finding"}])
        assert result["response"] == "Review the finding."
        body = captured["contents"][0]["parts"][0]["text"]
        assert "Missing CSP" in body and "Actual scan evidence" in body and "Explain the finding" in body


def test_assistant_local_summary_does_not_invent_findings(database, monkeypatch):
    for key in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    with Session(database) as session:
        result = query_assistant("Is my bucket public?", session)
        assert "No audit observations" in result["response"]
        assert "production-assets" not in result["response"]


def test_tls_observations_distinguish_verification_and_connection_failures(monkeypatch):
    tool = SslTlsCertificateInspectorTool()
    monkeypatch.setattr(type(tool), "_fetch_crtsh", lambda self, domain: [])
    captured = []
    def verification_error(self, host, port):
        captured.append((host, port))
        return {"success": False, "verification_error": True, "error": "certificate expired"}
    monkeypatch.setattr(type(tool), "_inspect_live_socket", verification_error)
    _, findings = tool.inspect("https://example.test:8443")
    assert captured == [("example.test", 8443)]
    assert findings[0]["title"] == "TLS certificate verification failed"
    monkeypatch.setattr(type(tool), "_inspect_live_socket", lambda *args: {"success": False, "error": "connection refused"})
    assert tool.inspect("https://example.test")[1] == []
