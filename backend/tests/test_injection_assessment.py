from types import SimpleNamespace

from app.devsecops.crew_tools.tools.sql_injection_vulnerability_tester import SqlInjectionVulnerabilityTesterTool
from app.devsecops.crew_tools.tools.authentication_security_tester import AuthenticationSecurityTesterTool


def response(text="", status=200, headers=None):
    return SimpleNamespace(text=text, status_code=status, headers=headers or {})


def test_failed_baseline_marks_test_incomplete(monkeypatch):
    tool = SqlInjectionVulnerabilityTesterTool()
    monkeypatch.setattr(type(tool), "_safe_request", lambda *args, **kwargs: None)
    result = tool._test_target_parameter("https://example.test", "q")
    assert result["tested_vectors"] == 0
    assert result["error"]
    report = tool._build_injection_report("https://example.test", [], ["q"], [result])
    assert "Incomplete checks" in report
    assert "does not establish" in report


def test_existing_database_error_is_not_reported_as_injection(monkeypatch):
    tool = SqlInjectionVulnerabilityTesterTool()
    monkeypatch.setattr(type(tool), "_safe_request", lambda *args, **kwargs: response("You have an error in your SQL syntax"))
    result = tool._test_target_parameter("https://example.test", "q")
    assert result["successful_vectors"] == result["tested_vectors"]
    assert not any(f["category"] == "SQL Injection" for f in result["findings"])


def test_external_form_actions_are_not_probed(monkeypatch):
    tool = SqlInjectionVulnerabilityTesterTool()
    html = '<form action="https://other.test/login" method="post"><input name="email"></form><form action="/search"><input name="q"></form>'
    monkeypatch.setattr(type(tool), "_safe_request", lambda *args, **kwargs: response(html))
    forms, _ = tool._scrape_forms_and_inputs("https://example.test")
    assert [form["action"] for form in forms] == ["https://example.test/search"]


def test_redirect_hostname_must_match_probe_domain(monkeypatch):
    tool = SqlInjectionVulnerabilityTesterTool()
    monkeypatch.setattr(type(tool), "_safe_request", lambda *args, **kwargs: response("", 302, {"Location": "https://safe.test/evil-security-check.com"}))
    result = tool._test_target_parameter("https://example.test", "next")
    assert not any(f["category"] == "Open Redirect" for f in result["findings"])


def test_authentication_tests_are_skipped_without_login_form(monkeypatch):
    tool = AuthenticationSecurityTesterTool()
    monkeypatch.setattr(type(tool), "_discover_login_page", lambda *args: ("https://example.test", "<html>Welcome</html>", None))
    def unexpected(*args):
        raise AssertionError("Credential probes should not run without a login form")
    monkeypatch.setattr(type(tool), "_audit_default_credentials", unexpected)
    report = tool._run("https://example.test")
    assert "Not run: no in-scope password form" in report
    assert "Protected" not in report
