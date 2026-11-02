import json
from types import SimpleNamespace
from unittest.mock import patch

from app.devsecops.service import run_real_sast_scan, run_dependency_scan, run_optional_scan


def test_bandit_findings_are_reported():
    output = {"metrics": {"_totals": {"SEVERITY.HIGH": 1, "loc": 20}}}
    result = SimpleNamespace(returncode=1, stdout=json.dumps(output), stderr="")
    with patch("app.devsecops.service.subprocess.run", return_value=result):
        scan = run_real_sast_scan()
    assert scan["status"] == "FAILED"
    assert scan["high_issues"] == 1


def test_bandit_errors_do_not_pass():
    results = [
        SimpleNamespace(returncode=2, stdout="", stderr="scan failed"),
        SimpleNamespace(returncode=0, stdout="invalid JSON", stderr=""),
        SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    ]
    for result in results:
        with patch("app.devsecops.service.subprocess.run", return_value=result):
            assert run_real_sast_scan()["status"] == "ERROR"
    with patch("app.devsecops.service.subprocess.run", side_effect=FileNotFoundError("bandit")):
        assert run_real_sast_scan()["status"] == "ERROR"


def test_dependency_scan_reports_advisories_and_does_not_treat_errors_as_clean():
    report = {"dependencies": [{"name": "example", "version": "1.0", "vulns": [{"id": "TEST-1", "fix_versions": ["1.1"]}]}]}
    with patch("app.devsecops.service.shutil.which", return_value="/usr/bin/pip-audit"):
        with patch("app.devsecops.service.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=json.dumps(report))):
            result = run_dependency_scan()
            assert result["status"] == "FAILED"
            assert result["vulnerabilities"][0]["id"] == "TEST-1"
        with patch("app.devsecops.service.subprocess.run", return_value=SimpleNamespace(returncode=1, stdout="")):
            assert run_dependency_scan()["status"] == "ERROR"


def test_optional_scanners_distinguish_findings_from_errors():
    with patch("app.devsecops.service.shutil.which", return_value=None):
        assert run_optional_scan("trivy", [], "test")["status"] == "NOT RUN"
    with patch("app.devsecops.service.shutil.which", return_value="/usr/bin/scanner"):
        with patch("app.devsecops.service.subprocess.run", return_value=SimpleNamespace(returncode=10)):
            assert run_optional_scan("trivy", [], "test")["status"] == "FAILED"
        with patch("app.devsecops.service.subprocess.run", return_value=SimpleNamespace(returncode=2)):
            assert run_optional_scan("trivy", [], "test")["status"] == "ERROR"
