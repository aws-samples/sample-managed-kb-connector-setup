"""Unit tests for core/diagnostics and core/log_analysis."""

import datetime as _dt

from kb_connector.core.diagnostics import (
    CheckResult,
    build_diagnose_result,
    check_cert_expiry,
    check_certificate_installed,
)
from kb_connector.core.log_analysis import (
    DocumentEvent,
    analyze_logs,
    parse_document_events,
)


# --- Certificate expiry checks -----------------------------------------------


def test_cert_expiry_valid():
    future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=200)).isoformat()
    result = check_cert_expiry(cert_not_after=future)
    assert result.passed is True
    assert "200" in result.details or "199" in result.details


def test_cert_expiry_expired():
    past = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=10)).isoformat()
    result = check_cert_expiry(cert_not_after=past)
    assert result.passed is False
    assert "EXPIRED" in result.details


def test_cert_expiry_soon():
    soon = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=15)).isoformat()
    result = check_cert_expiry(cert_not_after=soon, warn_days=30)
    assert result.passed is False
    assert "expires in" in result.details


def test_cert_expiry_none():
    result = check_cert_expiry(cert_not_after=None)
    assert result.passed is True


# --- DiagnoseResult building -------------------------------------------------


def test_diagnose_result_healthy():
    checks = [
        CheckResult(name="secret", passed=True, details="OK", side="aws"),
        CheckResult(name="cert", passed=True, details="OK", side="source"),
    ]
    result = build_diagnose_result("my-sp", checks)
    assert result.status == "healthy"


def test_diagnose_result_failing():
    checks = [
        CheckResult(name="secret_validation", passed=False,
                    details="Missing clientId", side="aws",
                    data={"missing_fields": ["clientId"]}),
        CheckResult(name="cert_expiry", passed=True, details="OK", side="source"),
    ]
    result = build_diagnose_result("my-sp", checks)
    assert result.status == "failing"
    assert result.attribution == "aws"
    assert result.suggested_fix is not None


def test_diagnose_result_mixed_attribution():
    checks = [
        CheckResult(name="cert_expiry", passed=False,
                    details="Expired", side="source", data={"days_remaining": -5}),
        CheckResult(name="cloudtrail_permissions", passed=False,
                    details="Access denied", side="aws", data={}),
    ]
    result = build_diagnose_result("my-sp", checks)
    assert result.attribution == "unknown"  # mixed sides


# --- Log analysis ------------------------------------------------------------


def test_parse_document_events():
    raw = [
        {"message": '{"documentId": "doc1", "status": "INDEXED"}'},
        {"message": '{"documentId": "doc2", "status": "FAILED", "reason": "Access denied"}'},
        {"message": "not json"},
    ]
    events = parse_document_events(raw)
    assert len(events) == 2
    assert events[0].status == "INDEXED"
    assert events[1].reason == "Access denied"


def test_analyze_logs_basic():
    events = [
        DocumentEvent("d1", "/d1", "INDEXED"),
        DocumentEvent("d2", "/d2", "INDEXED"),
        DocumentEvent("d3", "/d3", "FAILED", "Access denied"),
        DocumentEvent("d4", "/d4", "SKIPPED", "No ACL"),
    ]
    result = analyze_logs(events)
    assert result.total_events == 4
    assert result.indexed_count == 2
    assert result.failed_count == 1
    assert result.skipped_count == 1
    assert len(result.groups) > 0


def test_analyze_logs_actionable_permissions():
    events = [
        DocumentEvent(f"d{i}", f"/d{i}", "FAILED", "Access denied to resource")
        for i in range(20)
    ]
    result = analyze_logs(events)
    assert result.failed_count == 20
    assert any("permission" in issue.lower() for issue in result.actionable_issues)


def test_analyze_logs_empty():
    result = analyze_logs([])
    assert result.total_events == 0
    assert result.indexed_count == 0
    assert result.groups == []


# --- The certificate the connector uses is still on the app -------------------
#
# Expiry is read from state, so it cannot tell you whether the directory still
# carries the certificate. The private key in Secrets Manager stays perfectly
# intact when the app's certificate is replaced, so the AWS side looks healthy
# while authentication is broken. This is the check that catches that.

_RECORDED = "MU2ZxMbvstlL9kFKLLyYrg6QF50"
_OTHER = "ZZZZxMbvstlL9kFKLLyYrg6QF50"


def test_certificate_installed_passes_when_the_app_carries_it():
    check = check_certificate_installed(
        recorded_thumbprint=_RECORDED, installed_thumbprints=[_OTHER, _RECORDED]
    )
    assert check.passed
    assert check.data["verified"] is True


def test_certificate_installed_fails_when_the_app_carries_a_different_one():
    """The desync: AWS holds a private key the directory no longer trusts."""
    check = check_certificate_installed(
        recorded_thumbprint=_RECORDED, installed_thumbprints=[_OTHER]
    )
    assert not check.passed
    assert "--rotate-cert" in check.details


def test_certificate_installed_fails_when_the_app_carries_none():
    check = check_certificate_installed(
        recorded_thumbprint=_RECORDED, installed_thumbprints=[]
    )
    assert not check.passed


def test_certificate_unreadable_reports_unverified_rather_than_failing():
    """An operator diagnosing the AWS side may hold no Graph access at all, and
    one unverifiable check must not fail the whole diagnosis."""
    check = check_certificate_installed(
        recorded_thumbprint=_RECORDED, installed_thumbprints=None
    )
    assert check.passed
    assert check.data["verified"] is False
    assert "Not verified" in check.details


def test_certificate_check_is_inert_without_a_recorded_thumbprint():
    check = check_certificate_installed(
        recorded_thumbprint=None, installed_thumbprints=[_OTHER]
    )
    assert check.passed
    assert check.data["verified"] is False


def test_a_failing_certificate_check_is_attributed_to_the_source_side():
    """Attribution drives the diagnosis summary; this failure is not AWS's."""
    check = check_certificate_installed(
        recorded_thumbprint=_RECORDED, installed_thumbprints=[_OTHER]
    )
    assert check.side == "source"
    assert build_diagnose_result("c", [check]).status != "healthy"
