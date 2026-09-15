"""Diagnostic checks for a configured connector.

  * CloudTrail permission check (scan for AccessDenied events)
  * Secret validation (parse + verify required fields)
  * Ingestion log analysis (delegates to log_analysis.py)
  * Cert expiry check

Each check produces a structured CheckResult. The DiagnoseResult aggregates
all checks and attributes the failure to source-side or AWS-side.

The credential mint check is not one of these: minting a token needs the
private key, which never reaches the state file, so `service.validate` runs it
as an informational step instead.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class CheckResult:
    """Result of a single diagnostic check."""

    name: str
    passed: bool
    details: str  # human-readable explanation
    data: dict = field(default_factory=dict)  # raw data for programmatic use
    side: Literal["source", "aws", "shared"] = "shared"


@dataclass
class DiagnoseResult:
    """Structured result from a full diagnose operation."""

    connector: str
    status: Literal["healthy", "degraded", "failing"]
    checks: list[CheckResult]
    root_cause: str | None = None
    suggested_fix: str | None = None
    attribution: Literal["source", "aws", "unknown"] = "unknown"


# --- CloudTrail permission check ---------------------------------------------


def check_cloudtrail_permissions(
    *,
    session: Any,
    region: str,
    role_arn: str | None = None,
    secret_arn: str | None = None,
    lookback_minutes: int = 60,
) -> CheckResult:
    """Scan CloudTrail for recent AccessDenied events on KB resources.

    Looks for denied calls involving the KB role, secret, or cert bucket.
    """
    ct = session.client("cloudtrail")
    now = _dt.datetime.now(_dt.timezone.utc)
    start = now - _dt.timedelta(minutes=lookback_minutes)

    denied_events: list[dict] = []
    try:
        kwargs: dict = {
            "LookupAttributes": [
                {"AttributeKey": "ReadOnly", "AttributeValue": "false"},
            ],
            "StartTime": start,
            "EndTime": now,
            "MaxResults": 50,
        }
        resp = ct.lookup_events(**kwargs)
        for event in resp.get("Events", []):
            event_data = json.loads(event.get("CloudTrailEvent", "{}"))
            error_code = event_data.get("errorCode", "")
            if "Denied" in error_code or "Unauthorized" in error_code:
                event_name = event_data.get("eventName", "")
                # Filter to relevant resources
                is_relevant = False
                if role_arn and role_arn in json.dumps(event_data):
                    is_relevant = True
                if secret_arn and secret_arn in json.dumps(event_data):
                    is_relevant = True
                if any(kw in event_name.lower() for kw in
                       ("getsecret", "getobject", "assumerole", "putmetric")):
                    is_relevant = True

                if is_relevant:
                    denied_events.append({
                        "event_name": event_name,
                        "error_code": error_code,
                        "time": event.get("EventTime", "").isoformat() if hasattr(event.get("EventTime", ""), "isoformat") else str(event.get("EventTime", "")),
                        "source_ip": event_data.get("sourceIPAddress", ""),
                    })
    except Exception as exc:
        return CheckResult(
            name="cloudtrail_permissions",
            passed=True,  # Can't check = assume OK
            details=f"Could not scan CloudTrail: {exc}",
            data={"error": str(exc)},
            side="aws",
        )

    if denied_events:
        details_parts = [f"{len(denied_events)} AccessDenied event(s) in the last {lookback_minutes}m:"]
        for ev in denied_events[:5]:
            details_parts.append(f"  {ev['event_name']}: {ev['error_code']}")
        return CheckResult(
            name="cloudtrail_permissions",
            passed=False,
            details="\n".join(details_parts),
            data={"denied_events": denied_events},
            side="aws",
        )

    return CheckResult(
        name="cloudtrail_permissions",
        passed=True,
        details=f"No AccessDenied events in the last {lookback_minutes}m.",
        data={},
        side="aws",
    )


# --- Secret validation -------------------------------------------------------


def check_secret_validity(
    *,
    session: Any,
    secret_arn: str,
    connector_type: str,
    credential: str = "cert",
) -> CheckResult:
    """Read and validate the connector secret has all required fields."""
    sm = session.client("secretsmanager")
    try:
        resp = sm.get_secret_value(SecretId=secret_arn)
        body = json.loads(resp["SecretString"])
    except Exception as exc:
        return CheckResult(
            name="secret_validation",
            passed=False,
            details=f"Cannot read secret {secret_arn}: {exc}",
            data={"error": str(exc)},
            side="aws",
        )

    # Check required fields based on connector type + credential
    missing: list[str] = []
    if "clientId" not in body:
        missing.append("clientId")

    cred = credential.strip().lower()
    if cred == "cert":
        if "certificatePassword" not in body:
            missing.append("certificatePassword")
    elif cred in ("client_secret", "client-secret"):
        if "clientSecret" not in body:
            missing.append("clientSecret")
    elif cred == "ropc":
        for f in ("clientSecret", "userName", "password"):
            if f not in body:
                missing.append(f)
    elif cred in ("oauth2_refresh", "oauth2-refresh"):
        for f in ("clientSecret", "refreshToken"):
            if f not in body:
                missing.append(f)

    if missing:
        return CheckResult(
            name="secret_validation",
            passed=False,
            details=f"Secret is missing required fields: {', '.join(missing)}",
            data={"missing_fields": missing, "present_fields": list(body.keys())},
            side="aws",
        )

    return CheckResult(
        name="secret_validation",
        passed=True,
        details="Secret contains all required fields.",
        data={"present_fields": list(body.keys())},
        side="aws",
    )


# --- Ingestion log analysis --------------------------------------------------


def default_log_group_name(knowledge_base_id: str) -> str:
    """The conventional CloudWatch log group for a KB's vended APPLICATION_LOGS.

    Vended log delivery is configured per knowledge base and the destination is
    chosen when delivery is set up, so this is a convention rather than a
    guarantee — callers can override with --log-group.
    """
    return f"/aws/bedrock/knowledgebases/{knowledge_base_id}"


def check_ingestion_logs(
    *,
    session: Any,
    log_group_name: str,
    lookback_minutes: int = 60,
    limit: int = 10000,
    redact: bool = True,
) -> CheckResult:
    """Analyze per-document ingestion events from CloudWatch Logs.

    This answers the question the other checks can't: an ingestion job reports
    "scanned 400, indexed 40" and the operator needs to know what happened to
    the other 360. The per-document log events carry the status and reason, so
    grouping them by reason turns a count into a cause.

    Sample document locations are redacted by default because this output is
    routinely pasted into tickets — see log_analysis.redact_document_location.
    A missing log group is reported as a pass with an explanation rather than a
    failure: vended log delivery is opt-in, so its absence is a setup gap, not
    evidence that the connector is broken.
    """
    from kb_connector.core.errors import AwsError
    from kb_connector.core.log_analysis import (
        analyze_logs,
        fetch_ingestion_logs,
        parse_document_events,
    )

    now = _dt.datetime.now(_dt.timezone.utc)
    start = now - _dt.timedelta(minutes=lookback_minutes)

    try:
        raw_events = fetch_ingestion_logs(
            session=session,
            log_group_name=log_group_name,
            start_time_ms=int(start.timestamp() * 1000),
            end_time_ms=int(now.timestamp() * 1000),
            limit=limit,
        )
    except AwsError as exc:
        text = str(exc)
        if "ResourceNotFound" in text:
            return CheckResult(
                name="ingestion_logs",
                passed=True,
                details=(
                    f"No CloudWatch log group {log_group_name!r}. Enable vended "
                    f"log delivery on the knowledge base to get per-document "
                    f"ingestion detail, or pass --log-group if it delivers "
                    f"elsewhere."
                ),
                data={"log_group": log_group_name, "available": False},
                side="aws",
            )
        return CheckResult(
            name="ingestion_logs",
            passed=True,  # can't read logs != connector is unhealthy
            details=f"Could not read ingestion logs from {log_group_name!r}: {exc}",
            data={"log_group": log_group_name, "error": text},
            side="aws",
        )

    parsed = parse_document_events(raw_events)
    if not parsed:
        return CheckResult(
            name="ingestion_logs",
            passed=True,
            details=(
                f"No per-document ingestion events in the last "
                f"{lookback_minutes}m in {log_group_name!r}."
            ),
            data={"log_group": log_group_name, "total_events": 0},
            side="aws",
        )

    analysis = analyze_logs(parsed, redact=redact)

    # Attribution: permission and ACL failures are source-side problems (the
    # connector app can't read what it was pointed at); everything else is
    # reported as shared because the cause could be either side.
    lowered = " ".join(analysis.actionable_issues).lower()
    side: Literal["source", "aws", "shared"] = (
        "source" if ("permission" in lowered or "acl" in lowered) else "shared"
    )

    data = {
        "log_group": log_group_name,
        "total_events": analysis.total_events,
        "indexed": analysis.indexed_count,
        "failed": analysis.failed_count,
        "skipped": analysis.skipped_count,
        "filtered": analysis.filtered_count,
        "redacted": redact,
        "groups": [
            {
                "status": g.status,
                "reason": g.reason,
                "count": g.count,
                "sample_documents": g.sample_documents,
            }
            for g in analysis.groups
        ],
        "actionable_issues": analysis.actionable_issues,
    }

    if analysis.actionable_issues:
        summary = "; ".join(analysis.actionable_issues[:3])
        return CheckResult(
            name="ingestion_logs",
            passed=False,
            details=(
                f"{analysis.failed_count} failed, {analysis.skipped_count} "
                f"skipped of {analysis.total_events} document event(s). {summary}"
            ),
            data=data,
            side=side,
        )

    return CheckResult(
        name="ingestion_logs",
        passed=True,
        details=(
            f"{analysis.indexed_count} indexed, {analysis.failed_count} failed, "
            f"{analysis.skipped_count} skipped of {analysis.total_events} "
            f"document event(s)."
        ),
        data=data,
        side="aws",
    )


# --- Certificate expiry check ------------------------------------------------


def check_cert_expiry(
    *,
    cert_not_after: str | None,
    warn_days: int = 30,
) -> CheckResult:
    """Check if the connector's certificate is expired or expiring soon."""
    if not cert_not_after:
        return CheckResult(
            name="cert_expiry",
            passed=True,
            details="No certificate expiry tracked in state (non-cert credential or fresh setup).",
            data={},
            side="source",
        )

    try:
        expiry = _dt.datetime.fromisoformat(cert_not_after)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=_dt.timezone.utc)
    except (ValueError, TypeError):
        return CheckResult(
            name="cert_expiry",
            passed=False,
            details=f"Cannot parse cert expiry date: {cert_not_after}",
            data={"cert_not_after": cert_not_after},
            side="source",
        )

    now = _dt.datetime.now(_dt.timezone.utc)
    days_remaining = (expiry - now).days

    if days_remaining < 0:
        return CheckResult(
            name="cert_expiry",
            passed=False,
            details=f"Certificate EXPIRED {-days_remaining} days ago (expired {cert_not_after}).",
            data={"days_remaining": days_remaining, "cert_not_after": cert_not_after},
            side="source",
        )

    if days_remaining < warn_days:
        return CheckResult(
            name="cert_expiry",
            passed=False,
            details=f"Certificate expires in {days_remaining} days ({cert_not_after}). Rotate soon.",
            data={"days_remaining": days_remaining, "cert_not_after": cert_not_after},
            side="source",
        )

    return CheckResult(
        name="cert_expiry",
        passed=True,
        details=f"Certificate valid for {days_remaining} more days (expires {cert_not_after}).",
        data={"days_remaining": days_remaining, "cert_not_after": cert_not_after},
        side="source",
    )


# --- Aggregate diagnostics ---------------------------------------------------


def build_diagnose_result(
    connector: str,
    checks: list[CheckResult],
) -> DiagnoseResult:
    """Aggregate check results into a DiagnoseResult with attribution."""
    failed_checks = [c for c in checks if not c.passed]

    if not failed_checks:
        return DiagnoseResult(
            connector=connector,
            status="healthy",
            checks=checks,
            attribution="unknown",
        )

    # Attribute: if all failures are same side, attribute there
    sides = set(c.side for c in failed_checks)
    if sides == {"source"}:
        attribution: Literal["source", "aws", "unknown"] = "source"
    elif sides == {"aws"}:
        attribution = "aws"
    else:
        attribution = "unknown"

    # Determine severity
    critical_failures = [c for c in failed_checks if c.name in (
        "cloudtrail_permissions", "secret_validation", "cert_expiry",
        "ingestion_logs",
    )]
    status: Literal["healthy", "degraded", "failing"] = "failing" if critical_failures else "degraded"

    # Suggest fix from first critical failure
    root_cause = failed_checks[0].details if failed_checks else None
    suggested_fix = _suggest_fix(failed_checks[0]) if failed_checks else None

    return DiagnoseResult(
        connector=connector,
        status=status,
        checks=checks,
        root_cause=root_cause,
        suggested_fix=suggested_fix,
        attribution=attribution,
    )


def _suggest_fix(check: CheckResult) -> str | None:
    """Generate a suggested fix based on the check type and failure."""
    if check.name == "cloudtrail_permissions":
        return (
            "The KB's IAM role is missing permissions. Extend the role's inline "
            "policy to include the denied action, or re-run setup to auto-provision."
        )
    if check.name == "secret_validation":
        missing = check.data.get("missing_fields", [])
        return f"Update the secret to include: {', '.join(missing)}"
    if check.name == "cert_expiry":
        days = check.data.get("days_remaining", 0)
        if days < 0:
            return "Certificate has expired. Run `kb-connector setup` to generate a new one."
        return "Certificate is expiring soon. Plan a rotation."
    if check.name == "ingestion_logs":
        issues = check.data.get("actionable_issues") or []
        joined = " ".join(issues).lower()
        if "permission" in joined or "acl" in joined:
            return (
                "Documents are failing on access, not on AWS configuration. "
                "Check that the connector's app registration still holds the "
                "permissions the ACL crawl needs (admin consent can be revoked "
                "independently of the app), then re-run ingestion."
            )
        if issues:
            return (
                "Group the failures by reason (see the ingestion_logs check "
                "data) and address the largest group first; the reason strings "
                "come from the connector itself."
            )
    return None
