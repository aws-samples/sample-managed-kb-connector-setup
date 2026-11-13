"""Pure helpers behind the Amazon Quick validate and diagnose checks."""

from __future__ import annotations

import datetime as _dt
import json

import pytest

from kb_connector.quick import checks

_ROLE = "arn:aws:iam::123456789012:role/service-role/aws-quicksight-kms-role-v0"
_KEY = "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-0000-0000-0000-000000000001"
_ROOT = {
    "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "kms:*", "Resource": "*",
}


def _policy(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [_ROOT, *statements]})


@pytest.mark.parametrize("principal", [_ROLE, [_ROLE, "arn:aws:iam::123456789012:role/other"]])
def test_key_policy_allows_sign_for_a_str_or_list_principal(principal):
    statement = {"Effect": "Allow", "Principal": {"AWS": principal},
                 "Action": ["kms:Sign", "kms:GetPublicKey"], "Resource": "*"}
    assert checks.key_policy_allows_sign(_policy(statement), _ROLE)


def test_key_policy_allows_sign_with_kms_star_and_a_single_statement():
    policy = {"Statement": {"Effect": "Allow", "Principal": {"AWS": _ROLE},
                            "Action": "kms:*", "Resource": "*"}}
    assert checks.key_policy_allows_sign(policy, _ROLE)


@pytest.mark.parametrize("statement", [
    {"Effect": "Deny", "Principal": {"AWS": _ROLE}, "Action": "kms:Sign"},
    {"Effect": "Allow", "Principal": "*", "Action": "kms:Sign"},
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:Sign"},
    {"Effect": "Allow", "Principal": {"AWS": _ROLE}, "Action": "kms:GetPublicKey"},
])
def test_key_policy_ignores_deny_wildcards_and_other_actions(statement):
    assert not checks.key_policy_allows_sign(_policy(statement), _ROLE)


def test_the_default_root_statement_does_not_count():
    assert not checks.key_policy_allows_sign(_policy(), _ROLE)
    assert not checks.key_policy_allows_sign("not json", _ROLE)


def test_grants_allow_sign():
    assert checks.grants_allow_sign(
        [{"GranteePrincipal": _ROLE, "Operations": ["Sign", "GetPublicKey"]}], _ROLE
    )
    assert not checks.grants_allow_sign(
        [{"GranteePrincipal": _ROLE, "Operations": ["GetPublicKey"]}], _ROLE
    )
    assert not checks.grants_allow_sign(
        [{"GranteePrincipal": "arn:aws:iam::123456789012:role/other",
          "Operations": ["Sign"]}], _ROLE
    )
    assert not checks.grants_allow_sign([], _ROLE)


def _kb(status: str | None, count: int = 0) -> dict:
    kb: dict = {"KnowledgeBaseId": "kb-1", "Status": "ACTIVE", "DocumentCount": count}
    if status:
        kb["LatestIngestionSummary"] = {"IngestionId": "ing-1", "IngestionStatus": status}
    return kb


@pytest.mark.parametrize("status,passed", [
    ("COMPLETED", True), ("QUEUED", True), ("RUNNING", True),
    ("INCOMPLETE", False), ("FAILED", False), ("TIMEOUT", False), ("CANCELLED", False),
])
def test_latest_sync_status_table(status, passed):
    result = checks.check_kb_latest_sync(_kb(status))
    assert not isinstance(result, str)
    assert result.passed is passed
    if status in ("QUEUED", "RUNNING"):
        assert "in progress" in result.details
    if not passed:
        assert "sync report" in result.details and checks.SYNC_REPORT_DOCS in result.details


def test_latest_sync_without_a_summary_is_a_note():
    assert isinstance(checks.check_kb_latest_sync(_kb(None)), str)


def test_kb_documents():
    result = checks.kb_documents(_kb("COMPLETED", 33))
    assert not isinstance(result, str) and result.passed
    note = checks.kb_documents(_kb("RUNNING", 0))
    assert isinstance(note, str) and "RUNNING" in note
    empty = checks.kb_documents(_kb("COMPLETED", 0))
    assert not isinstance(empty, str) and not empty.passed


def _event(event_id: str, body: dict) -> dict:
    return {
        "EventId": event_id,
        "EventTime": _dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=_dt.timezone.utc),
        "CloudTrailEvent": json.dumps(body),
    }


def test_sign_denials_match_the_key_in_error_message_without_resources():
    caller = "arn:aws:sts::123456789012:assumed-role/aws-quicksight-kms-role-v0/quick"
    denied = {
        "eventName": "Sign", "errorCode": "AccessDenied",
        "errorMessage": f"User: {caller} is not authorized to perform: kms:Sign "
                        f"on resource: {_KEY} because no identity-based policy allows it",
        "userIdentity": {"arn": caller},
    }
    other_key = dict(denied, errorMessage=denied["errorMessage"].replace(_KEY, "key/other"))
    allowed = {k: v for k, v in denied.items() if k not in ("errorCode", "errorMessage")}
    operator = dict(
        denied,
        userIdentity={"arn": "arn:aws:sts::123456789012:assumed-role/Admin/tester"},
        errorMessage=denied["errorMessage"].replace(caller, "arn:aws:sts::x:assumed-role/Admin/t"),
    )
    events = [_event("e1", denied), _event("e2", other_key), _event("e3", allowed),
              _event("e4", operator)]
    found = checks.sign_denials(events, _KEY, "aws-quicksight-kms-role-v0")
    assert found == [{"event_id": "e1", "time": "2026-01-02T03:04:05+00:00"}]
    assert [d["event_id"] for d in checks.sign_denials(events, _KEY, None)] == ["e1", "e4"]
