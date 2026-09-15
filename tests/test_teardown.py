"""Unit tests for the teardown precheck and stop-and-wait helpers.

The destructive teardown loop itself isn't unit-tested (it'd need a full
mock of a session, target, and Graph client that exercises every branch).
What IS tested is the precheck — the gate that blocks teardown while an
ingestion job is in progress, which is what stops a delete racing a live
crawl.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kb_connector.cli.teardown import (
    _find_active_ingestion_job,
    _stop_and_wait_for_terminal,
    _TERMINAL_INGESTION_STATES,
)
from kb_connector.core.errors import ConnectorError


def _fake_target_with_jobs(jobs: list[dict]) -> MagicMock:
    """Build a fake target whose client.buildtime returns the given job list."""
    target = MagicMock()
    target.client.buildtime.return_value = {"ingestionJobSummaries": jobs}
    return target


def test_find_active_returns_in_progress_job():
    target = _fake_target_with_jobs([
        {"ingestionJobId": "JOB-RUNNING", "status": "IN_PROGRESS"},
    ])
    with patch("kb_connector.targets.get_target", return_value=target):
        assert _find_active_ingestion_job(
            session=MagicMock(), region="us-west-2",
            kb_id="kb-1", ds_id="ds-1",
        ) == "JOB-RUNNING"


def test_find_active_returns_none_for_all_terminal():
    target = _fake_target_with_jobs([
        {"ingestionJobId": "JOB-OLD", "status": "COMPLETE"},
        {"ingestionJobId": "JOB-OLDER", "status": "FAILED"},
    ])
    with patch("kb_connector.targets.get_target", return_value=target):
        assert _find_active_ingestion_job(
            session=MagicMock(), region="us-west-2",
            kb_id="kb-1", ds_id="ds-1",
        ) is None


def test_find_active_returns_none_on_no_jobs():
    target = _fake_target_with_jobs([])
    with patch("kb_connector.targets.get_target", return_value=target):
        assert _find_active_ingestion_job(
            session=MagicMock(), region="us-west-2",
            kb_id="kb-1", ds_id="ds-1",
        ) is None


def test_find_active_handles_lookup_error():
    """A failed list call shouldn't block teardown — return None and let it proceed."""
    target = MagicMock()
    target.client.buildtime.side_effect = RuntimeError("network down")
    with patch("kb_connector.targets.get_target", return_value=target):
        assert _find_active_ingestion_job(
            session=MagicMock(), region="us-west-2",
            kb_id="kb-1", ds_id="ds-1",
        ) is None


def test_terminal_states_set_includes_expected_values():
    """Terminal states the precheck recognizes."""
    assert "COMPLETE" in _TERMINAL_INGESTION_STATES
    assert "COMPLETED" in _TERMINAL_INGESTION_STATES
    assert "FAILED" in _TERMINAL_INGESTION_STATES
    assert "STOPPED" in _TERMINAL_INGESTION_STATES
    assert "IN_PROGRESS" not in _TERMINAL_INGESTION_STATES
    assert "STARTING" not in _TERMINAL_INGESTION_STATES
    assert "STOPPING" not in _TERMINAL_INGESTION_STATES


def test_stop_and_wait_returns_when_terminal_observed(monkeypatch):
    """Once GET reports a terminal state, the polling loop returns."""
    target = MagicMock()
    target.client.buildtime.side_effect = [
        None,  # POST stop
        {"ingestionJob": {"status": "STOPPED"}},  # GET status
    ]
    monkeypatch.setattr("kb_connector.targets.get_target", lambda *a, **kw: target)
    monkeypatch.setattr("time.sleep", lambda _: None)
    _stop_and_wait_for_terminal(
        session=MagicMock(), region="us-west-2",
        kb_id="kb-1", ds_id="ds-1", job_id="JOB-1",
    )
    # Should have made two calls (POST stop, GET status)
    assert target.client.buildtime.call_count == 2


def test_stop_and_wait_proceeds_on_stop_failure(monkeypatch):
    """If StopIngestionJob fails, log and proceed — don't raise."""
    target = MagicMock()
    target.client.buildtime.side_effect = RuntimeError("boom")
    monkeypatch.setattr("kb_connector.targets.get_target", lambda *a, **kw: target)
    # Should not raise
    _stop_and_wait_for_terminal(
        session=MagicMock(), region="us-west-2",
        kb_id="kb-1", ds_id="ds-1", job_id="JOB-1",
    )


# --- T-02: teardown must not write state before it is allowed to ------------


def _args(**overrides):
    """Build a teardown argparse.Namespace with all defaults populated."""
    import argparse
    base = dict(
        connector="c1", kb=None, only=None, dry_run=False, yes=True, force=False,
        include_adopted=False, region="us-west-2", profile=None,
        auth_method="az", device_client_id=None, config=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _state_with(created_resources):
    """A StateFile holding one connector with a secret and the given ownership."""
    from kb_connector.core.state import ConnectorState, StateFile
    cs = ConnectorState(
        connector_type="sharepoint",
        region="us-west-2",
        secret_arn="arn:aws:secretsmanager:us-west-2:111122223333:secret:s-a1",
        created_resources=dict(created_resources),
    )
    return StateFile(connectors={"c1": cs})


def _run_with_spies(monkeypatch, state_file, args):
    """Run teardown with save_state spied and all deletion stubbed out."""
    from kb_connector.cli import teardown as td
    calls: list[str] = []
    monkeypatch.setattr(td, "load_state", lambda *a, **kw: state_file)
    monkeypatch.setattr(td, "save_state", lambda *a, **kw: calls.append("save"))
    monkeypatch.setattr(td, "load_config", lambda *a, **kw: MagicMock(
        connector_names=lambda: ["c1"]
    ))
    monkeypatch.setattr(td, "_delete_secret", lambda *a, **kw: None)
    monkeypatch.setattr(
        td, "_find_active_ingestion_job", lambda *a, **kw: None
    )
    monkeypatch.setattr("boto3.Session", lambda *a, **kw: MagicMock())
    rc = td._run_teardown(args)
    return rc, calls


@pytest.mark.parametrize("marker", ["tool", "external"])
def test_dry_run_writes_no_state(monkeypatch, marker):
    """--dry-run must not write state under any ownership shape.

    The "external" shape is the one worth pinning: with every candidate
    adopted, `resources` is empty and control reaches the nothing-to-delete
    branch, which sits ahead of the --dry-run check.
    """
    state_file = _state_with({"secret": marker})
    rc, calls = _run_with_spies(
        monkeypatch, state_file, _args(dry_run=True)
    )
    assert rc == 0
    assert calls == [], f"dry run wrote state (ownership={marker})"
    assert "c1" in state_file.connectors


def test_all_adopted_keeps_state_entry(monkeypatch):
    """Every candidate adopted: nothing to delete, and the entry must survive.

    The entry is the only record that this connector is attached to those
    still-live resources, so clearing it would strand them.
    """
    state_file = _state_with({"secret": "external"})
    rc, calls = _run_with_spies(monkeypatch, state_file, _args())
    assert rc == 0
    assert calls == [], "cleared state while adopted resources are still live"
    assert "c1" in state_file.connectors
    assert state_file.connectors["c1"].secret_arn is not None


def test_owned_resource_teardown_does_write_state(monkeypatch):
    """Control: a real teardown of an owned resource still persists state."""
    state_file = _state_with({"secret": "tool"})
    rc, calls = _run_with_spies(monkeypatch, state_file, _args())
    assert rc == 0
    assert calls == ["save"]


# --- T-02: _delete_role must refuse before it removes anything --------------


def _iam_session(inline=(), attached=(), profiles=()):
    """A session whose IAM client reports the given role attachments."""
    iam = MagicMock()
    iam.list_role_policies.return_value = {"PolicyNames": list(inline)}
    iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": n} for n in attached]
    }
    iam.list_instance_profiles_for_role.return_value = {
        "InstanceProfiles": [{"InstanceProfileName": n} for n in profiles]
    }
    session = MagicMock()
    session.client.return_value = iam
    return session, iam


_ROLE_ARN = "arn:aws:iam::111122223333:role/kb-connector-c1-role"


def test_delete_role_removes_only_exact_tool_policies():
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session(inline=["kb-connector-access"])
    _delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_called_once_with(
        RoleName="kb-connector-c1-role", PolicyName="kb-connector-access"
    )
    iam.delete_role.assert_called_once_with(RoleName="kb-connector-c1-role")


def test_delete_role_refuses_foreign_inline_policy_without_deleting():
    """Foreign policies must be caught before any delete, not after."""
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session(
        inline=["kb-connector-access", "app-team-dynamodb-access"]
    )
    with pytest.raises(ConnectorError, match="did not create"):
        _delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_does_not_claim_prefix_lookalike_policies():
    """`kb-connector-audit` matches the name prefix but the tool never wrote it."""
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session(
        inline=["kb-connector-access", "kb-connector-audit"]
    )
    with pytest.raises(ConnectorError, match="kb-connector-audit"):
        _delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()


def test_delete_role_refuses_managed_policy_without_deleting():
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session(
        inline=["kb-connector-access"], attached=["AdministratorAccess"]
    )
    with pytest.raises(ConnectorError, match="managed policies"):
        _delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_refuses_role_in_instance_profile():
    """A role in an instance profile is in use by an EC2 workload."""
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session(
        inline=["kb-connector-access"], profiles=["web-tier-profile"]
    )
    with pytest.raises(ConnectorError, match="instance profile"):
        _delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_handles_iam_role_paths():
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session()
    _delete_role(
        session, "arn:aws:iam::111122223333:role/service-roles/nested/MyRole"
    )
    iam.delete_role.assert_called_once_with(RoleName="MyRole")


@pytest.mark.parametrize(
    "bad_arn",
    [
        "OrganizationAccountAccessRole",   # bare name from a tampered state file
        "arn:aws:iam::111122223333:user/bob",
        "",
        "arn:aws:iam::111122223333:role/",
        "arn:aws:iam::111122223333:role/has spaces",
    ],
)
def test_delete_role_refuses_a_target_state_does_not_justify(bad_arn):
    from kb_connector.cli.teardown import _delete_role
    session, iam = _iam_session()
    with pytest.raises(ConnectorError):
        _delete_role(session, bad_arn)
    iam.delete_role.assert_not_called()
    iam.delete_role_policy.assert_not_called()


def test_tool_policy_names_cover_every_authored_policy():
    """Guards against a new put_role_policy name drifting out of the set.

    If this fails, a call site started writing an inline policy that teardown
    will refuse to remove. Add the name to TOOL_INLINE_POLICY_NAMES.
    """
    import inspect
    from kb_connector.core import provisioning
    from kb_connector.core.provisioning import TOOL_INLINE_POLICY_NAMES

    sig = inspect.signature(provisioning.ensure_kb_role)
    assert sig.parameters["inline_policy_name"].default in TOOL_INLINE_POLICY_NAMES
    sig = inspect.signature(provisioning._attach_supplemental_access_policy)
    assert sig.parameters["policy_name"].default in TOOL_INLINE_POLICY_NAMES


# --- T-18: destructive targets taken from state must be shape-checked -------


def test_delete_secret_refuses_a_non_secret_arn():
    """ForceDeleteWithoutRecovery has no undo, so the target is checked first."""
    from kb_connector.cli.teardown import _delete_secret
    sm = MagicMock()
    session = MagicMock()
    session.client.return_value = sm
    with pytest.raises(ConnectorError):
        _delete_secret(session, "arn:aws:kms:us-west-2:111122223333:key/abc")
    sm.delete_secret.assert_not_called()


def test_delete_secret_accepts_a_real_secret_arn():
    from kb_connector.cli.teardown import _delete_secret
    sm = MagicMock()
    session = MagicMock()
    session.client.return_value = sm
    arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:kb-connector/c1-a1"
    _delete_secret(session, arn)
    sm.delete_secret.assert_called_once_with(
        SecretId=arn, ForceDeleteWithoutRecovery=True
    )


@pytest.mark.parametrize(
    "bucket,key",
    [
        ("UPPER-CASE", "kb-connector/c1.p12"),
        ("ok-bucket-name", "/etc/passwd"),
        ("ok-bucket-name", "a/../../secrets/prod.p12"),
        ("ok-bucket-name", ""),
    ],
)
def test_delete_cert_refuses_an_implausible_target(bucket, key):
    from kb_connector.cli.teardown import _delete_cert
    s3 = MagicMock()
    session = MagicMock()
    session.client.return_value = s3
    with pytest.raises(ConnectorError):
        _delete_cert(session, bucket, key)
    s3.delete_object.assert_not_called()


def test_delete_cert_accepts_a_real_target():
    from kb_connector.cli.teardown import _delete_cert
    s3 = MagicMock()
    session = MagicMock()
    session.client.return_value = s3
    _delete_cert(session, "kb-connector-certs-111122223333-us-west-2", "kb/c1.p12")
    s3.delete_object.assert_called_once_with(
        Bucket="kb-connector-certs-111122223333-us-west-2", Key="kb/c1.p12"
    )
