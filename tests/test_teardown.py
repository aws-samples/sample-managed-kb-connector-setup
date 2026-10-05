"""Tests for teardown: the delete primitives, the plan, and the delete flow.

The flow tests run the real CLI against a config and state file in a temp
directory, with the AWS session, the control-plane target, and the delete
primitives replaced by fakes that record what they were asked to do.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kb_connector.core import teardown as td
from kb_connector.core.errors import ConnectorError

_KB = "KB12345678"
_DS = "DS12345678"
_SECRET = "arn:aws:secretsmanager:us-west-2:111122223333:secret:kb-connector/c1-a1"
_ROLE_ARN = "arn:aws:iam::111122223333:role/kb-connector-c1-role"


# --- ingestion job precheck ------------------------------------------------------


def _target_with_jobs(jobs: list[dict]) -> MagicMock:
    target = MagicMock()
    target.list_ingestion_jobs.return_value = {"ingestionJobSummaries": jobs}
    return target


def test_find_active_returns_in_progress_job():
    target = _target_with_jobs([{"ingestionJobId": "JOB-RUNNING", "status": "IN_PROGRESS"}])
    assert td.find_active_ingestion_job(target, "kb", "ds") == "JOB-RUNNING"


def test_find_active_returns_none_for_all_terminal():
    target = _target_with_jobs([
        {"ingestionJobId": "JOB-OLD", "status": "COMPLETE"},
        {"ingestionJobId": "JOB-OLDER", "status": "FAILED"},
    ])
    assert td.find_active_ingestion_job(target, "kb", "ds") is None


def test_find_active_returns_none_on_no_jobs():
    assert td.find_active_ingestion_job(_target_with_jobs([]), "kb", "ds") is None


def test_terminal_states():
    assert {"COMPLETE", "COMPLETED", "FAILED", "STOPPED"} == set(td.TERMINAL_INGESTION_STATES)


def test_stop_and_wait_returns_the_terminal_status(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    target = MagicMock()
    target.get_ingestion_job.return_value = {"ingestionJob": {"status": "STOPPED"}}
    assert td.stop_and_wait(target, "kb", "ds", "JOB-1") == "STOPPED"
    target.stop_ingestion_job.assert_called_once_with("kb", "ds", "JOB-1")


def test_stop_and_wait_raises_when_the_stop_request_fails():
    target = MagicMock()
    target.stop_ingestion_job.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        td.stop_and_wait(target, "kb", "ds", "JOB-1")


# --- T-02: delete_role refuses before it removes anything ------------------------


def _iam_session(inline=(), attached=(), profiles=()):
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


def test_delete_role_removes_only_exact_tool_policies():
    session, iam = _iam_session(inline=["kb-connector-access"])
    td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_called_once_with(
        RoleName="kb-connector-c1-role", PolicyName="kb-connector-access"
    )
    iam.delete_role.assert_called_once_with(RoleName="kb-connector-c1-role")


def test_delete_role_refuses_foreign_inline_policy_without_deleting():
    session, iam = _iam_session(inline=["kb-connector-access", "app-team-dynamodb-access"])
    with pytest.raises(ConnectorError, match="did not create"):
        td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_does_not_claim_prefix_lookalike_policies():
    """`kb-connector-audit` matches the name prefix but the tool never wrote it."""
    session, iam = _iam_session(inline=["kb-connector-access", "kb-connector-audit"])
    with pytest.raises(ConnectorError, match="kb-connector-audit"):
        td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()


def test_delete_role_refuses_managed_policy_without_deleting():
    session, iam = _iam_session(inline=["kb-connector-access"], attached=["AdministratorAccess"])
    with pytest.raises(ConnectorError, match="managed policies"):
        td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_refuses_role_in_instance_profile():
    session, iam = _iam_session(inline=["kb-connector-access"], profiles=["web-tier-profile"])
    with pytest.raises(ConnectorError, match="instance profile"):
        td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
    iam.delete_role.assert_not_called()


def test_delete_role_handles_iam_role_paths():
    session, iam = _iam_session()
    td.delete_role(session, "arn:aws:iam::111122223333:role/service-roles/nested/MyRole")
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
    session, iam = _iam_session()
    with pytest.raises(ConnectorError):
        td.delete_role(session, bad_arn)
    iam.delete_role.assert_not_called()
    iam.delete_role_policy.assert_not_called()


def test_tool_policy_names_cover_every_authored_policy():
    """A new put_role_policy name must be added to TOOL_INLINE_POLICY_NAMES,
    or teardown refuses to remove the role."""
    import inspect

    from kb_connector.core import provisioning
    from kb_connector.core.provisioning import TOOL_INLINE_POLICY_NAMES

    sig = inspect.signature(provisioning.ensure_kb_role)
    assert sig.parameters["inline_policy_name"].default in TOOL_INLINE_POLICY_NAMES
    sig = inspect.signature(provisioning._attach_supplemental_access_policy)
    assert sig.parameters["policy_name"].default in TOOL_INLINE_POLICY_NAMES


# --- T-24: destructive targets taken from state are shape-checked ----------------


def _client_session():
    client = MagicMock()
    session = MagicMock()
    session.client.return_value = client
    return session, client


def test_delete_secret_refuses_a_non_secret_arn():
    session, sm = _client_session()
    with pytest.raises(ConnectorError):
        td.delete_secret(session, _ROLE_ARN)
    sm.delete_secret.assert_not_called()


def test_delete_secret_force_deletes_a_real_secret_arn():
    session, sm = _client_session()
    td.delete_secret(session, _SECRET)
    sm.delete_secret.assert_called_once_with(SecretId=_SECRET, ForceDeleteWithoutRecovery=True)


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
    session, s3 = _client_session()
    with pytest.raises(ConnectorError):
        td.delete_cert(session, bucket, key)
    s3.delete_object.assert_not_called()


def test_delete_cert_accepts_a_real_target():
    session, s3 = _client_session()
    td.delete_cert(session, "kb-connector-certs-111122223333-us-west-2", "kb/c1.p12")
    s3.delete_object.assert_called_once_with(
        Bucket="kb-connector-certs-111122223333-us-west-2", Key="kb/c1.p12"
    )


# --- the flow, through the CLI ---------------------------------------------------


class _Recorder:
    """Fakes for everything teardown reaches, recording what it was asked."""

    def __init__(self, *, active_job=None, fail=()):
        self.calls: list[str] = []
        self.sessions: list[tuple] = []
        self.fail = set(fail)
        self.target = MagicMock()
        self.target.list_ingestion_jobs.return_value = {
            "ingestionJobSummaries": (
                [{"ingestionJobId": active_job, "status": "IN_PROGRESS"}] if active_job else []
            )
        }
        self.target.get_ingestion_job.return_value = {"ingestionJob": {"status": "STOPPED"}}
        self.target.delete_data_source.side_effect = lambda kb, ds: self._call("ds")
        self.target.delete_knowledge_base.side_effect = lambda kb: self._call("kb")

    def _call(self, kind):
        self.calls.append(kind)
        if kind in self.fail:
            raise RuntimeError(f"{kind} delete failed")

    def install(self, monkeypatch):
        monkeypatch.setattr(
            "kb_connector.context.default_session_factory",
            lambda region, profile: self.sessions.append((region, profile)) or MagicMock(),
        )
        monkeypatch.setattr(
            "kb_connector.context.default_target_factory", lambda **kw: self.target
        )
        monkeypatch.setattr(td, "delete_secret", lambda s, arn: self._call("secret"))
        monkeypatch.setattr(td, "delete_role", lambda s, arn: self._call("role"))
        monkeypatch.setattr(td, "delete_cert", lambda s, b, k: self._call("cert"))
        monkeypatch.setattr(td, "delete_entra_app", lambda **kw: self._call("app"))
        monkeypatch.setattr("time.sleep", lambda _: None)
        return self


def _project(tmp_path: Path, monkeypatch, *, owners: dict, config_region="us-west-2",
             state_region="us-west-2", **fields) -> Path:
    """A project dir with one connector `c1`, resources and ownership as given."""
    region_line = f'region = "{config_region}"\n' if config_region else ""
    (tmp_path / "kb-connector.toml").write_text(
        f'[connectors.c1]\ntype = "sharepoint"\n{region_line}'
    )
    state = {
        "connector_type": "sharepoint",
        "region": state_region,
        "created_resources": owners,
        **fields,
    }
    path = tmp_path / "kb-connector.state.json"
    path.write_text(json.dumps({"connectors": {"c1": state}}))
    monkeypatch.chdir(tmp_path)
    return path


def _all_resources():
    return dict(
        knowledge_base_id=_KB, data_source_id=_DS, secret_arn=_SECRET,
        kb_role_arn=_ROLE_ARN, cert_s3_bucket="kb-connector-certs-111122223333-us-west-2",
        cert_s3_key="kb-connector/c1.p12", client_app_id="app-1",
        client_app_object_id="obj-1", tenant_id="t-1",
    )


def _teardown(*argv):
    from kb_connector.cli.main import build_parser

    args = build_parser().parse_args(["teardown", "c1", *argv])
    return args.func(args)


def _state(path: Path) -> dict:
    return json.loads(path.read_text())["connectors"]


_TOOL = {k: "tool" for k in ("ds", "kb", "secret", "role", "cert", "app")}


def test_full_teardown_deletes_control_plane_first_and_clears_state(tmp_path, monkeypatch):
    path = _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.calls[:2] == ["ds", "kb"]
    assert set(rec.calls) == set(_TOOL)
    assert "c1" not in _state(path)


def test_control_plane_failure_keeps_credentials_and_exits_nonzero(tmp_path, monkeypatch):
    path = _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    rec = _Recorder(fail={"kb"}).install(monkeypatch)
    assert _teardown("--yes") == 1
    assert rec.calls == ["ds", "kb"]
    remaining = _state(path)["c1"]
    assert remaining["knowledge_base_id"] == _KB
    assert remaining["secret_arn"] == _SECRET
    assert remaining["data_source_id"] is None


def test_a_credential_failure_exits_nonzero_and_keeps_the_entry(tmp_path, monkeypatch):
    path = _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    _Recorder(fail={"role"}).install(monkeypatch)
    assert _teardown("--yes") == 1
    assert _state(path)["c1"]["kb_role_arn"] == _ROLE_ARN


def test_running_job_blocks_teardown_without_force(tmp_path, monkeypatch):
    path = _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    before = path.read_text()
    rec = _Recorder(active_job="JOB-1").install(monkeypatch)
    assert _teardown("--yes") == 1
    assert rec.calls == []
    assert path.read_text() == before


def test_force_stops_the_running_job_then_deletes(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    rec = _Recorder(active_job="JOB-1").install(monkeypatch)
    assert _teardown("--yes", "--force") == 0
    rec.target.stop_ingestion_job.assert_called_once_with(_KB, _DS, "JOB-1")
    assert rec.calls[:2] == ["ds", "kb"]


def test_a_failed_job_check_does_not_block_cleanup(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    rec = _Recorder().install(monkeypatch)
    rec.target.list_ingestion_jobs.side_effect = RuntimeError("network down")
    assert _teardown("--yes") == 0
    assert "could not check for a running ingestion job" in capsys.readouterr().err


@pytest.mark.parametrize("marker", ["tool", "external"])
def test_dry_run_writes_no_state_and_calls_nothing(tmp_path, monkeypatch, marker):
    path = _project(tmp_path, monkeypatch, owners={"secret": marker}, secret_arn=_SECRET)
    before = path.read_text()
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--dry-run") == 0
    assert rec.calls == [] and rec.sessions == []
    assert path.read_text() == before


def test_all_adopted_keeps_the_state_entry(tmp_path, monkeypatch):
    """The entry is the only record that this connector is attached to them."""
    path = _project(tmp_path, monkeypatch, owners={"secret": "external"}, secret_arn=_SECRET)
    before = path.read_text()
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.calls == []
    assert path.read_text() == before


def test_include_adopted_deletes_adopted_resources(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, owners={"secret": "external"}, secret_arn=_SECRET)
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes", "--include-adopted") == 0
    assert rec.calls == ["secret"]


def test_scoped_teardown_keeps_the_entry(tmp_path, monkeypatch):
    path = _project(tmp_path, monkeypatch, owners=_TOOL, **_all_resources())
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes", "--only", "secret") == 0
    assert rec.calls == ["secret"]
    assert _state(path)["c1"]["secret_arn"] is None
    assert _state(path)["c1"]["knowledge_base_id"] == _KB


def test_nothing_tracked_is_a_no_op(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, owners={})
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.calls == []
    assert "Nothing to tear down" in capsys.readouterr().out


# --- region: delete where the resources are, or refuse ----------------------------


def test_state_region_beats_config(tmp_path, monkeypatch):
    """State records where the resources are; config may have been edited."""
    _project(tmp_path, monkeypatch, owners={"secret": "tool"}, secret_arn=_SECRET,
             config_region="eu-west-1", state_region="us-west-2")
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.sessions[0][0] == "us-west-2"


def test_config_region_when_state_has_none(tmp_path, monkeypatch):
    """State without a region falls back to config, not boto's default region."""
    _project(tmp_path, monkeypatch, owners={"secret": "tool"}, secret_arn=_SECRET,
             config_region="eu-west-1", state_region=None)
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.sessions[0][0] == "eu-west-1"


def test_refuses_without_any_region_before_prompting(tmp_path, monkeypatch, capsys):
    _project(tmp_path, monkeypatch, owners={"secret": "tool"}, secret_arn=_SECRET,
             config_region=None, state_region=None)
    rec = _Recorder().install(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("prompted"))
    monkeypatch.setattr("sys.argv", ["kb-connector", "teardown", "c1"])
    from kb_connector.cli.main import main

    assert main() == 1
    assert "No region known" in capsys.readouterr().err
    assert rec.calls == [] and rec.sessions == []


def test_entra_only_teardown_needs_no_region(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, owners={"app": "tool"}, client_app_id="app-1",
             client_app_object_id="obj-1", tenant_id="t-1",
             config_region=None, state_region=None)
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.calls == ["app"]


def test_profile_comes_from_config(tmp_path, monkeypatch):
    _project(tmp_path, monkeypatch, owners={"secret": "tool"}, secret_arn=_SECRET)
    with open("kb-connector.toml", "a") as f:
        f.write('profile = "team-profile"\n')
    rec = _Recorder().install(monkeypatch)
    assert _teardown("--yes") == 0
    assert rec.sessions[0] == ("us-west-2", "team-profile")


def test_delete_role_removes_per_connector_content_policies():
    session, iam = _iam_session(inline=[
        "kb-connector-access", "kb-connector-s3-content-access",
        "kb-connector-s3-content-access-other",
    ])
    td.delete_role(session, _ROLE_ARN)
    assert iam.delete_role_policy.call_count == 3
    iam.delete_role.assert_called_once()


@pytest.mark.parametrize("name", [
    "kb-connector-s3-content-access-",
    "kb-connector-s3-content-access-bad name",
    "kb-connector-s3-content-accessx",
])
def test_lookalike_content_policy_names_are_foreign(name):
    session, iam = _iam_session(inline=["kb-connector-access", name])
    with pytest.raises(ConnectorError, match="did not create"):
        td.delete_role(session, _ROLE_ARN)
    iam.delete_role_policy.assert_not_called()
