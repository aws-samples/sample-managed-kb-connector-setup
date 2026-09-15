"""Unit tests for the service layer.

The service layer is the orchestration glue between the CLI / MCP and the
core primitives. These tests cover:

  * Pure functions (list_connectors, handoff) with on-disk fixtures.
  * Mocked sessions / targets for diagnose, monitor, validate so we don't
    require AWS credentials.

The core check/stat/builder primitives are already covered by their own
test modules; this file only exercises the wiring.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kb_connector import service
from kb_connector.core.errors import ConfigError, StateError
from kb_connector.core.monitor import IngestionStats, MonitorResult


# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A temp directory that looks like a project with a config + state."""
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\n"
        'region = "us-west-2"\n\n'
        "[connectors.engineering-sp]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
        'credential = "cert"\n'
        "acl = true\n"
        'site_urls = ["https://contoso.sharepoint.com/sites/eng"]\n\n'
        "[connectors.docs-s3]\n"
        'type = "s3"\n'
        'bucket_name = "my-docs-bucket"\n'
    )
    state = tmp_path / "kb-connector.state.json"
    state.write_text(json.dumps({
        "connectors": {
            "engineering-sp": {
                "connector_type": "sharepoint",
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "region": "us-west-2",
                "client_app_id": "app-12345",
                "knowledge_base_id": "kb-abc",
                "data_source_id": "ds-xyz",
                "secret_arn": "arn:aws:secretsmanager:us-west-2:111:secret:eng-sp-AbCdEf",
                "kb_role_arn": "arn:aws:iam::111:role/kb-eng-sp",
                "cert_not_after": "2099-12-31T00:00:00+00:00",
                "last_ingestion_job_id": "job-123",
            },
        },
    }))
    return tmp_path


@pytest.fixture
def project_paths(project: Path) -> dict:
    """Convenience: dict with the config_path / state_path kwargs ready to splat."""
    return {
        "config_path": str(project / "kb-connector.toml"),
        "state_path": str(project / "kb-connector.state.json"),
    }


# --- list_connectors ---------------------------------------------------------


def test_list_connectors_merges_config_and_state(project_paths):
    result = service.list_connectors(**project_paths)
    names = [c.name for c in result.connectors]
    assert "engineering-sp" in names
    assert "docs-s3" in names

    sp = next(c for c in result.connectors if c.name == "engineering-sp")
    assert sp.type == "sharepoint"
    assert sp.has_state is True
    assert sp.knowledge_base_id == "kb-abc"
    assert sp.data_source_id == "ds-xyz"
    assert sp.last_ingestion_job_id == "job-123"

    s3 = next(c for c in result.connectors if c.name == "docs-s3")
    assert s3.type == "s3"
    assert s3.has_state is False
    assert s3.knowledge_base_id is None


def test_list_connectors_includes_state_only_entries(tmp_path: Path):
    # State file references a connector with no config entry — should still surface.
    state = tmp_path / "kb-connector.state.json"
    state.write_text(json.dumps({
        "connectors": {
            "orphan": {
                "connector_type": "web",
                "knowledge_base_id": "kb-orphan",
                "region": "us-east-1",
            },
        },
    }))
    result = service.list_connectors(
        config_path=None,
        state_path=str(state),
    )
    names = [c.name for c in result.connectors]
    assert "orphan" in names
    orphan = next(c for c in result.connectors if c.name == "orphan")
    assert orphan.type == "web"
    assert orphan.has_state is True


def test_list_connectors_no_config_no_state(tmp_path: Path, monkeypatch):
    # No config, no state — empty result, not an error. Run from a clean
    # cwd so the project-local config search doesn't find this repo's own
    # kb-connector.toml.
    monkeypatch.chdir(tmp_path)
    result = service.list_connectors(
        config_path=None,
        state_path=str(tmp_path / "missing.json"),
    )
    assert result.connectors == []


# --- handoff -----------------------------------------------------------------


def test_handoff_aws_direction(project_paths):
    result = service.handoff(connector_name="engineering-sp", direction="aws", **project_paths)
    assert result.direction == "source-to-aws"
    assert result.document["direction"] == "source-to-aws"
    assert result.document["source"]["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert result.document["source"]["client_id"] == "app-12345"
    assert result.document["source"]["acl"] is True


def test_handoff_source_direction(project_paths):
    result = service.handoff(connector_name="engineering-sp", direction="source", **project_paths)
    assert result.direction == "aws-to-source"
    assert result.document["aws"]["knowledge_base_id"] == "kb-abc"
    assert result.document["aws"]["data_source_id"] == "ds-xyz"


def test_handoff_unknown_direction(project_paths):
    with pytest.raises(ConfigError, match="Unknown direction"):
        service.handoff(connector_name="engineering-sp", direction="upload", **project_paths)


# --- diagnose ----------------------------------------------------------------


def _stub_session_factory(**clients):
    """Build a fake session whose .client(name) returns the matching mock."""
    sess = MagicMock()
    sess.client.side_effect = lambda name, **_: clients.get(name, MagicMock())
    return lambda region, profile: sess


def test_diagnose_healthy_path(project_paths):
    sm = MagicMock()
    sm.get_secret_value.return_value = {
        "SecretString": json.dumps({
            "clientId": "app-12345",
            "certificatePassword": "redacted",
        })
    }
    ct = MagicMock()
    ct.lookup_events.return_value = {"Events": []}
    factory = _stub_session_factory(secretsmanager=sm, cloudtrail=ct)

    result = service.diagnose(
        connector_name="engineering-sp",
        session_factory=factory,
        **project_paths,
    )
    assert result.connector == "engineering-sp"
    assert result.status == "healthy"
    # Three checks: secret, cert (state has cert_not_after), cloudtrail.
    assert len(result.checks) == 3
    assert all(c.passed for c in result.checks)


def test_diagnose_flags_missing_secret_field(project_paths):
    sm = MagicMock()
    sm.get_secret_value.return_value = {
        "SecretString": json.dumps({"clientId": "app-12345"})  # no certificatePassword
    }
    ct = MagicMock()
    ct.lookup_events.return_value = {"Events": []}
    factory = _stub_session_factory(secretsmanager=sm, cloudtrail=ct)

    result = service.diagnose(
        connector_name="engineering-sp",
        session_factory=factory,
        **project_paths,
    )
    assert result.status == "failing"
    secret_check = next(c for c in result.checks if c.name == "secret_validation")
    assert secret_check.passed is False
    assert "certificatePassword" in secret_check.details


# --- monitor -----------------------------------------------------------------


def test_monitor_poll_only_uses_state_job_id(project_paths, monkeypatch):
    """monitor(start=False) polls the job id from state; no boto needed."""
    fake_target = MagicMock()
    captured = {}

    def fake_poll(target, *, kb_id, ds_id, job_id, **_):
        captured["kb_id"] = kb_id
        captured["ds_id"] = ds_id
        captured["job_id"] = job_id
        return MonitorResult(
            job_id=job_id,
            stats=IngestionStats(status="COMPLETE", scanned=10, new_indexed=10),
        )

    monkeypatch.setattr("kb_connector.service.poll_job", fake_poll)
    factory = lambda region, profile: MagicMock()
    target_factory = lambda **_: fake_target

    result = service.monitor(
        connector_name="engineering-sp",
        session_factory=factory,
        target_factory=target_factory,
        **project_paths,
    )
    assert captured == {"kb_id": "kb-abc", "ds_id": "ds-xyz", "job_id": "job-123"}
    assert result.stats.status == "COMPLETE"
    assert result.stats.indexed_total == 10


def test_monitor_start_calls_start_and_poll(project_paths, monkeypatch):
    captured = {}

    def fake_start_and_poll(target, *, kb_id, ds_id, **_):
        captured["kb_id"] = kb_id
        captured["ds_id"] = ds_id
        return MonitorResult(
            job_id="job-new",
            stats=IngestionStats(status="COMPLETE", scanned=5, new_indexed=5),
        )

    monkeypatch.setattr("kb_connector.service.start_and_poll", fake_start_and_poll)
    factory = lambda region, profile: MagicMock()
    target_factory = lambda **_: MagicMock()

    result = service.monitor(
        connector_name="engineering-sp",
        start=True,
        session_factory=factory,
        target_factory=target_factory,
        **project_paths,
    )
    assert result.job_id == "job-new"
    assert captured["kb_id"] == "kb-abc"


def test_monitor_poll_only_requires_job_id(tmp_path: Path):
    # Empty state — poll-only must fail loudly rather than silently start a job.
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\nregion = \"us-west-2\"\n\n"
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
    )
    factory = lambda region, profile: MagicMock()
    target_factory = lambda **_: MagicMock()
    with pytest.raises(StateError, match="kb_id and ds_id"):
        service.monitor(
            connector_name="eng",
            session_factory=factory,
            target_factory=target_factory,
            config_path=str(config),
            state_path=str(tmp_path / "missing.json"),
        )


# --- validate ----------------------------------------------------------------


def test_validate_runs_retrieve_basic_for_non_acl_connector(project_paths):
    """For a non-ACL connector, validate runs a single basic retrieve."""
    fake_target = MagicMock()
    fake_target.retrieve.return_value = {"retrievalResults": [{"id": 1}, {"id": 2}]}
    factory = lambda region, profile: MagicMock()
    target_factory = lambda **_: fake_target

    # docs-s3 is non-ACL in the fixture
    # But the fixture's docs-s3 has no kb_id in state, so add one.
    import json
    state = Path(project_paths["state_path"])
    data = json.loads(state.read_text())
    data["connectors"]["docs-s3"] = {
        "connector_type": "s3",
        "knowledge_base_id": "kb-s3",
        "data_source_id": "ds-s3",
        "region": "us-west-2",
    }
    state.write_text(json.dumps(data))

    result = service.validate(
        connector_name="docs-s3",
        session_factory=factory,
        target_factory=target_factory,
        **project_paths,
    )
    assert result.healthy is True
    retrieve = next(c for c in result.checks if c.name == "retrieve")
    assert retrieve.passed is True
    assert retrieve.data["result_count"] == 2
    fake_target.retrieve.assert_called_once()


def test_validate_acl_three_check_trio(project_paths):
    """ACL connector with both users runs the authorized/denied/no-user trio."""
    fake_target = MagicMock()

    def retrieve_side_effect(kb_id, *, query, user_id=None, **_):
        if user_id == "alice@example.com":
            return {"retrievalResults": [{"id": 1}]}  # authorized -> hits
        return {"retrievalResults": []}  # denied or no user -> empty

    fake_target.retrieve.side_effect = retrieve_side_effect
    factory = lambda region, profile: MagicMock()
    target_factory = lambda **_: fake_target

    result = service.validate(
        connector_name="engineering-sp",
        authorized_user="alice@example.com",
        unauthorized_user="bob@example.com",
        session_factory=factory,
        target_factory=target_factory,
        **project_paths,
    )
    assert result.healthy is True
    names = {c.name for c in result.checks}
    assert {"retrieve_authorized", "retrieve_denied", "retrieve_no_user"}.issubset(names)
    assert fake_target.retrieve.call_count == 3


def test_validate_acl_uses_validation_block_from_config(tmp_path: Path):
    """Test query and users come from the [validation] block when not passed."""
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\nregion = \"us-west-2\"\n\n"
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
        "acl = true\n\n"
        "[connectors.eng.validation]\n"
        'query = "Atlanta Falcons"\n'
        'authorized_user = "ok@example.com"\n'
        'unauthorized_user = "bad@example.com"\n'
    )
    state = tmp_path / "kb-connector.state.json"
    state.write_text('{"connectors": {"eng": {"knowledge_base_id": "kb-1", '
                     '"connector_type": "sharepoint"}}}')

    captured: list[dict] = []

    fake_target = MagicMock()
    def retrieve_side_effect(kb_id, *, query, user_id=None, **_):
        captured.append({"query": query, "user_id": user_id})
        if user_id == "ok@example.com":
            return {"retrievalResults": [{"id": 1}]}
        return {"retrievalResults": []}
    fake_target.retrieve.side_effect = retrieve_side_effect

    result = service.validate(
        connector_name="eng",
        config_path=str(config),
        state_path=str(state),
        session_factory=lambda r, p: MagicMock(),
        target_factory=lambda **_: fake_target,
    )

    assert result.healthy is True
    assert all(c["query"] == "Atlanta Falcons" for c in captured)
    user_ids = {c["user_id"] for c in captured}
    assert {"ok@example.com", "bad@example.com", None} == user_ids


def test_validate_acl_authorized_user_returning_zero_fails(project_paths):
    """If the authorized user gets zero results, the check fails."""
    fake_target = MagicMock()
    fake_target.retrieve.return_value = {"retrievalResults": []}
    result = service.validate(
        connector_name="engineering-sp",
        authorized_user="alice@example.com",
        unauthorized_user="bob@example.com",
        session_factory=lambda r, p: MagicMock(),
        target_factory=lambda **_: fake_target,
        **project_paths,
    )
    assert result.healthy is False
    auth = next(c for c in result.checks if c.name == "retrieve_authorized")
    assert auth.passed is False


def test_validate_acl_unauthorized_user_returning_results_fails(project_paths):
    """If the unauthorized user actually gets results, ACL is leaking — fail."""
    fake_target = MagicMock()
    fake_target.retrieve.return_value = {"retrievalResults": [{"id": 1}]}
    result = service.validate(
        connector_name="engineering-sp",
        authorized_user="alice@example.com",
        unauthorized_user="bob@example.com",
        session_factory=lambda r, p: MagicMock(),
        target_factory=lambda **_: fake_target,
        **project_paths,
    )
    assert result.healthy is False
    denied = next(c for c in result.checks if c.name == "retrieve_denied")
    assert denied.passed is False


def test_validate_acl_skips_user_checks_without_config(project_paths):
    """ACL connector without users configured runs only the no-user check."""
    fake_target = MagicMock()
    fake_target.retrieve.return_value = {"retrievalResults": []}
    result = service.validate(
        connector_name="engineering-sp",
        session_factory=lambda r, p: MagicMock(),
        target_factory=lambda **_: fake_target,
        **project_paths,
    )
    # Only retrieve_no_user runs (and passes since ACL on -> 0 results)
    names = {c.name for c in result.checks}
    assert "retrieve_no_user" in names
    assert "retrieve_authorized" not in names
    assert "retrieve_denied" not in names
    assert any("authorized_user" in n for n in result.notes)


def test_validate_skip_retrieve_with_no_kb(tmp_path: Path):
    # No state -> no kb_id -> retrieve note should appear.
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\nregion = \"us-west-2\"\n\n"
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
    )
    result = service.validate(
        connector_name="eng",
        config_path=str(config),
        state_path=str(tmp_path / "missing.json"),
    )
    assert result.healthy is False  # no checks ran
    assert any("no kb_id" in n for n in result.notes)


def test_validate_skip_retrieve_flag(project_paths):
    result = service.validate(
        connector_name="engineering-sp",
        skip_retrieve=True,
        **project_paths,
    )
    assert any("skip_retrieve" in n for n in result.notes)


# --- error paths -------------------------------------------------------------


def test_diagnose_no_connector_no_config(tmp_path: Path, monkeypatch):
    # No config, no connector arg, no kb/ds — should fail clearly.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="No connectors configured"):
        service.diagnose(config_path=None, state_path=None)


def test_diagnose_multiple_connectors_requires_choice(project_paths):
    # The fixture has two connectors and we don't pass a name.
    with pytest.raises(ConfigError, match="Multiple connectors"):
        service.diagnose(**project_paths)
