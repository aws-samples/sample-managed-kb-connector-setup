"""Tests for the CLI layer: entry-point smoke tests and setup's pre-flight guards."""

import argparse

import pytest

from kb_connector.cli.main import build_parser
from kb_connector.cli.setup import _setup_microsoft
from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import ConfigError
from kb_connector.core.state import ConnectorState


def test_parser_builds():
    """Parser builds without error and has expected subcommands."""
    parser = build_parser()
    assert parser is not None


def test_help_contains_subcommands(capsys):
    """--help output lists all subcommands."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    for cmd in ("init", "setup", "monitor", "validate", "diagnose", "handoff", "teardown"):
        assert cmd in captured.out

# --- setup: SharePoint credential guards -------------------------------------
#
# These exercise setup's pre-flight validation, which runs before any Graph or
# AWS client is constructed — so they need no network and no mocks. Reaching
# past the guards does require a live Graph client, which is why the positive
# (cert) path isn't covered here.


def _sp_config(credential: str, *, acl: bool = False) -> ConnectorConfig:
    """Minimal SharePoint config for exercising the pre-flight guards."""
    return ConnectorConfig(
        name="sp",
        type="sharepoint",
        credential=credential,
        acl=acl,
        tenant_id="00000000-0000-4000-8000-000000000000",
    )


def _run_guards(cfg: ConnectorConfig) -> None:
    _setup_microsoft(argparse.Namespace(), cfg, ConnectorState(), "sp", "1")


@pytest.mark.parametrize("credential", ["client_secret", "ropc"])
def test_setup_sharepoint_rejects_non_cert_credential(credential):
    """SharePoint is certificate-only; non-cert modes fail before anything is created."""
    with pytest.raises(ConfigError, match="requires credential = 'cert'"):
        _run_guards(_sp_config(credential))


def test_setup_sharepoint_non_cert_error_names_the_credential():
    """The error repeats the offending value so the fix is obvious."""
    with pytest.raises(ConfigError, match="ropc"):
        _run_guards(_sp_config("ropc"))


def test_setup_acl_guard_precedes_sharepoint_guard():
    """ACL + non-cert reports the ACL constraint, which is checked first."""
    with pytest.raises(ConfigError, match="ACL requires 'cert'"):
        _run_guards(_sp_config("ropc", acl=True))


def test_setup_microsoft_requires_tenant_id():
    """Missing tenant id is caught before credential validation."""
    cfg = ConnectorConfig(name="sp", type="sharepoint", credential="cert")
    with pytest.raises(ConfigError, match="tenant_id is required"):
        _run_guards(cfg)


# --- Setup records its region before it creates anything -------------------


def test_setup_records_region_up_front():
    from kb_connector.cli.setup import _record_region

    cs = ConnectorState()
    _record_region(cs, ConnectorConfig(name="c", type="s3", region="eu-west-1"))
    assert cs.region == "eu-west-1"


def test_setup_refuses_a_region_change_while_resources_are_tracked():
    """New resources in one region with state tracking the old ones in another
    would leave teardown unable to reach half of them."""
    from kb_connector.cli.setup import _record_region

    cs = ConnectorState(region="us-west-2", knowledge_base_id="KB12345678")
    with pytest.raises(ConfigError, match="us-west-2"):
        _record_region(cs, ConnectorConfig(name="c", type="s3", region="eu-west-1"))
    assert cs.region == "us-west-2"


def test_region_change_with_nothing_tracked_is_allowed():
    from kb_connector.cli.setup import _record_region

    cs = ConnectorState(region="us-west-2")
    _record_region(cs, ConnectorConfig(name="c", type="s3", region="eu-west-1"))
    assert cs.region == "eu-west-1"


# --- diagnose --json is machine-readable -------------------------------------


def test_diagnose_json_prints_only_json(monkeypatch, capsys):
    import json

    from kb_connector import service
    from kb_connector.core.diagnostics import CheckResult, build_diagnose_result

    def _fake_diagnose(**kwargs):
        check = CheckResult(name="cert_expiry", passed=True, details="ok", side="source")
        kwargs["on_check"](check)
        return build_diagnose_result("sp", [check])

    monkeypatch.setattr(service, "diagnose", _fake_diagnose)
    args = build_parser().parse_args(["--json", "diagnose", "sp"])
    assert args.func(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "healthy"
    assert out["checks"][0]["name"] == "cert_expiry"


# --- errors reach the top-level renderer ---------------------------------------


def test_expired_token_from_a_command_gets_the_login_hint(monkeypatch, capsys):
    from kb_connector import service
    from kb_connector.cli.main import main
    from kb_connector.core.errors import AwsError

    def _expired(**kwargs):
        raise AwsError("AWS error (ExpiredToken): token expired", code="ExpiredToken")

    monkeypatch.setattr(service, "validate", _expired)
    monkeypatch.setattr("sys.argv", ["kb-connector", "validate", "c1", "--profile", "dev"])
    assert main() == 1
    assert "aws sso login --profile dev" in capsys.readouterr().err


def test_wait_timeout_is_both_a_connector_error_and_a_timeout(monkeypatch):
    from unittest.mock import MagicMock

    from kb_connector.core.errors import ConnectorError, WaitTimeout
    from kb_connector.core.knowledge_base import wait_until_ds_available

    monkeypatch.setattr("time.sleep", lambda _: None)
    target = MagicMock()
    target.get_data_source.return_value = {"dataSource": {"status": "CREATING"}}
    with pytest.raises(WaitTimeout) as exc_info:
        wait_until_ds_available(target, "KB", "DS", timeout_seconds=0)
    assert isinstance(exc_info.value, ConnectorError)
    assert isinstance(exc_info.value, TimeoutError)
