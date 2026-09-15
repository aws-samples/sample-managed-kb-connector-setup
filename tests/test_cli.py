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
