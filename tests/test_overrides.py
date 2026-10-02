"""Tests for request-level overrides on CreateKnowledgeBase and CreateDataSource."""

from __future__ import annotations

import argparse
import tomllib
from unittest.mock import MagicMock

import pytest

from kb_connector.core import overrides as o
from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import ConfigError
from kb_connector.core.state import ConnectorState

_MANAGED = "dataSourceConfiguration.managedKnowledgeBaseConnectorConfiguration"
_MEDIA = (
    f"[overrides.create_data_source.{_MANAGED}]\n"
    'mediaExtractionConfiguration = { videoExtractionConfiguration = '
    '{ videoExtractionStatus = "ENABLED" } }\n'
)


def _load(text: str) -> o.RequestOverrides:
    return o.load(tomllib.loads(text))


def _managed(body: dict) -> dict:
    return body["dataSourceConfiguration"]["managedKnowledgeBaseConnectorConfiguration"]


# --- load --------------------------------------------------------------------------


def test_no_overrides_is_empty():
    ro = o.load({})
    assert not ro
    assert ro.create_data_source == {} and ro.create_knowledge_base == {}


def test_data_source_override_reaches_outside_connector_parameters():
    ro = _load(_MEDIA + 'dataDeletionPolicy = "RETAIN"\n')
    managed = _managed(ro.create_data_source)
    assert managed["mediaExtractionConfiguration"]["videoExtractionConfiguration"] == {
        "videoExtractionStatus": "ENABLED"
    }


def test_connector_params_overrides_still_applies_and_new_table_wins():
    ro = _load(
        "[connector_params_overrides.filterConfiguration]\n"
        'maxFileSizeInMegaBytes = "100"\n'
        'inclusionPatterns = ["*.mp4"]\n'
        f"[overrides.create_data_source.{_MANAGED}.connectorParameters.filterConfiguration]\n"
        'maxFileSizeInMegaBytes = "1500"\n'
    )
    params = _managed(ro.create_data_source)["connectorParameters"]
    assert params["filterConfiguration"] == {
        "maxFileSizeInMegaBytes": "1500",
        "inclusionPatterns": ["*.mp4"],
    }


@pytest.mark.parametrize("table,key", [
    ("create_knowledge_base", "roleArn"),
    ("create_knowledge_base", "name"),
    ("create_data_source", "knowledgeBaseId"),
    ("create_data_source", "clientToken"),
])
def test_fields_setup_sets_are_refused(table, key):
    with pytest.raises(ConfigError, match=f"overrides.{table}.{key}"):
        _load(f'[overrides.{table}]\n{key} = "x"\n')


@pytest.mark.parametrize("key", ["ManagedBy", "KbConnectorName", "aws:foo"])
def test_ownership_tags_cannot_be_set_through_overrides(key):
    with pytest.raises(ConfigError, match="tags"):
        _load(f'[overrides.create_knowledge_base.tags]\n"{key}" = "x"\n')


def test_ordinary_tags_are_allowed():
    ro = _load('[overrides.create_knowledge_base.tags]\nCostCenter = "1234"\n')
    assert ro.create_knowledge_base["tags"] == {"CostCenter": "1234"}


@pytest.mark.parametrize("text,match", [
    ("[overrides.create_kb]\nx = 1\n", "Unknown overrides table"),
    ("overrides = 5\n", "overrides must be a table"),
    ("[overrides]\ncreate_data_source = 5\n", "overrides.create_data_source must be a table"),
    ("connector_params_overrides = 5\n", "connector_params_overrides must be a table"),
])
def test_malformed_tables_are_refused(text, match):
    with pytest.raises(ConfigError, match=match):
        _load(text)


# --- check_against_model -----------------------------------------------------------


def test_known_fields_pass_the_model():
    o.check_against_model(_load(
        _MEDIA
        + 'deletionProtectionConfiguration = { deletionProtectionStatus = "ENABLED", '
        'deletionProtectionThreshold = 15 }\n'
        '[overrides.create_data_source]\ndataDeletionPolicy = "RETAIN"\n'
        '[overrides.create_knowledge_base]\ndescription = "video KB"\n'
    ))


def test_a_misspelled_field_names_its_location():
    ro = _load(f"[overrides.create_data_source.{_MANAGED}]\nmediaExtractionConfig = {{}}\n")
    with pytest.raises(ConfigError, match="mediaExtractionConfig") as exc_info:
        o.check_against_model(ro)
    assert "overrides.create_data_source" in str(exc_info.value)


def test_a_wrong_type_is_refused():
    with pytest.raises(ConfigError, match="dataDeletionPolicy"):
        o.check_against_model(_load("[overrides.create_data_source]\ndataDeletionPolicy = 5\n"))


def test_connector_parameters_contents_are_not_checked():
    """A free-form document in the model; the service checks it."""
    o.check_against_model(_load(
        "[connector_params_overrides]\nsomethingTheServiceKnows = { a = 1 }\n"
    ))


# --- setup wiring --------------------------------------------------------------------


def _provision(raw: dict, *, cs: ConnectorState | None = None, ds_status="AVAILABLE"):
    from kb_connector.cli.setup import _provision_kb_and_ds

    target = MagicMock()
    target.create_knowledge_base.return_value = {"knowledgeBase": {"knowledgeBaseId": "KB1"}}
    target.create_data_source_raw.return_value = {"dataSource": {"dataSourceId": "DS1"}}
    target.get_data_source.return_value = {"dataSource": {"status": ds_status}}
    args = argparse.Namespace(knowledge_base_id=None, kb_name=None, ds_name=None, kms_key_arn=None)
    cfg = ConnectorConfig(name="c", type="s3", region="us-west-2", raw=raw)
    _provision_kb_and_ds(
        target=target, args=args, cfg=cfg, cs=cs or ConnectorState(), connector_name="c",
        kb_role_arn="arn:aws:iam::111122223333:role/r",
        connector_parameters={"type": "S3", "version": "1"},
    )
    return target


def test_setup_sends_the_overridden_data_source_request():
    raw = tomllib.loads(_MEDIA + "[connector_params_overrides]\nmetadataFilesPrefix = \"m/\"\n")
    target = _provision(raw)
    kb_id, payload = target.create_data_source_raw.call_args.args
    assert kb_id == "KB1" and payload["name"] == "c-ds"
    managed = _managed(payload)
    assert managed["mediaExtractionConfiguration"]["videoExtractionConfiguration"][
        "videoExtractionStatus"
    ] == "ENABLED"
    assert managed["connectorParameters"] == {
        "type": "S3", "version": "1", "metadataFilesPrefix": "m/",
    }


def test_setup_passes_knowledge_base_overrides():
    raw = tomllib.loads('[overrides.create_knowledge_base]\ndescription = "video KB"\n')
    target = _provision(raw)
    assert target.create_knowledge_base.call_args.kwargs["overrides"] == {"description": "video KB"}


def test_a_reused_data_source_is_left_alone_and_the_operator_told(capsys):
    cs = ConnectorState(data_source_id="DS-OLD", knowledge_base_id="KB1")
    cs.record_owned("kb")
    target = _provision(tomllib.loads(_MEDIA), cs=cs)
    target.create_data_source_raw.assert_not_called()
    assert "apply only when the data source is created" in capsys.readouterr().out


def test_bmkb_merges_knowledge_base_overrides_into_the_request():
    from kb_connector.targets.bmkb import BmkbTarget

    client = MagicMock()
    session = MagicMock()
    session.client.return_value = client
    BmkbTarget(session=session, region="us-west-2").create_knowledge_base(
        name="kb", role_arn="arn:aws:iam::111122223333:role/r",
        overrides={"description": "d", "knowledgeBaseConfiguration": {
            "managedKnowledgeBaseConfiguration": {"embeddingModelType": "MANAGED"}}},
    )
    sent = client.create_knowledge_base.call_args.kwargs
    assert sent["description"] == "d" and sent["roleArn"].endswith(":role/r")
    managed = sent["knowledgeBaseConfiguration"]["managedKnowledgeBaseConfiguration"]
    assert managed == {"embeddingModelType": "MANAGED"}
    assert sent["knowledgeBaseConfiguration"]["type"] == "MANAGED"


def test_setup_rejects_a_bad_override_before_any_work(tmp_path, monkeypatch, capsys):
    from kb_connector.cli import setup as setup_mod
    from kb_connector.cli.main import main

    (tmp_path / "kb-connector.toml").write_text(
        '[connectors.c]\ntype = "s3"\nregion = "us-west-2"\nbucket_name = "b"\n'
        f"[connectors.c.overrides.create_data_source.{_MANAGED}]\nmediaExtractionConfig = {{}}\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(setup_mod, "_setup_s3", lambda *a, **k: pytest.fail("setup ran"))
    monkeypatch.setattr("sys.argv", ["kb-connector", "setup", "c"])
    assert main() == 1
    assert "mediaExtractionConfig" in capsys.readouterr().err
