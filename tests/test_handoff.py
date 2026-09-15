"""Tests for handoff document validation.

A handoff arrives from another admin, usually over email or chat. Every field
in it becomes connector state, and `secret_arn` goes on to be the target of a
force-delete during teardown — so it is validated on the way in.
"""

from __future__ import annotations

import pytest

from kb_connector.core.errors import ConfigError
from kb_connector.core.handoff import (
    DIRECTION_AWS_TO_SOURCE,
    DIRECTION_SOURCE_TO_AWS,
    build_aws_to_source,
    build_source_to_aws,
    parse_handoff,
)
from kb_connector.core.state import ConnectorState

_GOOD_SECRET = (
    "arn:aws:secretsmanager:us-west-2:111122223333:secret:kb-connector/c1-cred-a1"
)
_GOOD_GUID = "f204b1c2-3d4e-5f60-7182-93a4b5c6d7e8"


def _aws_doc(**aws):
    base = {
        "region": "us-west-2",
        "knowledge_base_id": "ABC123DEF4",
        "data_source_id": "DEF456ABC1",
        "secret_arn": _GOOD_SECRET,
    }
    base.update(aws)
    return {
        "version": "1",
        "connector": "c1",
        "type": "sharepoint",
        "direction": DIRECTION_AWS_TO_SOURCE,
        "aws": base,
        "created_at": "2026-01-01T00:00:00+00:00",
    }


# --- round trip: what the builders emit must parse ---------------------------


def test_builder_output_parses_source_to_aws():
    cs = ConnectorState(
        connector_type="sharepoint", tenant_id=_GOOD_GUID, client_app_id=_GOOD_GUID
    )
    doc = build_source_to_aws("c1", cs, None)
    assert parse_handoff(doc)["direction"] == DIRECTION_SOURCE_TO_AWS


def test_builder_output_parses_aws_to_source():
    cs = ConnectorState(
        connector_type="sharepoint",
        region="us-west-2",
        knowledge_base_id="ABC123DEF4",
        data_source_id="DEF456ABC1",
        secret_arn=_GOOD_SECRET,
    )
    doc = build_aws_to_source("c1", cs, None)
    assert parse_handoff(doc)["direction"] == DIRECTION_AWS_TO_SOURCE


def test_partially_populated_handoff_is_valid():
    """A stage that produced little still emits a usable document."""
    doc = build_aws_to_source("c1", ConnectorState(), None)
    assert parse_handoff(doc)["aws"] == {}


# --- version ----------------------------------------------------------------


@pytest.mark.parametrize("version", [None, "", "2", "1.1", "abc"])
def test_unsupported_version_refused(version):
    doc = _aws_doc()
    if version is None:
        doc.pop("version")
    else:
        doc["version"] = version
    with pytest.raises(ConfigError, match="version"):
        parse_handoff(doc)


# --- direction --------------------------------------------------------------


@pytest.mark.parametrize(
    "direction",
    [
        "x-source-to-aws-y",       # would pass a substring match
        "source-to-aws-evil",
        "not-source-to-aws",
        "SOURCE-TO-AWS",
        "",
        None,
    ],
)
def test_direction_must_match_exactly(direction):
    doc = _aws_doc()
    if direction is None:
        doc.pop("direction")
    else:
        doc["direction"] = direction
    with pytest.raises(ConfigError, match="direction"):
        parse_handoff(doc)


# --- field shapes -----------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad",
    [
        ("secret_arn", "arn:aws:s3:::someone-elses-bucket"),
        ("secret_arn", "not-an-arn"),
        ("secret_arn", "arn:aws:iam::111122223333:role/admin"),
        ("region", "../../etc"),
        ("region", "US-WEST-2"),
        ("knowledge_base_id", "has space"),
        ("data_source_id", "x"),
    ],
)
def test_malformed_identifier_refused(field, bad):
    with pytest.raises(ConfigError):
        parse_handoff(_aws_doc(**{field: bad}))


def test_secret_arn_for_wrong_service_cannot_become_a_delete_target():
    """The path that mattered: a crafted ARN reaching ForceDeleteWithoutRecovery."""
    with pytest.raises(ConfigError):
        parse_handoff(_aws_doc(secret_arn="arn:aws:kms:us-west-2:111122223333:key/x"))


@pytest.mark.parametrize("bad", ["not-a-guid", "", 42])
def test_malformed_tenant_id_refused(bad):
    doc = {
        "version": "1",
        "direction": DIRECTION_SOURCE_TO_AWS,
        "type": "sharepoint",
        "source": {"tenant_id": bad},
    }
    with pytest.raises(ConfigError):
        parse_handoff(doc)


# --- structural ------------------------------------------------------------


@pytest.mark.parametrize("raw", ["a string", 42, ["a", "list"], None])
def test_non_object_document_refused(raw):
    with pytest.raises(ConfigError, match="JSON object"):
        parse_handoff(raw)


@pytest.mark.parametrize("section", ["a string", 42, ["x"]])
def test_non_object_section_refused(section):
    doc = _aws_doc()
    doc["aws"] = section
    with pytest.raises(ConfigError, match="must be a JSON object"):
        parse_handoff(doc)


def test_unknown_top_level_keys_are_preserved_not_rejected():
    """A newer writer can add fields without breaking an older reader."""
    doc = _aws_doc()
    doc["future_field"] = {"something": "new"}
    assert parse_handoff(doc)["future_field"] == {"something": "new"}


def test_valid_document_is_returned_normalized():
    out = parse_handoff(_aws_doc())
    assert out["aws"]["secret_arn"] == _GOOD_SECRET
    assert out["version"] == "1"
