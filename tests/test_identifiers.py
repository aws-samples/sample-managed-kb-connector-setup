"""Tests for the identifier validators guarding destructive calls.

These exist because the state file and handoff documents are local JSON the
tool reads back and acts on: `secret_arn` becomes the target of a
force-delete, `cert_s3_bucket`/`cert_s3_key` become the target of a
DeleteObject. A value that parsed as JSON is not the same as a value a
provisioning run could have produced.
"""

from __future__ import annotations

import pytest

from kb_connector.core.errors import ConnectorError
from kb_connector.core.identifiers import (
    validate_arn,
    validate_bedrock_id,
    validate_guid,
    validate_name_component,
    validate_region,
    validate_s3_bucket,
    validate_s3_key,
    validate_s3_key_prefix,
    validate_secret_arn,
)

_GOOD_SECRET = (
    "arn:aws:secretsmanager:us-west-2:111122223333:secret:kb-connector/c1-cred-a1b2"
)


# --- secret ARNs -------------------------------------------------------------


def test_valid_secret_arn_accepted():
    assert validate_secret_arn(_GOOD_SECRET) == _GOOD_SECRET


def test_secret_arn_accepted_in_other_partitions():
    for partition in ("aws-cn", "aws-us-gov"):
        arn = f"arn:{partition}:secretsmanager:us-gov-west-1:111122223333:secret:s-a1"
        assert validate_secret_arn(arn) == arn


@pytest.mark.parametrize(
    "bad",
    [
        "",
        None,
        123,
        "kb-connector/c1-credentials",                      # bare name
        "arn:aws:s3:::my-bucket",                           # wrong service
        "arn:aws:iam::111122223333:role/admin",             # wrong service
        "arn:aws:secretsmanager:us-west-2:111122223333:secret:",  # no secret named
        "arn:aws:secretsmanager:us-west-2:111122223333:key:abc",  # wrong resource
        "arn:evil:secretsmanager:us-west-2:111122223333:secret:s",  # bad partition
        "arn:aws:secretsmanager:us-west-2:1111:secret:s",   # malformed account
    ],
)
def test_bad_secret_arn_refused(bad):
    with pytest.raises(ConnectorError):
        validate_secret_arn(bad)


def test_secret_arn_service_is_matched_exactly():
    """A prefix-ish service name must not satisfy a secretsmanager check."""
    with pytest.raises(ConnectorError):
        validate_arn(
            "arn:aws:secretsmanager-fake:us-west-2:111122223333:secret:s",
            field="x",
            service="secretsmanager",
        )


# --- S3 bucket and key -------------------------------------------------------


def test_valid_bucket_accepted():
    assert validate_s3_bucket("kb-connector-certs-111122223333-us-west-2") == (
        "kb-connector-certs-111122223333-us-west-2"
    )


@pytest.mark.parametrize(
    "bad",
    ["", None, "ab", "UPPER-CASE", "has space", "-leading", "trailing-",
     "has..dots", "under_score", "a" * 64],
)
def test_bad_bucket_refused(bad):
    with pytest.raises(ConnectorError):
        validate_s3_bucket(bad)


def test_valid_key_accepted():
    assert validate_s3_key("kb-connector/c1.p12") == "kb-connector/c1.p12"


@pytest.mark.parametrize(
    "bad",
    ["", None, "/absolute/key.p12", "trailing/", "a/../../etc/passwd", ".."],
)
def test_bad_key_refused(bad):
    with pytest.raises(ConnectorError):
        validate_s3_key(bad)


def test_key_allows_dots_that_are_not_traversal():
    """`..` only matters as a whole path segment."""
    assert validate_s3_key("kb-connector/v1.2..3/cert.p12")


# --- region, bedrock ids, guids ---------------------------------------------


@pytest.mark.parametrize(
    "good", ["us-east-1", "ap-southeast-2", "us-gov-west-1", "cn-north-1"]
)
def test_valid_regions_accepted(good):
    assert validate_region(good) == good


@pytest.mark.parametrize(
    "bad", ["", None, "us-east", "US-EAST-1", "us_east_1", "../../x", "useast1"]
)
def test_bad_regions_refused(bad):
    with pytest.raises(ConnectorError):
        validate_region(bad)


def test_valid_bedrock_id_accepted():
    assert validate_bedrock_id("ABC123DEF4", field="kb") == "ABC123DEF4"


@pytest.mark.parametrize("bad", ["", None, "abc", "has-hyphen", "has space", "x" * 33])
def test_bad_bedrock_id_refused(bad):
    with pytest.raises(ConnectorError):
        validate_bedrock_id(bad, field="kb")


def test_valid_guid_accepted():
    guid = "f204b1c2-3d4e-5f60-7182-93a4b5c6d7e8"
    assert validate_guid(guid, field="tenant_id") == guid


@pytest.mark.parametrize(
    "bad", ["", None, "not-a-guid", "f204b1c2-3d4e-5f60-7182", "z" * 36]
)
def test_bad_guid_refused(bad):
    with pytest.raises(ConnectorError):
        validate_guid(bad, field="tenant_id")


def test_error_message_names_the_field_and_explains_the_refusal():
    with pytest.raises(ConnectorError) as excinfo:
        validate_secret_arn("nonsense", field="aws.secret_arn")
    message = str(excinfo.value)
    assert "aws.secret_arn" in message
    assert "refused" in message.lower()


# --- config values that become IAM policy Resource ARNs ----------------------


@pytest.mark.parametrize(
    "good", ["prod", "c1", "sharepoint-hr", "team.finance", "a_b", "A1", "x" * 64]
)
def test_valid_name_components_accepted(good):
    assert validate_name_component(good, field="connector name") == good


@pytest.mark.parametrize(
    "bad",
    [
        "",
        None,
        "has space",
        "has/slash",
        "-leading-hyphen",
        ".leading-dot",
        "x" * 65,
        "naïve",          # IAM RoleName rejects non-ASCII
        "a:b",
        "a,b",
    ],
)
def test_bad_name_components_refused(bad):
    with pytest.raises(ConnectorError):
        validate_name_component(bad, field="connector name")


@pytest.mark.parametrize("wildcard", ["x*", "*", "a?b", "pre*fix", "?"])
def test_name_component_refuses_iam_policy_wildcards(wildcard):
    """A wildcard here widens the KB role's S3 grant beyond one certificate."""
    with pytest.raises(ConnectorError, match="wildcard"):
        validate_name_component(wildcard, field="connector name")


@pytest.mark.parametrize("good", ["kb-connector", "certs/prod", "a/b/c"])
def test_valid_key_prefixes_accepted(good):
    assert validate_s3_key_prefix(good, field="cert_s3_key_prefix") == good


@pytest.mark.parametrize(
    "bad", ["", None, "a//b", "a/../b", "..", "./x", "has space/x", "a/b:c"]
)
def test_bad_key_prefixes_refused(bad):
    with pytest.raises(ConnectorError):
        validate_s3_key_prefix(bad, field="cert_s3_key_prefix")


@pytest.mark.parametrize("wildcard", ["kb-connector/*", "*", "certs/?", "a*/b"])
def test_key_prefix_refuses_iam_policy_wildcards(wildcard):
    with pytest.raises(ConnectorError, match="wildcard"):
        validate_s3_key_prefix(wildcard, field="cert_s3_key_prefix")
