"""Tests for the security-relevant behaviors THREAT-MODEL.md depends on.

Each test names the threat it guards. These are the behaviors that are easy to
regress silently — an ownership check that stops refusing, a file mode that goes
back to the umask default, a redaction that stops redacting — so they're tested
directly rather than through a full setup flow.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

import pytest

from kb_connector.core.errors import AwsError, ConfigError
from kb_connector.core.fileio import (
    atomic_write_bytes,
    atomic_write_json,
    describe_mode,
    open_owner_only,
)
from kb_connector.core.log_analysis import (
    DocumentEvent,
    analyze_logs,
    redact_document_location,
    redact_reason,
)
from kb_connector.core.provisioning import _reclaim_untagged, build_inline_policy
from kb_connector.core.signed_client import validate_endpoint
from botocore.exceptions import ClientError

from kb_connector.core.config import load_config
from kb_connector.core.state import (
    OWNER_EXTERNAL,
    OWNER_TOOL,
    OWNER_TOOL_UNTAGGED,
    RESOURCE_KB,
    RESOURCE_ROLE,
    RESOURCE_SECRET,
    ConnectorState,
    StateFile,
    load_state,
    save_state,
)
from kb_connector.core.tagging import (
    CONNECTOR_KEY,
    MANAGED_BY_KEY,
    MANAGED_BY_VALUE,
    Ownership,
    ProvisionedResource,
    build_tag_dict,
    build_tag_list,
    build_tag_query_string,
    classify_ownership,
    is_tagging_access_error,
    normalize_tags,
    validate_extra_tags,
)
from kb_connector.providers.microsoft.apps import escape_odata_literal


# --- T-01: endpoint allowlist ------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://bedrock-agent.us-east-1.amazonaws.com",
    "https://bedrock-agent-runtime.eu-west-1.amazonaws.com/",
    "https://bedrock-agent.cn-north-1.amazonaws.com.cn",
    "https://something.api.aws",
    "https://something.on.aws",
])
def test_endpoint_allowlist_accepts_aws_hosts(url):
    assert validate_endpoint(url).startswith("https://")


@pytest.mark.parametrize("url,expected", [
    ("http://bedrock-agent.us-east-1.amazonaws.com", "only https is allowed"),
    ("https://blocked.example.com", "not an AWS-owned endpoint"),
    # The suffix check must be on the parsed hostname, not a substring match.
    ("https://amazonaws.com.blocked.example", "not an AWS-owned endpoint"),
    ("https://notamazonaws.com", "not an AWS-owned endpoint"),
    ("ftp://bedrock-agent.us-east-1.amazonaws.com", "only https is allowed"),
    ("not-a-url", "not a valid absolute URL"),
    ("", "is empty"),
])
def test_endpoint_allowlist_rejects(url, expected):
    with pytest.raises(AwsError, match=expected):
        validate_endpoint(url)


def test_endpoint_trailing_slash_normalized():
    assert validate_endpoint(
        "https://bedrock-agent.us-east-1.amazonaws.com/"
    ) == "https://bedrock-agent.us-east-1.amazonaws.com"


def test_endpoint_opt_out_requires_explicit_env(monkeypatch):
    monkeypatch.delenv("KB_CONNECTOR_ALLOW_INSECURE_ENDPOINT", raising=False)
    with pytest.raises(AwsError):
        validate_endpoint("https://localhost:8443")
    monkeypatch.setenv("KB_CONNECTOR_ALLOW_INSECURE_ENDPOINT", "1")
    assert validate_endpoint("https://localhost:8443") == "https://localhost:8443"


# --- T-03: tag-verified ownership -------------------------------------------


def _tags(managed=True, connector="alpha"):
    out = []
    if managed:
        out.append({"Key": MANAGED_BY_KEY, "Value": MANAGED_BY_VALUE})
    if connector:
        out.append({"Key": CONNECTOR_KEY, "Value": connector})
    return out


def test_classify_ours_when_tool_and_connector_match():
    assert classify_ownership(_tags(), "alpha") is Ownership.OURS


def test_classify_other_connector_is_not_safe_to_mutate():
    verdict = classify_ownership(_tags(connector="beta"), "alpha")
    assert verdict is Ownership.OTHER_CONNECTOR
    assert not verdict.safe_to_mutate


def test_classify_untagged_is_unmanaged():
    verdict = classify_ownership([], "alpha")
    assert verdict is Ownership.UNMANAGED
    assert not verdict.safe_to_mutate


def test_classify_foreign_managed_by_is_unmanaged():
    """A resource tagged by something else entirely isn't ours."""
    other = [{"Key": MANAGED_BY_KEY, "Value": "some-other-tool"}]
    assert classify_ownership(other, "alpha") is Ownership.UNMANAGED


def test_unreadable_tags_are_unverifiable_not_unmanaged():
    """Absence of evidence must not read as evidence of ownership."""
    verdict = classify_ownership(_tags(), "alpha", verifiable=False)
    assert verdict is Ownership.UNVERIFIABLE
    assert not verdict.safe_to_mutate


def test_missing_connector_tag_still_ours():
    """Bucket tags carry ManagedBy only, since the bucket is shared."""
    assert classify_ownership(_tags(connector=None), None) is Ownership.OURS


def test_normalize_tags_accepts_both_aws_shapes():
    as_list = [{"Key": "a", "Value": "1"}]
    assert normalize_tags(as_list) == {"a": "1"}
    assert normalize_tags({"a": "1"}) == {"a": "1"}
    assert normalize_tags(None) == {}
    assert normalize_tags("nonsense") == {}


def test_build_tag_list_shape():
    tags = build_tag_list("alpha")
    assert {"Key": MANAGED_BY_KEY, "Value": MANAGED_BY_VALUE} in tags
    assert {"Key": CONNECTOR_KEY, "Value": "alpha"} in tags


def test_provisioned_resource_state_marker():
    created = ProvisionedResource("arn:x", Ownership.CREATED)
    adopted = ProvisionedResource("arn:y", Ownership.UNMANAGED)
    assert created.state_marker == OWNER_TOOL
    assert created.created
    assert adopted.state_marker == OWNER_EXTERNAL
    assert not adopted.created


def test_created_but_untagged_gets_its_own_marker():
    """A resource we made but couldn't tag is neither plain "tool" nor external.

    Collapsing it into either one loses the connector: "tool" claims a tag that
    isn't there, "external" drops it out of teardown's scope.
    """
    degraded = ProvisionedResource("arn:z", Ownership.CREATED, tagged=False)
    assert degraded.state_marker == OWNER_TOOL_UNTAGGED
    assert degraded.created


def test_untagged_tool_resource_is_still_teardown_eligible():
    cs = ConnectorState()
    cs.record_ownership(RESOURCE_ROLE, OWNER_TOOL_UNTAGGED)
    assert cs.is_tool_owned(RESOURCE_ROLE)
    assert cs.created_untagged(RESOURCE_ROLE)
    # It is ours, so it must not show up as adopted.
    assert cs.adopted_resources() == []


def test_created_untagged_is_false_for_normal_and_external():
    cs = ConnectorState()
    cs.record_owned(RESOURCE_ROLE)
    cs.record_external(RESOURCE_KB)
    assert not cs.created_untagged(RESOURCE_ROLE)
    assert not cs.created_untagged(RESOURCE_KB)
    assert not cs.created_untagged("never-recorded")


def test_unknown_marker_falls_back_to_external():
    """An unrecognized marker must fail safe: teardown leaves it alone."""
    cs = ConnectorState()
    cs.record_ownership(RESOURCE_ROLE, "something-unexpected")
    assert not cs.is_tool_owned(RESOURCE_ROLE)


def test_degraded_ownership_survives_state_roundtrip(tmp_path):
    """The whole point of the marker is that it outlives the process."""
    path = str(tmp_path / "state.json")
    sf = StateFile()
    sf.get("alpha").record_ownership(RESOURCE_ROLE, OWNER_TOOL_UNTAGGED)
    save_state(sf, path)
    reloaded = load_state(path).get("alpha")
    assert reloaded.created_untagged(RESOURCE_ROLE)
    assert reloaded.is_tool_owned(RESOURCE_ROLE)


def test_untagged_resource_is_reclaimed_when_state_says_we_made_it():
    """The degraded round-trip: we created it untagged, so reuse it.

    Without this the tool refuses a resource it created itself, and the only
    documented remedy records it as external — permanently removing it from
    teardown's scope over a missing IAM permission.
    """
    assert _reclaim_untagged(Ownership.UNMANAGED, True)


def test_reclaim_only_applies_to_unmanaged():
    """Tag evidence, or the absence of any reading, always wins over state."""
    # A different connector's tag is real evidence — never override it.
    assert not _reclaim_untagged(Ownership.OTHER_CONNECTOR, True)
    # Unreadable tags say nothing either way, so keep refusing.
    assert not _reclaim_untagged(Ownership.UNVERIFIABLE, True)
    # And with nothing recorded in state there is no basis to reclaim.
    assert not _reclaim_untagged(Ownership.UNMANAGED, False)


def test_is_tagging_access_error_distinguishes_tagging_from_general_denial():
    assert is_tagging_access_error(
        Exception("AccessDenied: not authorized to perform iam:TagRole")
    )
    assert is_tagging_access_error(
        Exception("AccessDenied on secretsmanager:TagResource")
    )
    # A denial on the create itself is a real failure, not a tagging fallback.
    assert not is_tagging_access_error(
        Exception("AccessDenied: not authorized to perform iam:CreateRole")
    )
    assert not is_tagging_access_error(Exception("ValidationException"))


# --- T-02: teardown ownership gate ------------------------------------------


def test_adopted_resources_are_not_tool_owned():
    cs = ConnectorState()
    cs.record_owned(RESOURCE_SECRET)
    cs.record_external(RESOURCE_KB)
    assert cs.is_tool_owned(RESOURCE_SECRET)
    assert not cs.is_tool_owned(RESOURCE_KB)
    assert cs.adopted_resources() == [RESOURCE_KB]


def test_unrecorded_resource_defaults_to_tool_owned():
    """Adoption is always recorded, so an absent entry means "not adopted"."""
    assert ConnectorState().is_tool_owned(RESOURCE_SECRET)


def test_record_ownership_maps_markers():
    cs = ConnectorState()
    cs.record_ownership(RESOURCE_SECRET, OWNER_TOOL)
    cs.record_ownership(RESOURCE_KB, OWNER_EXTERNAL)
    assert cs.is_tool_owned(RESOURCE_SECRET)
    assert not cs.is_tool_owned(RESOURCE_KB)


def test_ownership_survives_state_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    sf = StateFile()
    cs = sf.get("alpha")
    cs.record_external(RESOURCE_KB)
    save_state(sf, path)
    assert not load_state(path).get("alpha").is_tool_owned(RESOURCE_KB)


# --- T-10: file permissions -------------------------------------------------


def test_state_file_is_owner_only(tmp_path):
    path = str(tmp_path / "state.json")
    save_state(StateFile(), path)
    assert describe_mode(path) == "0o600"


def test_atomic_write_json_is_owner_only_and_leaves_no_temp(tmp_path):
    path = str(tmp_path / "out.json")
    atomic_write_json(path, {"a": 1})
    assert describe_mode(path) == "0o600"
    assert json.loads(open(path).read()) == {"a": 1}
    strays = [p for p in os.listdir(tmp_path) if p.startswith(".kbc-")]
    assert strays == []


def test_atomic_write_tightens_existing_loose_file(tmp_path):
    path = tmp_path / "out.json"
    path.write_text("{}")
    os.chmod(path, 0o644)
    atomic_write_json(str(path), {"a": 1})
    assert describe_mode(str(path)) == "0o600"


def test_atomic_write_bytes_is_owner_only(tmp_path):
    target = tmp_path / "out.toml"
    atomic_write_bytes(str(target), b'region = "us-west-2"\n')
    assert describe_mode(str(target)) == "0o600"
    assert target.read_bytes() == b'region = "us-west-2"\n'


def test_atomic_write_bytes_leaves_no_temp_file(tmp_path):
    atomic_write_bytes(str(tmp_path / "out.toml"), b"x = 1\n")
    assert [p.name for p in tmp_path.iterdir()] == ["out.toml"]


def test_atomic_write_bytes_tightens_existing_loose_file(tmp_path):
    target = tmp_path / "out.toml"
    target.write_bytes(b"old")
    os.chmod(target, 0o644)
    atomic_write_bytes(str(target), b"new")
    assert describe_mode(str(target)) == "0o600"


def test_generated_config_is_owner_only(tmp_path):
    """The config file carries tenant/account detail, so it is 0600 too."""
    import argparse
    import json

    from kb_connector.cli.init_cmd import _init_from_fixture

    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({
        "defaults": {"region": "us-west-2"},
        "connectors": {"c1": {"type": "sharepoint"}},
    }))
    out = tmp_path / "kb-connector.toml"
    rc = _init_from_fixture(argparse.Namespace(
        from_file=str(fixture), output=str(out)
    ))
    assert rc == 0
    assert describe_mode(str(out)) == "0o600"
    assert "us-west-2" in out.read_text()


def test_open_owner_only_refuses_to_follow_a_symlink(tmp_path):
    """Following a link would write owner-only content to an attacker's target."""
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    os.chmod(victim, 0o644)
    link = tmp_path / "events.jsonl"
    link.symlink_to(victim)

    with pytest.raises(OSError):
        open_owner_only(str(link))

    assert victim.read_text() == "original"
    assert describe_mode(str(victim)) == "0o644"


def test_open_owner_only_creates_restricted_file(tmp_path):
    path = str(tmp_path / "events.jsonl")
    with open_owner_only(path) as f:
        f.write("{}\n")
    assert describe_mode(path) == "0o600"


def test_state_file_never_contains_stashed_secrets(tmp_path, fixture_secret_factory):
    """The dynamic-attribute stash must stay out of the serialized state."""
    path = str(tmp_path / "state.json")
    p12 = fixture_secret_factory("p12")
    cert_password = fixture_secret_factory("certpw")
    client_secret = fixture_secret_factory("clientsecret")
    private_key = fixture_secret_factory("privkey")

    sf = StateFile()
    cs = sf.get("alpha")
    cs._p12_bytes = p12.encode()
    cs._cert_password = cert_password
    cs._client_secret = client_secret
    cs._private_key_b64 = private_key
    save_state(sf, path)

    raw = open(path).read()
    for secret in (p12, cert_password, client_secret, private_key):
        assert secret not in raw


# --- T-11: secret material excluded from repr -------------------------------


def test_generated_certificate_repr_hides_key_material(fixture_secret):
    from kb_connector.providers.microsoft.certs import generate_self_signed

    cert = generate_self_signed(
        common_name="t", valid_days=1, pkcs12_password=fixture_secret
    )
    rendered = repr(cert)
    assert fixture_secret not in rendered
    assert cert.private_key_b64_pkcs8[:24] not in rendered
    # Still readable by the code that needs it.
    assert cert.pkcs12_password == fixture_secret
    assert cert.pkcs12_bytes


def test_document_event_repr_hides_raw_log_payload():
    event = DocumentEvent(
        document_id="d1",
        document_location="https://x/y.docx",
        status="FAILED",
        details={"internalField": "SENSITIVE-LOG-PAYLOAD"},
    )
    assert "SENSITIVE-LOG-PAYLOAD" not in repr(event)


# --- T-13: crawl target validation ------------------------------------------


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://example.com/docs",
    "https://sub.example.co.uk/a/b?page=2",
])
def test_web_accepts_public_targets(url):
    from kb_connector.connectors.web import build_connector_params

    params = build_connector_params(seed_urls=[url])
    assert params["connectionConfiguration"]["seedUrls"] == [url]


@pytest.mark.parametrize("url,expected", [
    ("http://169.254.169.254/latest/meta-data/", "link-local"),
    ("https://127.0.0.1/", "non-routable"),
    ("http://10.0.0.5/", "non-routable"),
    ("http://192.168.1.1/", "non-routable"),
    ("https://localhost/x", "localhost"),
    ("file:///etc/passwd", "crawls over"),
    ("s3://bucket/key", "crawls over"),
    ("notaurl", "crawls over"),
])
def test_web_rejects_non_public_or_non_http_targets(url, expected):
    from kb_connector.connectors.web import build_connector_params

    with pytest.raises(ValueError, match=expected):
        build_connector_params(seed_urls=[url])


def test_web_validates_sitemap_urls_too():
    from kb_connector.connectors.web import build_connector_params

    with pytest.raises(ValueError, match="sitemap_urls"):
        build_connector_params(
            seed_urls=["https://example.com"],
            sitemap_urls=["http://169.254.169.254/"],
        )


# --- T-15: log redaction ----------------------------------------------------


def test_redaction_removes_filename_and_query_string():
    out = redact_document_location(
        "https://contoso.sharepoint.com/sites/HR/offer-letter.docx?token=abc&sig=xyz"
    )
    assert "offer-letter" not in out
    assert "token" not in out
    assert "abc" not in out
    # Enough signal left to identify which location pattern is failing.
    assert "contoso.sharepoint.com" in out
    assert out.endswith(".docx")


def test_redaction_elides_deep_paths():
    out = redact_document_location(
        "https://contoso.sharepoint.com/sites/Fin/a/b/c/d/payroll.xlsx"
    )
    assert "payroll" not in out
    assert "…" in out


def test_redaction_handles_non_url_locations():
    assert "termination" not in redact_document_location(
        "s3://bucket/hr/termination-notice.pdf"
    )
    assert redact_document_location("bare-document-id") == "<redacted>"
    assert redact_document_location("") == ""


def test_analyze_logs_redacts_samples_by_default():
    events = [
        DocumentEvent("d1", "https://x.com/sites/A/secret-payroll.xlsx", "FAILED",
                      "AccessDenied"),
    ]
    result = analyze_logs(events)
    assert "secret-payroll" not in json.dumps(
        [g.sample_documents for g in result.groups]
    )


def test_analyze_logs_can_opt_out_of_redaction():
    location = "https://x.com/sites/A/secret-payroll.xlsx"
    result = analyze_logs(
        [DocumentEvent("d1", location, "FAILED", "AccessDenied")], redact=False
    )
    assert result.groups[0].sample_documents == [location]


def test_redaction_drops_userinfo_credentials():
    """netloc carries userinfo; the prefix must be rebuilt from hostname."""
    out = redact_document_location(
        "https://admin:s3cr3tP4ss@contoso.sharepoint.com/sites/Fin/pay.xlsx"
    )
    assert "s3cr3tP4ss" not in out
    assert "admin" not in out
    assert "contoso.sharepoint.com" in out


def test_redaction_preserves_explicit_port():
    out = redact_document_location("https://intranet.example.com:8443/docs/a/b.pdf")
    assert "intranet.example.com:8443" in out


def test_redaction_hides_onedrive_user_identity():
    """The second path segment on a personal site is the owning user."""
    out = redact_document_location(
        "https://contoso-my.sharepoint.com/personal/"
        "john_doe_contoso_com/Documents/Private/pay.xlsx"
    )
    assert "john_doe" not in out
    assert "contoso_com" not in out
    # The shape is still legible.
    assert out == "https://contoso-my.sharepoint.com/personal/…/<redacted>.xlsx"


def test_redact_reason_scrubs_embedded_url():
    """A service reason routinely embeds the document URL (T-15)."""
    out = redact_reason(
        "AccessDenied reading "
        "https://c.sharepoint.com/sites/Finance/Private/salaries-2026.xlsx"
    )
    assert "salaries-2026" not in out
    assert "Private" not in out
    assert "AccessDenied reading" in out


def test_redact_reason_scrubs_bare_filename():
    out = redact_reason("Failed to parse document Q4-Layoffs-Confidential.docx")
    assert "Layoffs" not in out
    assert "<redacted>.docx" in out


@pytest.mark.parametrize(
    "reason",
    [
        "Throttled by upstream after 3 retries; version 1.2 in use",
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:kb-connector/x-ab1",
        "Connection reset by contoso.sharepoint.com",
        "",
    ],
)
def test_redact_reason_leaves_non_document_text_intact(reason):
    """No false positives: version strings, ARNs and hostnames survive."""
    assert redact_reason(reason) == reason


def test_redact_reason_passes_through_none():
    assert redact_reason(None) is None


def test_analyze_logs_redacts_reason_and_actionable_issues():
    """The whole result must be free of the filename, not just the samples."""
    events = [
        DocumentEvent(
            "d1",
            "https://x.com/sites/A/pay.xlsx",
            "FAILED",
            "AccessDenied reading https://x.com/sites/HR/secret-payroll.xlsx",
        )
    ]
    result = analyze_logs(events)
    blob = json.dumps(asdict(result))
    assert "secret-payroll" not in blob
    assert "HR" not in blob
    # The diagnostic signal survives.
    assert "AccessDenied" in blob


def test_analyze_logs_reason_grouping_stays_exact_under_redaction():
    """Redaction happens at emission, so distinct reasons stay distinct."""
    events = [
        DocumentEvent("d1", "https://x.com/a/1.pdf", "FAILED", "denied a-report.pdf"),
        DocumentEvent("d2", "https://x.com/a/2.pdf", "FAILED", "denied b-report.pdf"),
    ]
    result = analyze_logs(events)
    assert len(result.groups) == 2
    assert all(g.count == 1 for g in result.groups)
    assert all("report" not in g.reason for g in result.groups)


# --- T-17: OData escaping ---------------------------------------------------


def test_odata_literal_escaping_doubles_quotes():
    assert escape_odata_literal("O'Brien") == "O''Brien"
    assert escape_odata_literal("a' or displayName eq 'b") == (
        "a'' or displayName eq ''b"
    )
    assert escape_odata_literal("plain") == "plain"


def test_find_application_reverifies_exact_name():
    """A server-side filter match isn't trusted on its own."""
    from unittest.mock import MagicMock

    from kb_connector.providers.microsoft.apps import find_application_by_name

    graph = MagicMock()
    graph.get.return_value = {"value": [{"appId": "a", "id": "1",
                                         "displayName": "something-else"}]}
    assert find_application_by_name(graph, "wanted") is None

    graph.get.return_value = {"value": [{"appId": "a", "id": "1",
                                         "displayName": "wanted"}]}
    assert find_application_by_name(graph, "wanted")["appId"] == "a"


# --- T-05 / T-19: generated policy shape ------------------------------------


def test_inline_policy_adds_scoped_kms_decrypt_when_cmk_used():
    policy = build_inline_policy(
        account_id="111122223333",
        region="us-east-1",
        secret_arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:s",
        cert_bucket=None,
        cert_key=None,
        kms_key_arn="arn:aws:kms:us-east-1:111122223333:key/abc",
    )
    kms = [s for s in policy["Statement"] if s["Sid"] == "KmsDecryptStatement"]
    assert len(kms) == 1
    assert kms[0]["Resource"] == ["arn:aws:kms:us-east-1:111122223333:key/abc"]
    # ViaService keeps this from being a standalone Decrypt grant.
    via = kms[0]["Condition"]["StringEquals"]["kms:ViaService"]
    assert any("secretsmanager" in v for v in via)
    # The key also encrypts the knowledge base, so Bedrock has to be able to
    # reach it, and encrypting needs the write side of the key.
    assert "bedrock.us-east-1.amazonaws.com" in via
    assert "kms:GenerateDataKey" in kms[0]["Action"]


def test_inline_policy_kms_grant_stays_narrow():
    """The grant must not widen beyond the three services that use the key."""
    policy = build_inline_policy(
        account_id="111122223333",
        region="us-east-1",
        secret_arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:s",
        cert_bucket=None,
        cert_key=None,
        kms_key_arn="arn:aws:kms:us-east-1:111122223333:key/abc",
    )
    kms = [s for s in policy["Statement"] if s["Sid"] == "KmsDecryptStatement"][0]
    assert set(kms["Condition"]["StringEquals"]["kms:ViaService"]) == {
        "secretsmanager.us-east-1.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "bedrock.us-east-1.amazonaws.com",
    }
    # No kms:* and no re-encrypt or key-management actions.
    assert set(kms["Action"]) == {
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:GenerateDataKey",
    }


def test_inline_policy_omits_kms_without_cmk():
    policy = build_inline_policy(
        account_id="111122223333",
        region="us-east-1",
        secret_arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:s",
        cert_bucket=None,
        cert_key=None,
    )
    assert not [s for s in policy["Statement"] if s["Sid"] == "KmsDecryptStatement"]


# --- T-26: kms_key_arn reaches a policy Resource, so it is shape-checked -----


def _config_with_kms(tmp_path, value):
    """Write a minimal config carrying the given kms_key_arn."""
    path = tmp_path / "kb-connector.toml"
    path.write_text(
        '[defaults]\nregion = "us-west-2"\n'
        f'kms_key_arn = "{value}"\n\n'
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
    )
    return path


@pytest.mark.parametrize("value", [
    "*",
    "arn:aws:kms:us-east-1:111122223333:key/*",
    "arn:aws:kms:us-east-1:111122223333:key/ab?",
    "arn:aws:s3:::not-a-kms-arn",
    "not-an-arn",
])
def test_kms_key_arn_rejected_before_it_reaches_a_policy(tmp_path, value):
    """A wildcard or wrong-service ARN here would widen the KB role's KMS grant."""
    config = _config_with_kms(tmp_path, value)
    with pytest.raises(ConfigError):
        load_config(str(config)).resolve_connector("eng")


def test_kms_key_arn_accepts_a_single_key():
    """The legitimate shape still resolves."""
    from kb_connector.core.identifiers import validate_arn

    arn = "arn:aws:kms:us-east-1:111122223333:key/abc-123"
    assert validate_arn(arn, field="kms_key_arn", service="kms") == arn


def test_secret_grant_is_read_only_and_single_resource():
    """The KB role reads the secret at crawl time; it never writes it."""
    arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:s"
    policy = build_inline_policy(
        account_id="111122223333", region="us-east-1", secret_arn=arn,
        cert_bucket=None, cert_key=None,
    )
    stmt = next(s for s in policy["Statement"]
                if s["Sid"] == "SecretsManagerGetStatement")
    assert stmt["Action"] == ["secretsmanager:GetSecretValue"]
    assert stmt["Resource"] == [arn]


def test_no_statement_grants_unconditional_wildcard():
    """The only Resource:* is CloudWatch, which must carry a namespace condition."""
    policy = build_inline_policy(
        account_id="111122223333",
        region="us-east-1",
        secret_arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:s",
        cert_bucket="bucket",
        cert_key="k.p12",
    )
    for stmt in policy["Statement"]:
        if "*" in stmt.get("Resource", []):
            assert stmt.get("Condition"), (
                f"{stmt['Sid']} grants Resource:* with no condition"
            )


# --- T-03: operator-supplied tags -------------------------------------------
#
# Organizations that mandate tags (often enforced by an SCP or tag policy that
# denies untagged creates) need to add their own. What must not happen is a
# config file overriding the ownership tags the refusal logic depends on.


def test_extra_tags_merge_with_ownership_tags():
    tags = build_tag_dict("alpha", {"CostCenter": "1234", "Owner": "josh"})
    assert tags["CostCenter"] == "1234"
    assert tags["Owner"] == "josh"
    assert tags[MANAGED_BY_KEY] == MANAGED_BY_VALUE
    assert tags[CONNECTOR_KEY] == "alpha"


def test_ownership_tags_cannot_be_displaced_by_extra_tags():
    """Even if validation were bypassed, the builder must win."""
    tags = build_tag_dict("alpha", {MANAGED_BY_KEY: "evil", CONNECTOR_KEY: "beta"})
    assert tags[MANAGED_BY_KEY] == MANAGED_BY_VALUE
    assert tags[CONNECTOR_KEY] == "alpha"


def test_extra_tags_reach_the_list_and_query_shapes():
    assert {"Key": "CostCenter", "Value": "1234"} in build_tag_list(
        "alpha", {"CostCenter": "1234"}
    )
    assert "CostCenter=1234" in build_tag_query_string("alpha", {"CostCenter": "1234"})


@pytest.mark.parametrize("bad,expected", [
    ({MANAGED_BY_KEY: "x"}, "reserved"),
    ({CONNECTOR_KEY: "x"}, "reserved"),
    ({"aws:cost": "x"}, "AWS reserves"),
    ({"": "x"}, "cannot be empty"),
    ({"k": {"nested": "table"}}, "must be a string"),
    ({"k": ["a", "b"]}, "must be a string"),
    ({"k": "v" * 257}, "exceeds"),
    ({"k" * 129: "v"}, "exceeds"),
    ("not-a-table", "must be a table"),
])
def test_validate_extra_tags_rejects(bad, expected):
    with pytest.raises(ValueError, match=expected):
        validate_extra_tags(bad)


def test_validate_extra_tags_accepts_and_normalizes():
    assert validate_extra_tags(None) == {}
    assert validate_extra_tags({}) == {}
    # Keys are trimmed and non-string values coerced, so TOML numbers work.
    assert validate_extra_tags({" CostCenter ": 1234}) == {"CostCenter": "1234"}


def test_config_merges_default_and_connector_tags(tmp_path):
    """[defaults.tags] provides the baseline; the connector overrides per key."""
    path = tmp_path / "kb-connector.toml"
    path.write_text(
        '[defaults]\nregion = "us-east-1"\n'
        '[defaults.tags]\nCostCenter = "1234"\nOwner = "platform"\n'
        '[connectors.a]\ntype = "sharepoint"\n'
        '[connectors.a.tags]\nOwner = "josh"\nExtra = "yes"\n'
    )
    cfg = load_config(str(path)).resolve_connector("a")
    assert cfg.tags == {"CostCenter": "1234", "Owner": "josh", "Extra": "yes"}


# --- T-03/T-04: ownership preflight runs before any source-side work ---------
#
# The ensure_* functions refuse unowned resources, but they run after the Entra
# app, its admin consent, and its certificate already exist. These cover the
# read-only preflight that moves the refusal ahead of that work.


def _client_error(code, status, op="HeadBucket"):
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, op
    )


class _FakeResourceNotFoundException(Exception):
    """Named so provisioning._classify_secret recognizes it as 'absent'."""


class _FakeS3:
    def __init__(self, exists, tag_set=None):
        self._exists, self._tag_set = exists, tag_set

    def head_bucket(self, Bucket):
        if not self._exists:
            raise _client_error("404", 404)

    def get_bucket_tagging(self, Bucket):
        if self._tag_set is None:
            raise _client_error("NoSuchTagSet", 404, "GetBucketTagging")
        return {"TagSet": self._tag_set}


class _FakeSecrets:
    def __init__(self, exists, tags=None):
        self._exists, self._tags = exists, tags

    def describe_secret(self, SecretId):
        if not self._exists:
            raise _FakeResourceNotFoundException("ResourceNotFoundException")
        return {"ARN": f"arn:aws:secretsmanager:::secret:{SecretId}",
                "Tags": self._tags or []}


class _FakeIam:
    def __init__(self, exists, tags=None):
        self._exists, self._tags = exists, tags

    def get_role(self, RoleName):
        if not self._exists:
            raise _FakeResourceNotFoundException("NoSuchEntity")
        return {"Role": {"Arn": f"arn:aws:iam:::role/{RoleName}",
                         "Tags": self._tags or []}}


class _FakeSession:
    def __init__(self, s3=None, secrets=None, iam=None):
        self._map = {"s3": s3, "secretsmanager": secrets, "iam": iam}

    def client(self, name):
        client = self._map.get(name)
        if client is None:
            raise AssertionError(f"unexpected client requested: {name}")
        return client


def _preflight(**kw):
    from kb_connector.core.provisioning import preflight_ownership
    return preflight_ownership(**kw)


def test_preflight_clean_when_nothing_exists():
    """The normal first run: absent resources are not conflicts."""
    session = _FakeSession(_FakeS3(False), _FakeSecrets(False), _FakeIam(False))
    assert _preflight(
        session=session, connector_name="alpha", cert_bucket="b",
        secret_name="s", role_name="r",
    ) == []


def test_preflight_clean_when_resources_are_tool_owned():
    owned = _tags(connector="alpha")
    session = _FakeSession(
        _FakeS3(True, _tags(connector=None)),  # bucket carries ManagedBy only
        _FakeSecrets(True, owned),
        _FakeIam(True, owned),
    )
    assert _preflight(
        session=session, connector_name="alpha", cert_bucket="b",
        secret_name="s", role_name="r",
    ) == []


def test_preflight_reports_every_untagged_resource():
    """All conflicts surface at once, and each names the missing tag."""
    session = _FakeSession(_FakeS3(True, []), _FakeSecrets(True, []), _FakeIam(True, []))
    conflicts = _preflight(
        session=session, connector_name="alpha", cert_bucket="mybucket",
        secret_name="mysecret", role_name="myrole",
    )
    assert len(conflicts) == 3
    joined = "\n".join(conflicts)
    for name in ("mybucket", "mysecret", "myrole"):
        assert name in joined
    assert joined.count(f"no {MANAGED_BY_KEY}={MANAGED_BY_VALUE} tag") == 3


def test_preflight_reports_another_connectors_resource():
    session = _FakeSession(
        _FakeS3(False), _FakeSecrets(True, _tags(connector="beta")), _FakeIam(False),
    )
    conflicts = _preflight(
        session=session, connector_name="alpha", cert_bucket="b",
        secret_name="s", role_name="r",
    )
    assert len(conflicts) == 1
    assert "another" in conflicts[0]


def test_preflight_skips_resources_not_requested():
    """Passing None must not probe that client at all (see _FakeSession)."""
    session = _FakeSession(secrets=_FakeSecrets(False))
    assert _preflight(
        session=session, connector_name="alpha", cert_bucket=None,
        secret_name="s", role_name=None,
    ) == []


def test_preflight_untagged_is_unverifiable_when_tags_disabled():
    """--no-tags means ownership can't be confirmed, so reuse is still refused."""
    session = _FakeSession(secrets=_FakeSecrets(True, _tags(connector="alpha")))
    conflicts = _preflight(
        session=session, connector_name="alpha", secret_name="s", tags_enabled=False,
    )
    assert len(conflicts) == 1
    assert "could not be read" in conflicts[0]


# --- Derived-name inputs are validated at config resolution ------------------


def _write_config(tmp_path, body: str) -> str:
    path = tmp_path / "kb-connector.toml"
    path.write_text(body)
    return str(path)


def test_connector_name_with_iam_wildcard_is_refused(tmp_path):
    """A '*' in the name would widen the KB role's S3 grant."""
    cfg = load_config(_write_config(tmp_path, """
[connectors."evil*"]
type = "sharepoint"
"""))
    with pytest.raises(ConfigError, match="wildcard"):
        cfg.resolve_connector("evil*")


def test_resource_prefix_with_wildcard_is_refused(tmp_path):
    cfg = load_config(_write_config(tmp_path, """
[connectors.c1]
type = "sharepoint"
resource_prefix = "team*"
"""))
    with pytest.raises(ConfigError, match="wildcard"):
        cfg.resolve_connector("c1")


def test_cert_key_prefix_with_wildcard_is_refused(tmp_path):
    cfg = load_config(_write_config(tmp_path, """
[connectors.c1]
type = "sharepoint"
cert_s3_key_prefix = "kb-connector/*"
"""))
    with pytest.raises(ConfigError, match="wildcard"):
        cfg.resolve_connector("c1")


def test_connector_name_with_slash_is_refused(tmp_path):
    cfg = load_config(_write_config(tmp_path, """
[connectors."a/b"]
type = "sharepoint"
"""))
    with pytest.raises(ConfigError):
        cfg.resolve_connector("a/b")


def test_ordinary_names_and_prefixes_still_resolve(tmp_path):
    cfg = load_config(_write_config(tmp_path, """
[connectors.sharepoint-hr]
type = "sharepoint"
region = "us-west-2"
resource_prefix = "team.finance"
cert_s3_key_prefix = "certs/prod"
"""))
    resolved = cfg.resolve_connector("sharepoint-hr")
    assert resolved.resource_prefix == "team.finance"
    assert resolved.cert_s3_key_prefix == "certs/prod"


# --- Graph requests must not carry the bearer token over plaintext -----------


def test_graph_client_refuses_plaintext_absolute_url():
    """The Graph token holds the operator's full directory privileges."""
    from kb_connector.core.errors import GraphError
    from kb_connector.providers.microsoft.client import GraphClient

    client = GraphClient("fake-token")
    with pytest.raises(GraphError, match="plaintext"):
        client.get("http://evil.example.com/v1.0/applications")


def test_graph_client_accepts_https_absolute_url(monkeypatch):
    """An @odata.nextLink is still followed, as long as it is TLS."""
    from kb_connector.providers.microsoft.client import GraphClient

    client = GraphClient("fake-token")
    seen: dict = {}

    class _Resp:
        status_code = 200
        content = b"{}"

        def json(self):
            return {}

    def _fake_request(method, url, **kwargs):
        seen["url"] = url
        return _Resp()

    monkeypatch.setattr(client._session, "request", _fake_request)
    client.get("https://graph.microsoft.com/v1.0/applications?$skiptoken=x")
    assert seen["url"].startswith("https://graph.microsoft.com")
