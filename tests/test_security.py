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

from kb_connector.core.diagnostics import describe_endpoints
from kb_connector.core.errors import ConfigError
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
from botocore.exceptions import ClientError

from kb_connector.core.config import load_config
from kb_connector.core.state import (
    OWNER_EXTERNAL,
    OWNER_TOOL,
    OWNER_TOOL_UNTAGGED,
    RESOURCE_APP,
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
from kb_connector.cli.setup import (
    _record_reused_resource,
    _should_reuse_certificate,
)
from kb_connector.providers.microsoft.apps import escape_odata_literal


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


# --- T-02 / AS-5: a rediscovered resource is only ours if state says so -------
#
# Setup is resumable, so it routinely rediscovers what an earlier pass created:
# Stage 1 finds an Entra app by display name, and the KB id and role ARN are read
# back out of state when not passed on the command line. Disowning those strands
# them beyond teardown's reach; claiming someone else's lets teardown delete it.
# Both directions are pinned, for every resource kind the check covers.

_OURS = "11111111-2222-3333-4444-555555555555"
_OTHER = "99999999-8888-7777-6666-555555555555"

# Each rediscoverable resource kind and the state field holding its identity.
_REDISCOVERABLE = [
    (RESOURCE_APP, "client_app_object_id"),
    (RESOURCE_KB, "knowledge_base_id"),
    (RESOURCE_ROLE, "kb_role_arn"),
]


def _state_recording(resource, field_name, marker, recorded_id=_OURS):
    cs = ConnectorState()
    setattr(cs, field_name, recorded_id)
    if marker is not None:
        cs.created_resources[resource] = marker
    return cs


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_rediscovering_what_we_created_keeps_it_deletable(resource, field_name):
    """The leak this exists to prevent: a re-run must not disown its own work."""
    cs = _state_recording(resource, field_name, OWNER_TOOL)
    assert cs.is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_rediscovering_an_adopted_resource_leaves_it_adopted(resource, field_name):
    """The dangerous direction: never claim what the operator pointed us at."""
    cs = _state_recording(resource, field_name, OWNER_EXTERNAL)
    assert not cs.is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_a_first_run_against_someone_elses_resource_does_not_claim_it(
    resource, field_name
):
    """Nothing is recorded yet, so there is no evidence the resource is ours."""
    assert not ConnectorState().is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_an_unrecorded_resource_is_not_claimed_even_if_the_id_matches(
    resource, field_name
):
    """is_tool_owned treats an absent entry as owned, which is right for
    teardown but wrong here: an explicit record is required."""
    cs = _state_recording(resource, field_name, None)
    assert not cs.is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_a_resource_replaced_out_of_band_is_not_claimed(resource, field_name):
    """Ours was deleted and something else now answers to the same name."""
    cs = _state_recording(resource, field_name, OWNER_TOOL, recorded_id=_OTHER)
    assert not cs.is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_an_untagged_tool_created_resource_is_still_ours(resource, field_name):
    """Created by this tool but untaggable still means ours."""
    cs = _state_recording(resource, field_name, OWNER_TOOL_UNTAGGED)
    assert cs.is_recorded_ours(resource, _OURS)


@pytest.mark.parametrize("resource,field_name", _REDISCOVERABLE)
def test_no_id_to_compare_is_never_claimed(resource, field_name):
    cs = _state_recording(resource, field_name, OWNER_TOOL)
    assert not cs.is_recorded_ours(resource, None)


# --- AS-2: a certificate is one credential split across two systems -----------
#
# The directory holds the public certificate; Secrets Manager and S3 hold the
# private key. Replacing one half without the other breaks authentication while
# leaving both halves individually intact, so a new certificate is issued only
# when asked for or when the halves cannot be confirmed to agree.

_INSTALLED = "MU2ZxMbvstlL9kFKLLyYrg6QF50"


def _state_with_certificate(thumbprint=_INSTALLED, *, s3_key="k.p12", secret="arn:s"):
    cs = ConnectorState()
    cs.cert_thumbprint_b64url = thumbprint
    cs.cert_s3_key = s3_key
    cs.secret_arn = secret
    return cs


def test_a_certificate_still_installed_is_kept():
    """A re-run must not replace a working credential."""
    assert _should_reuse_certificate(
        _state_with_certificate(), installed_thumbprints=[_INSTALLED], rotate=False
    )


def test_rotate_always_issues_a_new_certificate():
    assert not _should_reuse_certificate(
        _state_with_certificate(), installed_thumbprints=[_INSTALLED], rotate=True
    )


def test_a_certificate_the_app_no_longer_carries_is_reissued():
    """The halves already disagree, and reissuing is what puts them back in step."""
    assert not _should_reuse_certificate(
        _state_with_certificate(), installed_thumbprints=["other"], rotate=False
    )


def test_nothing_recorded_means_a_certificate_must_be_issued():
    assert not _should_reuse_certificate(
        ConnectorState(), installed_thumbprints=[_INSTALLED], rotate=False
    )


def test_a_certificate_missing_from_s3_is_reissued():
    """Stage 1 recorded a thumbprint but Stage 2 never stored the private key."""
    cs = _state_with_certificate(s3_key=None)
    assert not _should_reuse_certificate(
        cs, installed_thumbprints=[_INSTALLED], rotate=False
    )


def test_a_certificate_with_no_secret_recorded_is_reissued():
    cs = _state_with_certificate(secret=None)
    assert not _should_reuse_certificate(
        cs, installed_thumbprints=[_INSTALLED], rotate=False
    )


def test_an_unreadable_directory_reissues_rather_than_assuming():
    """Reuse cannot be confirmed, so the safe outcome is a fresh certificate
    written to both halves together."""
    assert not _should_reuse_certificate(
        _state_with_certificate(), installed_thumbprints=[], rotate=False
    )


def test_stage_one_alone_is_refused_for_a_microsoft_connector():
    """Stage 1 holds the credential only in memory, so running it alone cannot
    produce a working connector — and it would replace a certificate that AWS
    still depends on."""
    import argparse

    from kb_connector.cli.setup import _setup_microsoft
    from kb_connector.core.config import ConnectorConfig

    cfg = ConnectorConfig(
        name="c", type="sharepoint", credential="cert", tenant_id="t", region="us-west-2"
    )
    args = argparse.Namespace(from_handoff=None)
    with pytest.raises(ConfigError, match="cannot set up"):
        _setup_microsoft(args, cfg, ConnectorState(), "c", "1")


def test_a_resource_kind_without_a_tracked_id_is_never_claimed():
    """Secrets, certs and data sources are addressed by derived name and
    classified by tag, so they have no id to compare and must not be claimed
    by this check."""
    cs = ConnectorState()
    cs.created_resources[RESOURCE_SECRET] = OWNER_TOOL
    assert not cs.is_recorded_ours(RESOURCE_SECRET, _OURS)


def test_setup_records_a_rediscovered_resource_as_ours():
    """The setup-side wrapper flips the record, not just the return value."""
    cs = _state_recording(RESOURCE_KB, "knowledge_base_id", OWNER_EXTERNAL)
    assert not _record_reused_resource(cs, RESOURCE_KB, _OURS)
    assert not cs.is_tool_owned(RESOURCE_KB)

    cs = _state_recording(RESOURCE_KB, "knowledge_base_id", OWNER_TOOL)
    assert _record_reused_resource(cs, RESOURCE_KB, _OURS)
    assert cs.is_tool_owned(RESOURCE_KB)


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


# --- T-01: endpoint redirection is surfaced before the first write -----------


def _session():
    """A credential-shaped session; endpoint env vars come from monkeypatch."""
    import boto3

    return boto3.Session(
        region_name="us-west-2", aws_access_key_id="A", aws_secret_access_key="B"
    )


def test_default_endpoints_are_reported_as_default(monkeypatch):
    for var in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_BEDROCK_AGENT"):
        monkeypatch.delenv(var, raising=False)
    lines = describe_endpoints(_session(), "us-west-2")
    assert lines == ["AWS endpoints: default for us-west-2"]


def test_service_specific_redirect_is_reported(monkeypatch):
    """A per-service variable must not hide behind an unredirected STS check."""
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_AGENT", "https://elsewhere.example.com")
    lines = describe_endpoints(_session(), "us-west-2")
    assert "REDIRECTED" in lines[0]
    assert any("bedrock-agent: https://elsewhere.example.com" in ln for ln in lines)


def test_global_redirect_reports_every_affected_service(monkeypatch):
    """The exposure is not Bedrock-only: the secret-bearing path moves too."""
    monkeypatch.delenv("AWS_ENDPOINT_URL_BEDROCK_AGENT", raising=False)
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://elsewhere.example.com")
    lines = describe_endpoints(_session(), "us-west-2")
    joined = "\n".join(lines)
    for service in ("bedrock-agent", "secretsmanager", "s3", "sts"):
        assert f"{service}: https://elsewhere.example.com" in joined


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
