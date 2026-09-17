"""Unit tests for the Amazon Quick admin-managed credential path (no network).

Covers the two pieces that have no Bedrock equivalent: the KMS asymmetric
signing key (core.kms_signing) and the certificate built over its exported
public key (providers.microsoft.certs.generate_kms_backed_cert).
"""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from kb_connector.core import kms_signing
from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import AwsError, ConfigError
from kb_connector.core.state import ConnectorState
from kb_connector.providers.microsoft import certs

KEY_ARN = "arn:aws:kms:us-west-2:123456789012:key/abc-12345"

_OK_META = {
    "Arn": KEY_ARN,
    "KeySpec": "RSA_2048",
    "KeyUsage": "SIGN_VERIFY",
    "Enabled": True,
    "KeyState": "Enabled",
    "MultiRegion": False,
}


@pytest.fixture(scope="module")
def kms_keypair() -> rsa.RSAPrivateKey:
    """Stands in for the KMS key pair, generated once because RSA is slow.

    In production only the public half is exportable; the private half here is
    used solely to emulate what kms:Sign does inside KMS.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def kms_public_der(kms_keypair) -> bytes:
    """The DER SubjectPublicKeyInfo that GetPublicKey returns."""
    return kms_keypair.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture
def kms_sign(kms_keypair):
    """Emulate kms:Sign in DIGEST mode: PKCS#1 v1.5 over a SHA-256 prehash."""
    def sign(message: bytes) -> bytes:
        return kms_keypair.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return sign


def _kms_client(existing: dict | None = None, tags: list | None = None) -> MagicMock:
    kms = MagicMock()

    class NotFoundException(Exception):
        pass

    kms.exceptions.NotFoundException = NotFoundException
    if existing is None:
        kms.describe_key.side_effect = NotFoundException()
    else:
        kms.describe_key.return_value = {"KeyMetadata": existing}
    kms.create_key.return_value = {
        "KeyMetadata": {"Arn": KEY_ARN, "KeyId": "abc-12345"}
    }
    kms.list_resource_tags.return_value = {"Tags": tags or []}
    return kms


def _session(kms: MagicMock) -> MagicMock:
    session = MagicMock()
    session.client.return_value = kms
    return session


def _denied(operation: str) -> ClientError:
    """The exception botocore actually raises, so the narrow excepts are exercised."""
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}},
        operation,
    )


def _ours_tags(connector: str = "c1") -> list[dict[str, str]]:
    """Ownership tags in KMS's TagKey/TagValue spelling."""
    return [
        {"TagKey": "ManagedBy", "TagValue": "kb-connector"},
        {"TagKey": "KbConnectorName", "TagValue": connector},
    ]


# --- Key creation ------------------------------------------------------------


def test_create_key_uses_the_shape_quick_requires():
    """Entra assertion signing needs asymmetric RSA_2048 SIGN_VERIFY, one Region."""
    kms = _kms_client()
    res = kms_signing.ensure_signing_key(
        session=_session(kms), alias="quick-sp", connector_name="c1"
    )

    kwargs = kms.create_key.call_args.kwargs
    assert kwargs["KeySpec"] == "RSA_2048"
    assert kwargs["KeyUsage"] == "SIGN_VERIFY"
    assert kwargs["Origin"] == "AWS_KMS"
    # Explicit rather than defaulted: Quick rejects multi-Region keys.
    assert kwargs["MultiRegion"] is False
    assert res.arn == KEY_ARN
    assert res.created


def test_create_key_attaches_the_alias_so_reruns_find_it():
    kms = _kms_client()
    kms_signing.ensure_signing_key(
        session=_session(kms), alias="quick-sp", connector_name="c1"
    )
    assert kms.create_alias.call_args.kwargs["AliasName"] == "alias/quick-sp"


def test_alias_accepts_bare_or_prefixed_form():
    assert kms_signing.normalize_alias("quick-sp") == "alias/quick-sp"
    assert kms_signing.normalize_alias("alias/quick-sp") == "alias/quick-sp"
    with pytest.raises(AwsError):
        kms_signing.normalize_alias("  ")


def test_alias_failure_reports_the_key_it_stranded():
    """A key with no alias is invisible to the next run, so say so with the ARN."""
    kms = _kms_client()
    kms.create_alias.side_effect = _denied("CreateAlias")
    with pytest.raises(AwsError, match=KEY_ARN):
        kms_signing.ensure_signing_key(
            session=_session(kms), alias="quick-sp", connector_name="c1"
        )


# --- T-03: tag-verified ownership, in KMS's divergent tag shape --------------


def test_existing_key_tagged_ours_is_reused_not_recreated():
    """KMS spells tags TagKey/TagValue; misreading them would recreate the key."""
    kms = _kms_client(existing=dict(_OK_META), tags=_ours_tags())
    res = kms_signing.ensure_signing_key(
        session=_session(kms), alias="quick-sp", connector_name="c1"
    )
    assert res.state_marker == "tool"
    assert not kms.create_key.called


def test_untagged_existing_key_is_refused():
    """An unowned key would be tied to a directory object it does not own."""
    kms = _kms_client(existing=dict(_OK_META), tags=[])
    with pytest.raises(AwsError, match="already exists"):
        kms_signing.ensure_signing_key(
            session=_session(kms), alias="quick-sp", connector_name="c1"
        )


def test_another_connectors_key_is_refused():
    kms = _kms_client(existing=dict(_OK_META), tags=_ours_tags("someone-else"))
    with pytest.raises(AwsError):
        kms_signing.ensure_signing_key(
            session=_session(kms), alias="quick-sp", connector_name="c1"
        )


def test_adopt_existing_records_the_key_external():
    """Deliberate adoption keeps teardown away from it."""
    kms = _kms_client(existing=dict(_OK_META), tags=[])
    res = kms_signing.ensure_signing_key(
        session=_session(kms), alias="quick-sp", connector_name="c1",
        adopt_existing=True,
    )
    assert res.state_marker == "external"


def test_unreadable_tags_are_unverifiable_not_unowned():
    """Absence of evidence is not evidence of ownership."""
    kms = _kms_client(existing=dict(_OK_META))
    kms.list_resource_tags.side_effect = _denied("ListResourceTags")
    with pytest.raises(AwsError, match="could not be read"):
        kms_signing.ensure_signing_key(
            session=_session(kms), alias="quick-sp", connector_name="c1"
        )


def test_untagged_key_is_reclaimed_when_state_says_we_made_it():
    """The tagging-denied path must not orphan its own key on the next run."""
    kms = _kms_client(existing=dict(_OK_META), tags=[])
    res = kms_signing.ensure_signing_key(
        session=_session(kms), alias="quick-sp", connector_name="c1",
        created_untagged=True,
    )
    assert res.state_marker == "tool-untagged"


# --- Key shape is enforced on adoption, not just creation --------------------


@pytest.mark.parametrize(
    "override, expected",
    [
        ({"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"}, "key usage"),
        ({"KeySpec": "RSA_4096"}, "key spec"),
        ({"KeyUsage": "ENCRYPT_DECRYPT"}, "key usage"),
        ({"MultiRegion": True}, "multi-Region"),
        ({"Enabled": False, "KeyState": "Disabled"}, "not enabled"),
        ({"KeyState": "PendingDeletion"}, "pending deletion"),
    ],
)
def test_wrong_key_shape_is_refused_up_front(override, expected):
    """A mismatched key still yields a certificate Entra accepts; the failure
    surfaces much later as an opaque sync error, so it is caught here."""
    kms = _kms_client(existing={**_OK_META, **override}, tags=_ours_tags())
    with pytest.raises(AwsError, match=expected):
        kms_signing.ensure_signing_key(
            session=_session(kms), alias="quick-sp", connector_name="c1"
        )


def test_get_public_key_verifies_shape_of_a_directly_supplied_arn(kms_public_der):
    """A key passed by ARN never went through ensure_signing_key."""
    kms = _kms_client()
    kms.get_public_key.return_value = {
        "PublicKey": kms_public_der,
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT",
    }
    with pytest.raises(AwsError, match="cannot be used to sign"):
        kms_signing.get_public_key_der(session=_session(kms), key_id=KEY_ARN)


def test_get_public_key_returns_der(kms_public_der):
    kms = _kms_client()
    kms.get_public_key.return_value = {
        "PublicKey": kms_public_der,
        "KeySpec": "RSA_2048",
        "KeyUsage": "SIGN_VERIFY",
    }
    got = kms_signing.get_public_key_der(session=_session(kms), key_id=KEY_ARN)
    assert got == kms_public_der


def test_missing_public_key_material_is_an_error():
    kms = _kms_client()
    kms.get_public_key.return_value = {
        "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"
    }
    with pytest.raises(AwsError, match="no public key material"):
        kms_signing.get_public_key_der(session=_session(kms), key_id=KEY_ARN)


# --- T-05 / T-19: generated policy shape ------------------------------------


def test_sign_grant_is_scoped_to_the_one_key():
    stmt = kms_signing.build_sign_grant_statement(
        signing_key_arn=KEY_ARN, principal_arn="arn:aws:iam::1:role/quick"
    )
    assert stmt["Effect"] == "Allow"
    assert stmt["Resource"] == KEY_ARN
    assert "*" not in stmt["Resource"]
    # Sign, and read the public key to know what verifies it. Nothing else:
    # notably no Decrypt, and no key administration.
    assert set(stmt["Action"]) == {"kms:Sign", "kms:GetPublicKey"}


def test_orphan_note_does_not_promise_deletion():
    """KMS has no immediate delete, and the key may back other knowledge bases."""
    note = kms_signing.describe_orphan_risk(KEY_ARN)
    assert "not deleted automatically" in note
    assert KEY_ARN in note
    assert not hasattr(kms_signing, "delete_signing_key")


# --- The certificate over the KMS public key ---------------------------------


def test_cert_embeds_the_kms_public_key(kms_public_der, kms_sign):
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    parsed = x509.load_der_x509_certificate(cert.certificate_der)
    expected = serialization.load_der_public_key(kms_public_der)
    assert parsed.public_key().public_numbers() == expected.public_numbers()


def test_cert_is_rfc_compliant_signature_matches_embedded_key(
    kms_public_der, kms_sign
):
    """The point of signing via kms:Sign instead of the OpenSSL -force_pubkey
    trick: the signature verifies against the embedded key, so strict X.509
    validators and security review do not see a malformed certificate."""
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    parsed = x509.load_der_x509_certificate(cert.certificate_der)
    # Raises InvalidSignature if the artifact is the mismatched kind.
    parsed.public_key().verify(
        parsed.signature,
        parsed.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_cert_is_self_signed_and_not_a_ca(kms_public_der, kms_sign):
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    parsed = x509.load_der_x509_certificate(cert.certificate_der)
    assert parsed.issuer == parsed.subject
    basic = parsed.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.value.ca is False
    assert basic.critical
    assert parsed.serial_number > 0


def test_cert_thumbprint_is_unpadded_base64url(kms_public_der, kms_sign):
    """Quick wants base64url; Entra's portal shows hex. They are not swappable."""
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    assert "=" not in cert.thumbprint_b64url
    assert not set("+/") & set(cert.thumbprint_b64url)
    assert len(bytes.fromhex(cert.thumbprint_hex)) == 20  # SHA-1
    assert cert.thumbprint_b64url != cert.thumbprint_hex


def test_hex_thumbprint_is_uppercase_like_the_entra_portal(kms_public_der, kms_sign):
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    assert cert.thumbprint_hex == cert.thumbprint_hex.upper()


def test_cert_carries_no_private_key_material(kms_public_der, kms_sign):
    """There is nothing to leak: the private half never left KMS."""
    cert = certs.generate_kms_backed_cert(
        public_key_der=kms_public_der, signing_key_arn=KEY_ARN, sign=kms_sign
    )
    assert not any("private" in f.lower() for f in vars(cert))
    assert "PRIVATE KEY" not in repr(cert)
    assert cert.signing_key_arn == KEY_ARN


def test_cert_rejects_a_non_rsa_public_key(kms_sign):
    """Guarded rather than cast: it would otherwise fail without naming the spec."""
    ec_der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ValueError, match="RSA"):
        certs.generate_kms_backed_cert(
            public_key_der=ec_der, signing_key_arn=KEY_ARN, sign=kms_sign
        )


def test_cert_refuses_a_signature_from_the_wrong_key(kms_public_der):
    """A signer wired to a different key must fail here, not at sync time."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def wrong_signer(message: bytes) -> bytes:
        return other.sign(message, padding.PKCS1v15(), hashes.SHA256())

    with pytest.raises(ValueError, match="does not verify"):
        certs.generate_kms_backed_cert(
            public_key_der=kms_public_der, signing_key_arn=KEY_ARN,
            sign=wrong_signer,
        )


def test_signer_uses_digest_mode_so_large_certs_still_sign():
    """kms:Sign caps a RAW message at 4096 bytes; a TBSCertificate can exceed it,
    so RAW would pass in testing and fail on a longer subject."""
    kms = _kms_client()
    kms.sign.return_value = {"Signature": b"sig"}
    signer = kms_signing.make_signer(session=_session(kms), key_id=KEY_ARN)

    assert signer(b"x" * 9000) == b"sig"
    kwargs = kms.sign.call_args.kwargs
    assert kwargs["MessageType"] == "DIGEST"
    assert kwargs["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert len(kwargs["Message"]) == 32  # SHA-256 digest, not the message


def test_signer_reports_a_missing_kms_sign_permission():
    kms = _kms_client()
    kms.sign.side_effect = _denied("Sign")
    signer = kms_signing.make_signer(session=_session(kms), key_id=KEY_ARN)
    with pytest.raises(AwsError, match="kms:Sign"):
        signer(b"tbs")


def test_thumbprints_helper_is_shared_by_both_cert_paths():
    """One implementation, so the two flows cannot drift on encoding."""
    b64url, hexed = certs.certificate_thumbprints(b"some-der-bytes")
    assert "=" not in b64url
    assert len(bytes.fromhex(hexed)) == 20


# --- Certificate reuse ------------------------------------------------------


def _state_with_cert(**kw) -> ConnectorState:
    cs = ConnectorState(
        cert_thumbprint_b64url="TP1", signing_key_arn=KEY_ARN
    )
    for key, value in kw.items():
        setattr(cs, key, value)
    return cs


def test_kms_cert_is_reused_when_still_installed():
    from kb_connector.cli.setup import _should_reuse_kms_certificate

    assert _should_reuse_kms_certificate(
        _state_with_cert(), signing_key_arn=KEY_ARN,
        installed_thumbprints=["TP1"], rotate=False,
    )


@pytest.mark.parametrize(
    "kwargs, why",
    [
        (dict(installed_thumbprints=["TP1"], rotate=True), "rotate forces reissue"),
        (dict(installed_thumbprints=[], rotate=False), "no longer on the app"),
    ],
)
def test_kms_cert_is_reissued_when_it_cannot_be_confirmed(kwargs, why):
    from kb_connector.cli.setup import _should_reuse_kms_certificate

    assert not _should_reuse_kms_certificate(
        _state_with_cert(), signing_key_arn=KEY_ARN, **kwargs
    ), why


def test_kms_cert_is_reissued_when_the_signing_key_changed():
    """Keeping a cert built from another key leaves Entra verifying the wrong
    public key, which only fails at sync time."""
    from kb_connector.cli.setup import _should_reuse_kms_certificate

    assert not _should_reuse_kms_certificate(
        _state_with_cert(signing_key_arn="arn:aws:kms:us-west-2:1:key/other"),
        signing_key_arn=KEY_ARN,
        installed_thumbprints=["TP1"],
        rotate=False,
    )


# --- Config: target selection and key validation ----------------------------


def _tool_config(**connector) -> object:
    from kb_connector.core.config import ToolConfig

    return ToolConfig(connectors={"sp": {"type": "sharepoint", **connector}})


def test_target_defaults_to_bmkb():
    cfg = _tool_config().resolve_connector("sp")
    assert cfg.target == "bmkb"


def test_target_quick_resolves():
    cfg = _tool_config(target="Quick").resolve_connector("sp")
    assert cfg.target == "quick"  # normalized


@pytest.mark.parametrize("bad", ["bedrock", "qiuck", "quick "])
def test_unknown_target_is_refused_with_the_valid_names(bad):
    """A typo should name the options, not fail later inside a setup flow."""
    with pytest.raises(ConfigError) as exc:
        _tool_config(target=bad.strip() + "x").resolve_connector("sp")
    assert "quick" in str(exc.value)
    assert "bmkb" in str(exc.value)


def test_empty_target_is_treated_as_unset():
    """`target = ""` reads as "not specified" rather than as a bad name."""
    assert _tool_config(target="").resolve_connector("sp").target == "bmkb"


def test_non_string_target_is_refused_by_type():
    with pytest.raises(ConfigError, match="must be a string"):
        _tool_config(target=7).resolve_connector("sp")


def test_signing_key_arn_must_be_a_kms_arn():
    with pytest.raises(ConfigError, match="signing_key_arn"):
        _tool_config(
            signing_key_arn="arn:aws:s3:::not-a-key"
        ).resolve_connector("sp")


def test_signing_key_arn_wildcard_is_refused():
    """It reaches a policy Resource, where key/* grants every key in the account."""
    with pytest.raises(ConfigError, match="wildcard"):
        _tool_config(
            signing_key_arn="arn:aws:kms:us-west-2:123456789012:key/*"
        ).resolve_connector("sp")


def test_signing_key_wildcard_is_refused_from_a_cli_override_too():
    """The flag must not be a way around the config-file check."""
    with pytest.raises(ConfigError, match="wildcard"):
        _tool_config().resolve_connector(
            "sp",
            cli_overrides={
                "signing_key_arn": "arn:aws:kms:us-west-2:123456789012:key/*"
            },
        )


# --- Setup guardrails for target = quick ------------------------------------


def _quick_cfg(**kw) -> ConnectorConfig:
    base = dict(
        name="sp", type="sharepoint", credential="cert", target="quick",
        tenant_id="11111111-1111-1111-1111-111111111111", region="us-west-2",
    )
    base.update(kw)
    return ConnectorConfig(**base)


def _run_guards(cfg: ConnectorConfig) -> None:
    from kb_connector.cli.setup import _setup_microsoft

    _setup_microsoft(
        argparse.Namespace(from_handoff=None), cfg, ConnectorState(), "sp", "1"
    )


def test_quick_requires_certificate_credential():
    """There is nowhere in the admin-managed flow for a client secret to go."""
    with pytest.raises(ConfigError, match="requires credential = 'cert'"):
        _run_guards(_quick_cfg(credential="client_secret"))


def test_quick_requires_a_region_before_stage_one():
    """The KMS key is created before the certificate that wraps its public key."""
    with pytest.raises(ConfigError, match="region is required"):
        _run_guards(_quick_cfg(region=None))


def test_quick_rejects_sources_other_than_sharepoint_and_onedrive():
    with pytest.raises(ConfigError, match="SharePoint and OneDrive"):
        _run_guards(_quick_cfg(type="s3"))


# --- OneDrive on the Quick target -------------------------------------------


def test_quick_onedrive_permissions_match_the_documented_set():
    """The Quick guide lists five Graph permissions and no SharePoint REST one."""
    from kb_connector.providers.microsoft.permissions import (
        GRAPH_APP_ID, build_plan,
    )

    plan = build_plan(source="onedrive", acl=True, target="quick")
    assert {r.value for r in plan.requirements} == {
        "Files.Read.All", "Sites.Read.All", "User.Read.All",
        "Group.Read.All", "GroupMember.Read.All",
    }
    # Every one is Microsoft Graph. The Bedrock plan adds SharePoint REST
    # Sites.FullControl.All, which is tenant-wide full control that Quick's
    # documented set does not include.
    assert {r.resource_app_id for r in plan.requirements} == {GRAPH_APP_ID}


def test_quick_onedrive_requests_group_read_all_that_bedrock_never_does():
    """Missing it makes group-based access control resolve to nothing."""
    from kb_connector.providers.microsoft.permissions import build_plan

    quick = {r.value for r in build_plan(
        source="onedrive", acl=True, target="quick").requirements}
    bmkb = {r.value for r in build_plan(
        source="onedrive", acl=True, target="bmkb").requirements}
    assert "Group.Read.All" in quick
    assert "Group.Read.All" not in bmkb
    assert "Sites.FullControl.All" in bmkb
    assert "Sites.FullControl.All" not in quick


def test_quick_onedrive_ignores_acl_false_because_acl_is_mandatory():
    """acl = false has no valid meaning here: admin-managed OneDrive always
    enforces document-level access control, so the plan is ACL-complete either
    way rather than honoring a flag into a set that cannot support the crawl."""
    from kb_connector.providers.microsoft.permissions import build_plan

    assert (
        build_plan(source="onedrive", acl=False, target="quick").requirements
        == build_plan(source="onedrive", acl=True, target="quick").requirements
    )


def test_quick_onedrive_has_no_sites_selected_equivalent():
    """The OneDrive setup guide has no Step 3b: there is no per-site grant, so
    `sites_selected` must be inert rather than quietly altering the plan."""
    from kb_connector.providers.microsoft.permissions import build_plan

    plan = build_plan(source="onedrive", acl=True, target="quick")
    scoped = build_plan(
        source="onedrive", acl=True, sites_selected=True, target="quick"
    )
    assert plan.requirements == scoped.requirements
    # site_role is what drives the per-site grant call; None means no grant.
    assert plan.site_role is None and scoped.site_role is None


def test_quick_onedrive_never_requests_onenote():
    """Notes.Read.All cannot work in admin-managed setup. Microsoft retired
    app-only tokens for the OneNote APIs in March 2025."""
    from kb_connector.providers.microsoft.permissions import build_plan

    values = {r.value for r in build_plan(
        source="onedrive", acl=True, target="quick").requirements}
    assert "Notes.Read.All" not in values


def test_quick_sharepoint_plan_is_unchanged_by_the_target():
    """SharePoint's documented Quick sets already match the Bedrock plan, so the
    target must not alter it, otherwise the shared plan has silently diverged."""
    from kb_connector.providers.microsoft.permissions import build_plan

    for acl in (True, False):
        for sites_selected in (True, False):
            a = build_plan(source="sharepoint", acl=acl,
                           sites_selected=sites_selected, target="bmkb")
            b = build_plan(source="sharepoint", acl=acl,
                           sites_selected=sites_selected, target="quick")
            assert a.requirements == b.requirements
            assert a.site_role == b.site_role


def test_quick_permission_plans_match_the_documented_sets():
    """The Quick guide's four permission sets are what build_plan already emits,
    so the Bedrock plan is reused rather than duplicated."""
    from kb_connector.providers.microsoft.permissions import build_plan

    content = {r.value for r in build_plan(
        source="sharepoint", acl=False, sites_selected=False).requirements}
    assert content == {"Sites.Read.All"}

    with_acl = {r.value for r in build_plan(
        source="sharepoint", acl=True, sites_selected=False).requirements}
    assert with_acl == {
        "Sites.Read.All", "User.Read.All", "GroupMember.Read.All",
        "Sites.FullControl.All",
    }

    scoped = build_plan(source="sharepoint", acl=True, sites_selected=True)
    assert {r.value for r in scoped.requirements} == {
        "Sites.Selected", "User.Read.All", "GroupMember.Read.All",
    }
    # The guide grants per-site "fullcontrol" when ACLs are on.
    assert scoped.site_role == "fullcontrol"
