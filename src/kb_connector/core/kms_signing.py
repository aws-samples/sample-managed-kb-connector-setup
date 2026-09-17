"""AWS KMS asymmetric signing key for Amazon Quick service credentials.

The Quick admin-managed SharePoint flow authenticates to Microsoft Entra with a
signed OAuth client assertion, and Quick performs that signing through KMS. The
private key is generated inside KMS and never leaves it: only the public half is
exported, wrapped in an X.509 certificate, and uploaded to the Entra app
registration (see providers/microsoft/certs.generate_kms_backed_cert).

That makes this key a fundamentally different thing from the `kms_key_arn`
elsewhere in this tool, which is a *symmetric encryption* key protecting the
connector secret, the certificate object, and the knowledge base. This one is
asymmetric and sign-only, so the two are deliberately kept under separate names
(`signing_key_arn` vs `kms_key_arn`). Swapping them produces an authentication
failure with no useful diagnostic.

Key requirements come from the Quick setup guide and are enforced here rather
than assumed, because an adopted key of the wrong shape fails much later, at
crawl time, as an opaque Entra rejection:

    Key type     Asymmetric
    Key usage    SIGN_VERIFY
    Key spec     RSA_2048
    Origin       AWS_KMS
    Regionality  single-Region (multi-Region keys are not supported)

There is deliberately no delete function in this module. See
`describe_orphan_risk` for why teardown reports this key instead of removing it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from kb_connector.core.errors import AwsError
from kb_connector.core.tagging import (
    Ownership,
    ProvisionedResource,
    build_tag_dict,
    classify_ownership,
    describe_conflict,
    is_tagging_access_error,
)

# The shape Quick requires. Checked on create *and* on adopt.
REQUIRED_KEY_SPEC = "RSA_2048"
REQUIRED_KEY_USAGE = "SIGN_VERIFY"

# Entra validates client assertions signed as RS256, which is KMS's
# RSASSA_PKCS1_V1_5_SHA_256. Quick uses it at runtime, and `make_signer` uses it
# at setup time to sign the certificate, so both sides agree by construction.
SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"

_KEY_DESCRIPTION = (
    "Signs Entra OAuth client assertions for an Amazon Quick SharePoint "
    "knowledge base connection (managed by kb-connector)."
)


def _kms_tag_list(connector_name: str | None, extra: Any = None) -> list[dict[str, str]]:
    """Ownership tags in the shape KMS wants.

    KMS is the one service here that spells tags `TagKey`/`TagValue` instead of
    `Key`/`Value`. Building the list through build_tag_dict keeps the ownership
    keys and the reserved-key precedence identical to every other resource; only
    the field names differ.
    """
    return [
        {"TagKey": key, "TagValue": value}
        for key, value in build_tag_dict(connector_name, extra).items()
    ]


def _from_kms_tag_list(raw: Any) -> list[dict[str, str]]:
    """Convert KMS's TagKey/TagValue list into the Key/Value shape.

    Done here rather than by teaching core.tagging.normalize_tags a new shape:
    that function is the input to every ownership decision, and KMS's spelling
    is a quirk of one service rather than a general tag representation. An
    unconverted KMS tag list normalizes to `{}` and would classify a key this
    tool created as UNMANAGED.
    """
    if not isinstance(raw, list):
        return []
    return [
        {"Key": str(item["TagKey"]), "Value": str(item.get("TagValue", ""))}
        for item in raw
        if isinstance(item, dict) and "TagKey" in item
    ]


def normalize_alias(alias: str) -> str:
    """Return `alias` in the `alias/<name>` form KMS expects.

    Accepts either form so config and CLI flags can carry the bare name, which
    is what the Quick guide's example (`quick-sharepoint-service-auth`) looks
    like.
    """
    cleaned = (alias or "").strip()
    if not cleaned:
        raise AwsError("A KMS key alias is required for the signing key.")
    return cleaned if cleaned.startswith("alias/") else f"alias/{cleaned}"


def _describe_key(kms: Any, key_id: str) -> dict | None:
    """DescribeKey, returning None when the key or alias does not exist."""
    try:
        metadata: dict = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    except kms.exceptions.NotFoundException:
        return None
    except (ClientError, BotoCoreError) as exc:
        raise AwsError(f"Could not describe KMS key {key_id!r}: {exc}") from exc
    return metadata


def _verify_key_shape(meta: dict, *, identifier: str) -> None:
    """Refuse a key that cannot sign Entra assertions.

    Raised as a hard error rather than a warning: a key of the wrong spec still
    yields a public key and a certificate that Entra accepts on upload, and the
    mismatch only surfaces later as a failed sync with no indication that the
    key was the cause.
    """
    spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
    usage = meta.get("KeyUsage")
    problems: list[str] = []
    if usage != REQUIRED_KEY_USAGE:
        problems.append(f"key usage is {usage!r}, expected {REQUIRED_KEY_USAGE!r}")
    if spec != REQUIRED_KEY_SPEC:
        problems.append(f"key spec is {spec!r}, expected {REQUIRED_KEY_SPEC!r}")
    if meta.get("MultiRegion"):
        problems.append("it is a multi-Region key, which Quick does not support")
    if not meta.get("Enabled", True):
        problems.append(f"it is not enabled (state: {meta.get('KeyState')!r})")
    if meta.get("KeyState") == "PendingDeletion":
        problems.append("it is pending deletion")
    if problems:
        raise AwsError(
            f"KMS key {identifier!r} cannot be used to sign Entra assertions: "
            + "; ".join(problems)
            + ".\n\nAmazon Quick requires an asymmetric "
            f"{REQUIRED_KEY_SPEC} key with {REQUIRED_KEY_USAGE} usage, in a "
            "single Region. Create a new key, or point --signing-key-alias at "
            "one that matches."
        )


def _key_tags(kms: Any, key_id: str) -> tuple[list[dict[str, str]], bool]:
    """Return a key's tags in Key/Value shape, plus whether they were readable.

    An unreadable tag list is reported rather than treated as empty, so
    classify_ownership can distinguish "no ownership tag" from "I could not
    check", which is the difference between someone else's key and a missing
    kms:ListResourceTags permission.
    """
    try:
        resp = kms.list_resource_tags(KeyId=key_id)
    except (ClientError, BotoCoreError):
        return [], False
    return _from_kms_tag_list(resp.get("Tags")), True


def ensure_signing_key(
    *,
    session: Any,
    alias: str,
    connector_name: str | None = None,
    tags_enabled: bool = True,
    extra_tags: dict | None = None,
    adopt_existing: bool = False,
    created_untagged: bool = False,
) -> ProvisionedResource:
    """Create or reuse the asymmetric signing key; return it with its ownership.

    Idempotent, and addressed by alias so a re-run finds the same key rather
    than creating a second one. The alias is derived from the connector name,
    which makes it predictable, so an existing key's ownership is established
    from its tags before it is reused at all. Reusing a stranger's signing key
    would tie their key's lifecycle to this connector, and the Entra
    certificate this tool then issues would be built from their public key.

    Unlike the IAM role and secret paths, nothing about an adopted key is
    *modified*: the key is only read (DescribeKey/GetPublicKey). The ownership
    check still runs, because teardown consults the same record and the alias
    would otherwise make a stranger's key look like this connector's.
    """
    kms = session.client("kms")
    alias_name = normalize_alias(alias)

    meta = _describe_key(kms, alias_name)
    if meta is not None:
        key_arn = meta["Arn"]
        _verify_key_shape(meta, identifier=alias_name)
        raw_tags, tags_readable = _key_tags(kms, key_arn)
        ownership = classify_ownership(
            raw_tags, connector_name, verifiable=tags_readable and tags_enabled
        )
        from_state = created_untagged and ownership is Ownership.UNMANAGED
        if from_state:
            ownership = Ownership.OURS
        if not ownership.safe_to_mutate and not adopt_existing:
            raise AwsError(
                describe_conflict(
                    resource_kind="KMS signing key",
                    identifier=alias_name,
                    ownership=ownership,
                    connector_name=connector_name,
                    rename_hint="pass --signing-key-alias with a distinct alias",
                )
                + "\n\nThis connector would issue an Entra certificate built "
                "from this key's public half, tying the key to a directory "
                "object it does not own."
            )
        if not ownership.safe_to_mutate:
            ownership = Ownership.UNMANAGED  # adopted deliberately
        tagged = tags_enabled and ownership.tool_created and not from_state
        return ProvisionedResource(arn=key_arn, ownership=ownership, tagged=tagged)

    return _create_signing_key(
        kms,
        alias_name=alias_name,
        connector_name=connector_name,
        tags_enabled=tags_enabled,
        extra_tags=extra_tags,
    )


def _create_signing_key(
    kms: Any,
    *,
    alias_name: str,
    connector_name: str | None,
    tags_enabled: bool,
    extra_tags: dict | None,
) -> ProvisionedResource:
    """CreateKey + CreateAlias, degrading to an untagged key if tagging is denied."""
    params: dict[str, Any] = {
        "Description": _KEY_DESCRIPTION,
        "KeyUsage": REQUIRED_KEY_USAGE,
        "KeySpec": REQUIRED_KEY_SPEC,
        "Origin": "AWS_KMS",
        # Set explicitly rather than left to the default: Quick rejects
        # multi-Region keys, and a default is easier to change upstream than an
        # argument.
        "MultiRegion": False,
    }
    tagged = False
    if tags_enabled:
        params["Tags"] = _kms_tag_list(connector_name, extra_tags)
        tagged = True

    try:
        meta = kms.create_key(**params)["KeyMetadata"]
    except (ClientError, BotoCoreError) as exc:
        if tags_enabled and is_tagging_access_error(exc):
            params.pop("Tags", None)
            tagged = False
            try:
                meta = kms.create_key(**params)["KeyMetadata"]
            except (ClientError, BotoCoreError) as retry_exc:
                raise AwsError(
                    f"Could not create the KMS signing key: {retry_exc}"
                ) from retry_exc
        else:
            raise AwsError(f"Could not create the KMS signing key: {exc}") from exc

    key_arn = meta["Arn"]
    try:
        kms.create_alias(AliasName=alias_name, TargetKeyId=meta["KeyId"])
    except (ClientError, BotoCoreError) as exc:
        # The key exists and is usable by ARN, so this is reported rather than
        # raised: failing here would strand a freshly created key that the next
        # run could not find by alias and would not delete either.
        raise AwsError(
            f"Created KMS signing key {key_arn} but could not attach alias "
            f"{alias_name!r}: {exc}\n\nThe key is usable. Record its ARN and "
            f"pass --signing-key-arn on the next run, or attach the alias "
            f"manually so re-runs can find it."
        ) from exc

    return ProvisionedResource(
        arn=key_arn, ownership=Ownership.CREATED, tagged=tagged
    )


def get_public_key_der(
    *, session: Any, key_id: str, verify_shape: bool = True
) -> bytes:
    """Export the signing key's public half as DER-encoded SubjectPublicKeyInfo.

    This is the exact bytes `aws kms get-public-key --query PublicKey | base64
    --decode` produces, and the input to the Entra certificate. The private half
    stays in KMS, so there is nothing here to protect.
    """
    kms = session.client("kms")
    try:
        resp = kms.get_public_key(KeyId=key_id)
    except (ClientError, BotoCoreError) as exc:
        raise AwsError(
            f"Could not export the public key for {key_id!r}: {exc}"
        ) from exc

    if verify_shape:
        # GetPublicKey echoes the spec and usage, so the check costs nothing
        # extra and also covers a key passed directly by ARN, which never went
        # through ensure_signing_key.
        _verify_key_shape(
            {
                "KeySpec": resp.get("KeySpec") or resp.get("CustomerMasterKeySpec"),
                "KeyUsage": resp.get("KeyUsage"),
            },
            identifier=key_id,
        )

    public_key = resp.get("PublicKey")
    if not public_key:
        raise AwsError(
            f"KMS returned no public key material for {key_id!r}."
        )
    return bytes(public_key)


def make_signer(*, session: Any, key_id: str) -> Callable[[bytes], bytes]:
    """Return a callable that signs arbitrary bytes with the KMS signing key.

    Used to sign the certificate's TBSCertificate at setup time, so the
    certificate is signed by the same key whose public half it carries. Passed as
    a callback into providers.microsoft.certs.generate_kms_backed_cert, which
    keeps that package free of any AWS dependency.

    Signs in DIGEST mode over a locally computed SHA-256 rather than handing KMS
    the raw message. kms:Sign caps a RAW message at 4096 bytes and a
    TBSCertificate can exceed that, so RAW mode would work in testing and then
    fail on a certificate with a longer subject or more extensions.

    Note this means the *operator* running setup needs kms:Sign on the key, not
    only Quick. Creating the key grants the account root full access, so this is
    normally already true.
    """
    kms = session.client("kms")

    def sign(message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        try:
            resp = kms.sign(
                KeyId=key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm=SIGNING_ALGORITHM,
            )
        except (ClientError, BotoCoreError) as exc:
            raise AwsError(
                f"Could not sign the certificate with KMS key {key_id!r}: "
                f"{exc}\n\nThis requires kms:Sign on that key."
            ) from exc
        signature = resp.get("Signature")
        if not signature:
            raise AwsError(f"KMS returned no signature for {key_id!r}.")
        return bytes(signature)

    return sign


def build_sign_grant_statement(*, signing_key_arn: str, principal_arn: str) -> dict:
    """Policy statement letting the Quick service role sign with this key.

    Two ways exist to give Quick access to the key. The documented default is
    the Quick admin console (Manage account -> AWS resources -> AWS Key
    Management Service), which this tool cannot drive. The alternative, for
    organizations that manage their own Quick IAM service role, is to grant
    `kms:Sign` on the key ARN, which is what this statement expresses.

    `kms:GetPublicKey` is included alongside Sign because a signer that cannot
    read the public key cannot confirm which certificate its signature will be
    validated against.
    """
    return {
        "Sid": "QuickSignEntraAssertionStatement",
        "Effect": "Allow",
        "Principal": {"AWS": principal_arn},
        "Action": ["kms:Sign", "kms:GetPublicKey"],
        "Resource": signing_key_arn,
    }


def describe_orphan_risk(signing_key_arn: str) -> str:
    """Operator-facing note on why teardown leaves the signing key in place.

    Deliberately not a delete: KMS has no immediate delete, only
    ScheduleKeyDeletion with a mandatory 7-to-30 day window, and the key is
    shared infrastructure. A single Quick connection can back several knowledge
    bases, so removing the key breaks every one of them, and the break is
    unrecoverable, because a new key means a new certificate and a new Entra upload.
    """
    return (
        f"KMS signing key retained: {signing_key_arn}\n"
        f"  It is not deleted automatically. KMS only supports scheduled "
        f"deletion (7-30 days), and any other Quick knowledge base using this "
        f"connection would stop syncing.\n"
        f"  To remove it once nothing depends on it:\n"
        f"    aws kms schedule-key-deletion --key-id {signing_key_arn} "
        f"--pending-window-in-days 30"
    )
