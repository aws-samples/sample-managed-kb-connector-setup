"""IAM role create/extend, S3 bucket provisioning, Secrets Manager operations.

Provisions the AWS prerequisites for a managed-connector data source:
  * S3 bucket for certificates (cert mode)
  * IAM service role with correct trust + permissions policies
  * Secrets Manager secret with connector credentials
  * Certificate upload to S3

All operations are idempotent (create-or-update semantics), but idempotent is
not the same as unconditional: because resource names are derived from the
connector name and therefore predictable, every create-or-update path first
establishes *ownership* via tags before it modifies something that already
exists. See core/tagging.py for the model. Functions that ensure a resource
return a ProvisionedResource carrying that ownership verdict so callers can
record it in state and teardown can avoid deleting resources the tool merely
adopted.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from kb_connector.core.errors import AwsError
from kb_connector.core.tagging import (
    Ownership,
    ProvisionedResource,
    build_tag_list,
    build_tag_query_string,
    classify_ownership,
    describe_conflict,
    is_tagging_access_error,
)

_CW_NAMESPACE = "AWS/Bedrock/KnowledgeBases"


# --- Ownership recovery ------------------------------------------------------


def _reclaim_untagged(ownership: Ownership, created_untagged: bool) -> bool:
    """Whether an untagged resource should be reclaimed on the strength of state.

    Tagging degrades gracefully: when the caller lacks iam:TagRole or
    secretsmanager:TagResource the create succeeds untagged. Without this, the
    next run reads the missing tag as UNMANAGED and refuses to reuse a resource
    the tool created itself — and the only remedy,
    `--adopt-existing-resources`, records it as external and so drops it out of
    teardown's scope for good. A missing IAM permission would quietly turn into
    an orphan.

    So when state records that this tool created the resource but could not tag
    it, an absent tag is expected rather than evidence of a stranger's
    resource. Only UNMANAGED is reclaimed — tags readable and no ownership tag,
    which is the exact signature of the degraded path. OTHER_CONNECTOR is left
    alone because a different connector's tag is present and is real evidence,
    and UNVERIFIABLE is left alone because unreadable tags say nothing either
    way.

    This does move the trust anchor from the resource's tags to the local state
    file for this one case. That is the trust teardown already places in state
    (see T-02 in THREAT-MODEL.md) and it is narrower, since deleting a resource
    is the more consequential of the two. The file is written 0600.
    """
    return created_untagged and ownership is Ownership.UNMANAGED


# --- S3 bucket ---------------------------------------------------------------


def ensure_cert_bucket(
    *,
    session: Any,
    bucket: str,
    region: str,
    connector_name: str | None = None,
    tags_enabled: bool = True,
    adopt_existing: bool = False,
    allow_unhardened: bool = False,
    extra_tags: dict | None = None,
) -> ProvisionedResource:
    """Create the certificate bucket if absent; return it with its ownership.

    This bucket receives a PKCS#12 file containing an RSA private key, so both
    the ownership check and the hardening step are treated as preconditions
    for the upload rather than best-effort niceties:

    * An existing bucket is only reused when its tags prove this tool created
      it. Writing key material into a bucket controlled by someone else is
      exactly the exposure worth refusing, so an untagged or foreign bucket
      raises unless `adopt_existing` is set.
    * Public-access-block and default encryption must apply. If they cannot,
      the bucket is not a safe place for a private key and we stop instead of
      uploading anyway. `allow_unhardened` exists for the case where an
      operator has equivalent controls applied out-of-band (SCP, bucket
      policy) and has made that call knowingly.

    Unlike the role and secret, the bucket is shared across connectors by
    design (teardown removes the per-connector object, never the bucket), so
    it is tagged with ManagedBy only — never a single connector's name.
    """
    s3 = session.client("s3")
    existed, verifiable_presence = _bucket_status(s3, bucket)

    if existed:
        raw_tags, tags_readable = _get_bucket_tags(s3, bucket)
        ownership = classify_ownership(
            raw_tags, None, verifiable=tags_readable and tags_enabled
        )
        if not ownership.safe_to_mutate and not adopt_existing:
            raise AwsError(
                describe_conflict(
                    resource_kind="S3 certificate bucket",
                    identifier=bucket,
                    ownership=ownership,
                    connector_name=connector_name,
                    rename_hint="set cert_s3_bucket in config to a bucket you own",
                )
                + "\n\nThis bucket would receive a PKCS#12 file containing the "
                "connector's private key."
            )
        if not ownership.safe_to_mutate:
            ownership = Ownership.UNMANAGED  # adopted deliberately
    else:
        if not verifiable_presence:
            raise AwsError(
                f"Cannot determine whether S3 bucket {bucket!r} exists: "
                f"HeadBucket was denied. A bucket with this name may exist in "
                f"another account. Grant s3:ListBucket on it, or set "
                f"cert_s3_bucket in config to a bucket you own."
            )
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket)
            else:
                s3.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
        except Exception as exc:
            raise AwsError(
                f"Failed to create S3 bucket {bucket!r} in {region}: {exc}. "
                "Bucket names are globally unique — try a more specific name."
            ) from exc
        ownership = Ownership.CREATED

    _harden_cert_bucket(s3, bucket, allow_unhardened=allow_unhardened)

    tagged = False
    if tags_enabled and ownership is Ownership.CREATED:
        tagged = _tag_bucket(s3, bucket, extra_tags)

    return ProvisionedResource(arn=bucket, ownership=ownership, tagged=tagged)


def _harden_cert_bucket(s3: Any, bucket: str, *, allow_unhardened: bool) -> None:
    """Apply public-access-block + default SSE, or refuse to use the bucket."""
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
    except (ClientError, BotoCoreError) as exc:
        if allow_unhardened:
            print(
                f"  WARNING: could not apply hardening to {bucket!r}: {exc}\n"
                f"  Continuing because --allow-unhardened-cert-bucket was passed. "
                f"Confirm public access is blocked and default encryption is on.",
                file=sys.stderr,
            )
            return
        raise AwsError(
            f"Could not apply security hardening to S3 bucket {bucket!r}: {exc}\n\n"
            f"This bucket is about to receive a PKCS#12 file containing the "
            f"connector's private key, so it is not used unless public access "
            f"is blocked and default encryption is enabled.\n\n"
            f"Grant the caller s3:PutBucketPublicAccessBlock and "
            f"s3:PutBucketEncryption on this bucket, or — if equivalent "
            f"controls are already enforced another way (SCP, bucket policy, "
            f"Config rule) — re-run with --allow-unhardened-cert-bucket."
        ) from exc


def _bucket_status(s3: Any, bucket: str) -> tuple[bool, bool]:
    """Return (exists, verifiable).

    HeadBucket answers three different questions with two outcomes, so the
    error code matters: 404 means genuinely absent, 403 means the bucket
    exists but belongs to someone else. Collapsing 403 into "absent" sends
    the caller into CreateBucket, which then fails with a confusing
    BucketAlreadyExists — while the real problem is that another account
    holds the name. `verifiable` is False for that case so the caller can
    say so plainly.
    """
    try:
        s3.head_bucket(Bucket=bucket)
        return True, True
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in ("404", "NoSuchBucket") or status == 404:
            return False, True
        if code in ("403", "AccessDenied") or status == 403:
            return False, False
        return False, False
    except Exception:
        return False, False


def _get_bucket_tags(s3: Any, bucket: str) -> tuple[Any, bool]:
    """Return (raw tag set, readable). A bucket with no tags reads as []."""
    try:
        resp = s3.get_bucket_tagging(Bucket=bucket)
        return resp.get("TagSet", []), True
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code == "NoSuchTagSet":
            return [], True
        return None, False
    except Exception:
        return None, False


def _tag_bucket(s3: Any, bucket: str, extra_tags: dict | None = None) -> bool:
    """Tag the bucket with ManagedBy. Returns whether tagging succeeded."""
    try:
        s3.put_bucket_tagging(
            Bucket=bucket,
            Tagging={"TagSet": build_tag_list(None, extra_tags)},
        )
        return True
    except Exception as exc:
        print(
            f"  WARNING: could not tag bucket {bucket!r}: {exc}\n"
            f"  Ownership tracking is degraded; a later run may refuse to "
            f"reuse this bucket without --adopt-existing-resources.",
            file=sys.stderr,
        )
        return False


# --- S3 certificate upload ---------------------------------------------------


def upload_certificate_to_s3(
    *,
    session: Any,
    bucket: str,
    key: str,
    pkcs12_bytes: bytes,
    connector_name: str | None = None,
    tags_enabled: bool = True,
    kms_key_arn: str | None = None,
    extra_tags: dict | None = None,
) -> str:
    """Upload the .p12 bundle to S3 and return its s3:// URI.

    Defaults to SSE-S3 (AES256), which costs nothing. Passing `kms_key_arn`
    switches to SSE-KMS with a customer-managed key, which adds a key-policy
    gate on top of the IAM check — worth it when the private key needs a
    second authorization boundary, but it is opt-in because a CMK carries a
    monthly charge and the KB role then also needs kms:Decrypt.
    """
    s3 = session.client("s3")
    params: dict = {
        "Bucket": bucket,
        "Key": key,
        "Body": pkcs12_bytes,
        "ContentType": "application/x-pkcs12",
    }
    if kms_key_arn:
        params["ServerSideEncryption"] = "aws:kms"
        params["SSEKMSKeyId"] = kms_key_arn
    else:
        params["ServerSideEncryption"] = "AES256"
    if tags_enabled:
        params["Tagging"] = build_tag_query_string(connector_name, extra_tags)

    try:
        s3.put_object(**params)
    except Exception as exc:
        if tags_enabled and is_tagging_access_error(exc):
            # s3:PutObjectTagging missing — the object matters more than the
            # tag, so retry without it and say so.
            params.pop("Tagging", None)
            try:
                s3.put_object(**params)
                print(
                    f"  WARNING: uploaded certificate without tags "
                    f"(s3:PutObjectTagging denied): {exc}",
                    file=sys.stderr,
                )
                return f"s3://{bucket}/{key}"
            except Exception as retry_exc:  # pragma: no cover - defensive
                raise AwsError(
                    f"Failed to upload certificate to s3://{bucket}/{key}: {retry_exc}"
                ) from retry_exc
        raise AwsError(
            f"Failed to upload certificate to s3://{bucket}/{key}: {exc}"
        ) from exc
    return f"s3://{bucket}/{key}"


# --- Secrets Manager ---------------------------------------------------------


def put_secret(
    *,
    session: Any,
    name: str,
    body: dict,
    description: str = "",
    connector_name: str | None = None,
    tags_enabled: bool = True,
    adopt_existing: bool = False,
    kms_key_arn: str | None = None,
    extra_tags: dict | None = None,
    created_untagged: bool = False,
) -> ProvisionedResource:
    """Create or update a Secrets Manager secret; return it with its ownership.

    Create-or-update is deliberate — re-running setup should refresh rotated
    credentials in place. But "a secret already has the name I derived" is not
    the same as "I own that secret", and overwriting a stranger's secret value
    silently breaks whatever consumes it. So an existing secret is only
    updated when its tags prove this tool created it for this connector.

    `kms_key_arn` is optional. Without it the secret uses the AWS-managed
    `aws/secretsmanager` key, which is free and needs no key administration —
    the tradeoff being that any principal in the account holding
    secretsmanager:GetSecretValue can read the connector's source-system
    credentials. A customer-managed key adds a second gate via its key policy;
    if you set one, the KB service role also needs kms:Decrypt (see
    build_inline_policy).
    """
    sm = session.client("secretsmanager")
    serialized = json.dumps(body)

    existing_arn, ownership = _classify_secret(
        sm, name, connector_name, tags_enabled=tags_enabled
    )
    from_state = _reclaim_untagged(ownership, created_untagged)
    if from_state:
        ownership = Ownership.OURS

    if existing_arn:
        if not ownership.safe_to_mutate and not adopt_existing:
            raise AwsError(
                describe_conflict(
                    resource_kind="Secrets Manager secret",
                    identifier=name,
                    ownership=ownership,
                    connector_name=connector_name,
                    rename_hint="pass --secret-name with a distinct name",
                )
                + "\n\nOverwriting it would replace whatever credentials it "
                "currently holds."
            )
        try:
            resp = sm.update_secret(SecretId=existing_arn, SecretString=serialized)
        except Exception as exc:
            raise AwsError(f"Failed to update secret {name!r}: {exc}") from exc
        return ProvisionedResource(
            arn=resp.get("ARN", existing_arn),
            ownership=ownership if ownership.safe_to_mutate else Ownership.UNMANAGED,
            # See ensure_kb_role: when ownership came from state the tag really
            # is absent, so don't report it as tagged.
            tagged=tags_enabled and ownership.safe_to_mutate and not from_state,
        )

    params: dict = {
        "Name": name,
        "Description": description
        or "KB connector credentials (managed by kb-connector)",
        "SecretString": serialized,
    }
    if kms_key_arn:
        params["KmsKeyId"] = kms_key_arn
    if tags_enabled:
        params["Tags"] = build_tag_list(connector_name, extra_tags)

    try:
        resp = sm.create_secret(**params)
        return ProvisionedResource(
            arn=resp["ARN"], ownership=Ownership.CREATED, tagged=tags_enabled
        )
    except sm.exceptions.ResourceExistsException as exc:
        # We reach here only when DescribeSecret could not confirm the secret
        # (typically because it was denied), so ownership is unknown and the
        # value must not be overwritten on a guess.
        if adopt_existing:
            try:
                resp = sm.update_secret(SecretId=name, SecretString=serialized)
            except Exception as retry_exc:
                raise AwsError(
                    f"Failed to update existing secret {name!r}: {retry_exc}"
                ) from retry_exc
            return ProvisionedResource(
                arn=resp.get("ARN", name), ownership=Ownership.UNMANAGED, tagged=False
            )
        raise AwsError(
            f"Secrets Manager secret {name!r} already exists, but its ownership "
            f"could not be verified — DescribeSecret did not succeed, so the "
            f"tool cannot tell whether it created this secret.\n\n"
            f"Grant the caller secretsmanager:DescribeSecret on it to enable "
            f"the ownership check, pass --secret-name with a distinct name, or "
            f"re-run with --adopt-existing-resources to overwrite it "
            f"deliberately."
        ) from exc
    except Exception as exc:
        if tags_enabled and is_tagging_access_error(exc):
            params.pop("Tags", None)
            try:
                resp = sm.create_secret(**params)
                print(
                    f"  WARNING: created secret without tags "
                    f"(secretsmanager:TagResource denied): {exc}\n"
                    f"  Ownership tracking is degraded for this secret.",
                    file=sys.stderr,
                )
                return ProvisionedResource(
                    arn=resp["ARN"], ownership=Ownership.CREATED, tagged=False
                )
            except Exception as retry_exc:
                raise AwsError(
                    f"Failed to write secret {name!r}: {retry_exc}"
                ) from retry_exc
        raise AwsError(f"Failed to write secret {name!r}: {exc}") from exc


def _classify_secret(
    sm: Any, name: str, connector_name: str | None, *, tags_enabled: bool
) -> tuple[str | None, Ownership]:
    """Return (existing ARN or None, ownership verdict) for a secret name."""
    try:
        resp = sm.describe_secret(SecretId=name)
    except Exception as exc:
        # ResourceNotFound is the common, expected path on a fresh setup.
        if "ResourceNotFound" in type(exc).__name__ or "ResourceNotFound" in str(exc):
            return None, Ownership.CREATED
        # Anything else (including AccessDenied on DescribeSecret) means we
        # cannot confirm ownership. Report it as unverifiable rather than
        # assuming the secret is absent and blindly creating/overwriting.
        return None, Ownership.UNVERIFIABLE

    arn = resp.get("ARN") or name
    ownership = classify_ownership(
        resp.get("Tags", []), connector_name, verifiable=tags_enabled
    )
    return arn, ownership


def get_secret_value(*, session: Any, secret_id: str) -> dict:
    """Retrieve and parse a secret's JSON value."""
    sm = session.client("secretsmanager")
    try:
        resp = sm.get_secret_value(SecretId=secret_id)
        parsed = json.loads(resp["SecretString"])
    except Exception as exc:
        raise AwsError(f"Failed to read secret {secret_id!r}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AwsError(
            f"Secret {secret_id!r} decoded to {type(parsed).__name__}, "
            "expected a JSON object."
        )
    return parsed


# --- IAM role ----------------------------------------------------------------


def build_trust_policy(*, account_id: str, region: str) -> dict:
    """Trust policy matching the console-created managed-KB role."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustPolicyStatement",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/*"
                        )
                    },
                },
            }
        ],
    }


def build_inline_policy(
    *,
    account_id: str,
    region: str,
    secret_arn: str | None,
    cert_bucket: str | None,
    cert_key: str | None,
    cert_key_prefix: str | None = None,
    kms_key_arn: str | None = None,
) -> dict:
    """Inline permissions policy mirroring the console role.

    Includes S3 statements only for cert mode, SecretsManager only when
    a secret is needed. A NO_AUTH web crawler needs neither.

    `kms_key_arn` adds kms:Decrypt on that key. This is required, not
    optional: when the secret or the certificate object is encrypted with a
    customer-managed key, the KB service role cannot read either one without
    it, and the failure surfaces at crawl time as an opaque AccessDenied
    rather than at setup time.
    """
    statements: list[dict] = [
        {
            "Sid": "CloudWatchWritePermissionStatement",
            "Effect": "Allow",
            "Action": ["cloudwatch:PutMetricData"],
            "Resource": ["*"],
            "Condition": {"StringEquals": {"cloudwatch:namespace": _CW_NAMESPACE}},
        },
    ]
    if secret_arn:
        statements.append(
            {
                "Sid": "SecretsManagerGetStatement",
                "Effect": "Allow",
                # The KB service role is a crawl-time *reader* of the connector
                # secret; it never writes it. Keeping this to GetSecretValue
                # mirrors the least-privilege role the Bedrock console creates.
                "Action": [
                    "secretsmanager:GetSecretValue",
                ],
                "Resource": [secret_arn],
            }
        )

    if cert_bucket and (cert_key or cert_key_prefix):
        bucket_arn = f"arn:aws:s3:::{cert_bucket}"
        if cert_key_prefix:
            normalized = cert_key_prefix.strip("/")
            list_condition = {
                "StringEquals": {"aws:ResourceAccount": [account_id]},
                "StringLike": {"s3:prefix": [f"{normalized}/*"]},
            }
            get_resources = [bucket_arn, f"{bucket_arn}/{normalized}/*"]
        else:
            list_condition = {
                "StringEquals": {"aws:ResourceAccount": [account_id]},
            }
            get_resources = [
                bucket_arn,
                f"{bucket_arn}/{cert_key}",
                f"{bucket_arn}/{cert_key}.metadata.json",
            ]

        statements.append(
            {
                "Sid": "S3ListBucketStatement",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [bucket_arn],
                "Condition": list_condition,
            }
        )
        statements.append(
            {
                "Sid": "S3GetObjectStatement",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": get_resources,
                "Condition": {"StringEquals": {"aws:ResourceAccount": [account_id]}},
            }
        )

    if kms_key_arn:
        # Scoped to the one key, and further narrowed by ViaService so the
        # grant only works when the request arrives through one of the three
        # services that legitimately touch the key — never as a standalone
        # Decrypt call.
        #
        # Bedrock is on that list because the key also encrypts the knowledge
        # base itself, and GenerateDataKey is required for it: Decrypt alone
        # covers reading an encrypted secret, but encrypting the knowledge base
        # needs the write side of the key too.
        statements.append(
            {
                "Sid": "KmsDecryptStatement",
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"],
                "Resource": [kms_key_arn],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": [
                            f"secretsmanager.{region}.amazonaws.com",
                            f"s3.{region}.amazonaws.com",
                            f"bedrock.{region}.amazonaws.com",
                        ]
                    }
                },
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


# Every inline policy name this tool authors on a KB role. Teardown removes
# exactly these and refuses to touch anything else, so this is the single
# source of truth for "did we write this policy?".
#
# It is an exact-name set rather than a `kb-connector*` prefix on purpose: a
# prefix would also claim policies the tool never wrote — another connector's
# policy on a shared role, or an operator's own `kb-connector-audit` — and
# teardown would delete them. A new put_role_policy call site must add its name
# here; test_tool_policy_names_cover_every_authored_policy enforces that for
# the defaults.
TOOL_INLINE_POLICY_NAMES = frozenset({
    "kb-connector-access",               # ensure_kb_role
    "kb-connector-supplemental-access",  # _attach_supplemental_access_policy
    "kb-connector-s3-content-access",    # cli/setup.py, S3 content sources
})


def ensure_kb_role(
    *,
    session: Any,
    role_name: str,
    account_id: str,
    region: str,
    secret_arn: str | None,
    cert_bucket: str | None,
    cert_key: str | None,
    cert_key_prefix: str | None = None,
    inline_policy_name: str = "kb-connector-access",
    kms_key_arn: str | None = None,
    connector_name: str | None = None,
    tags_enabled: bool = True,
    adopt_existing: bool = False,
    extra_tags: dict | None = None,
    created_untagged: bool = False,
) -> ProvisionedResource:
    """Create or update the KB service role; return it with its ownership.

    Idempotent: creates the role if missing, then puts the inline permissions
    policy. When the role already exists, its trust policy is only rewritten
    after tags confirm this tool created it for this connector — replacing the
    trust policy of an unrelated role that happens to match the derived name
    (`kb-connector-<name>-role`) would hand `bedrock.amazonaws.com` the ability
    to assume a role it was never meant to, and silently break whatever the
    role was for.
    """
    iam = session.client("iam")
    trust = build_trust_policy(account_id=account_id, region=region)

    try:
        existing = iam.get_role(RoleName=role_name)
        role_arn = existing["Role"]["Arn"]
        raw_tags, tags_readable = _get_role_tags(iam, role_name, existing)
        ownership = classify_ownership(
            raw_tags, connector_name, verifiable=tags_readable and tags_enabled
        )
        from_state = _reclaim_untagged(ownership, created_untagged)
        if from_state:
            ownership = Ownership.OURS
        if not ownership.safe_to_mutate and not adopt_existing:
            raise AwsError(
                describe_conflict(
                    resource_kind="IAM role",
                    identifier=role_name,
                    ownership=ownership,
                    connector_name=connector_name,
                    rename_hint="pass --kb-role-name with a distinct name",
                )
                + "\n\nModifying it would replace its trust policy and add an "
                "inline policy."
            )
        if not ownership.safe_to_mutate:
            ownership = Ownership.UNMANAGED  # adopted deliberately
        iam.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=json.dumps(trust)
        )
        # `from_state` means the tag really is absent — ownership came from
        # state, not from the resource — so keep reporting it untagged instead
        # of letting state_marker flip to "tool" with nothing to back it up.
        tagged = tags_enabled and ownership.tool_created and not from_state
    except iam.exceptions.NoSuchEntityException:
        role_arn, tagged = _create_kb_role(
            iam,
            role_name=role_name,
            trust=trust,
            connector_name=connector_name,
            tags_enabled=tags_enabled,
            extra_tags=extra_tags,
        )
        ownership = Ownership.CREATED
    except AwsError:
        raise
    except Exception as exc:
        raise AwsError(f"Failed to ensure IAM role {role_name!r}: {exc}") from exc

    policy = build_inline_policy(
        account_id=account_id,
        region=region,
        secret_arn=secret_arn,
        cert_bucket=cert_bucket,
        cert_key=cert_key,
        cert_key_prefix=cert_key_prefix,
        kms_key_arn=kms_key_arn,
    )
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=inline_policy_name,
            PolicyDocument=json.dumps(policy),
        )
    except Exception as exc:
        raise AwsError(
            f"Failed to attach inline policy to role {role_name!r}: {exc}"
        ) from exc

    return ProvisionedResource(arn=role_arn, ownership=ownership, tagged=tagged)


def _create_kb_role(
    iam: Any,
    *,
    role_name: str,
    trust: dict,
    connector_name: str | None,
    tags_enabled: bool,
    extra_tags: dict | None = None,
) -> tuple[str, bool]:
    """Create the role, degrading to untagged if iam:TagRole is denied."""
    params: dict = {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": json.dumps(trust),
        "Description": (
            "Amazon Bedrock Managed Knowledge Base service role "
            "(created by kb-connector)."
        ),
        "MaxSessionDuration": 3600,
    }
    if tags_enabled:
        params["Tags"] = build_tag_list(connector_name, extra_tags)

    try:
        created = iam.create_role(**params)
        return created["Role"]["Arn"], tags_enabled
    except Exception as exc:
        if tags_enabled and is_tagging_access_error(exc):
            # CreateRole with Tags also requires iam:TagRole. Prefer a working
            # role over a tagged one, but be explicit that ownership tracking
            # is now degraded for this resource.
            params.pop("Tags", None)
            try:
                created = iam.create_role(**params)
                print(
                    f"  WARNING: created role {role_name!r} without tags "
                    f"(iam:TagRole denied): {exc}\n"
                    f"  Ownership tracking is degraded; a later run may refuse "
                    f"to reuse this role without --adopt-existing-resources.",
                    file=sys.stderr,
                )
                return created["Role"]["Arn"], False
            except Exception as retry_exc:
                raise AwsError(
                    f"Failed to create IAM role {role_name!r}: {retry_exc}"
                ) from retry_exc
        raise AwsError(f"Failed to create IAM role {role_name!r}: {exc}") from exc


def _get_role_tags(iam: Any, role_name: str, get_role_resp: dict) -> tuple[Any, bool]:
    """Return (raw tags, readable) for a role.

    GetRole already includes Tags for most callers; list_role_tags is the
    fallback for paginated or trimmed responses.
    """
    role = get_role_resp.get("Role", {})
    if "Tags" in role:
        return role.get("Tags", []), True
    try:
        resp = iam.list_role_tags(RoleName=role_name)
        return resp.get("Tags", []), True
    except Exception:
        return None, False


# --- Read-only ownership preflight -------------------------------------------


def preflight_ownership(
    *,
    session: Any,
    connector_name: str | None,
    tags_enabled: bool = True,
    cert_bucket: str | None = None,
    secret_name: str | None = None,
    role_name: str | None = None,
) -> list[str]:
    """Classify what setup would modify, changing nothing. Returns conflicts.

    The ensure_* functions each refuse an unowned resource, but they run in the
    AWS stage — after the Microsoft stage has already registered an Entra app,
    granted tenant-wide admin consent, and replaced the app's certificate. A
    refusal at that point leaves live directory objects behind for a run that
    could never have succeeded.

    This composes the same read-only classification helpers those functions use
    (`_bucket_status`/`_get_bucket_tags`, `_classify_secret`, `_get_role_tags`),
    so a conflict reported here is the same conflict that would be raised later
    — just before anything has been created. Absent resources are not conflicts:
    they are the normal path.
    """
    conflicts: list[str] = []

    if cert_bucket:
        s3 = session.client("s3")
        existed, _ = _bucket_status(s3, cert_bucket)
        if existed:
            raw_tags, readable = _get_bucket_tags(s3, cert_bucket)
            ownership = classify_ownership(
                raw_tags, None, verifiable=readable and tags_enabled
            )
            if not ownership.safe_to_mutate:
                conflicts.append(
                    describe_conflict(
                        resource_kind="S3 certificate bucket",
                        identifier=cert_bucket,
                        ownership=ownership,
                        connector_name=connector_name,
                        rename_hint="set cert_s3_bucket in config to a bucket you own",
                    )
                )

    if secret_name:
        sm = session.client("secretsmanager")
        existing_arn, ownership = _classify_secret(
            sm, secret_name, connector_name, tags_enabled=tags_enabled
        )
        if existing_arn and not ownership.safe_to_mutate:
            conflicts.append(
                describe_conflict(
                    resource_kind="Secrets Manager secret",
                    identifier=secret_name,
                    ownership=ownership,
                    connector_name=connector_name,
                    rename_hint="pass --secret-name with a distinct name",
                )
            )

    if role_name:
        iam = session.client("iam")
        try:
            existing = iam.get_role(RoleName=role_name)
        except Exception:
            # Absent (NoSuchEntity) or unreadable. An unreadable role is not
            # reported here: ensure_kb_role classifies it authoritatively, and
            # guessing at this stage would block a run that would have worked.
            existing = None
        if existing:
            raw_tags, readable = _get_role_tags(iam, role_name, existing)
            ownership = classify_ownership(
                raw_tags, connector_name, verifiable=readable and tags_enabled
            )
            if not ownership.safe_to_mutate:
                conflicts.append(
                    describe_conflict(
                        resource_kind="IAM role",
                        identifier=role_name,
                        ownership=ownership,
                        connector_name=connector_name,
                        rename_hint="pass --kb-role-name with a distinct name",
                    )
                )

    return conflicts


# --- KB role extension (adding DS to existing KB) ----------------------------


def extend_kb_role_for_secret(
    *,
    session: Any,
    role_name: str,
    secret_arn: str,
    cert_bucket: str | None = None,
    cert_key: str | None = None,
    cert_key_prefix: str | None = None,
    account_id: str | None = None,
    region: str | None = None,
    kms_key_arn: str | None = None,
) -> dict:
    """Append a new secret ARN (and cert paths) to an existing KB role.

    Used when attaching a new data source to an existing KB whose role
    doesn't yet have access to the new connector's secret/cert.
    Returns a summary dict of what was changed.

    This path intentionally modifies a role the tool does not own — that is
    the point of attaching to an existing KB — so it only ever *adds*
    resources to statements it recognizes by Sid, never removes or widens
    actions. When no statement is recognizable, it attaches a separate
    clearly-named policy instead of editing someone else's statement.
    """
    iam = session.client("iam")
    try:
        names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    except Exception as exc:
        raise AwsError(
            f"Could not list inline policies on role {role_name!r}: {exc}"
        ) from exc

    # B105 reads "secret_added" as a credential name; the value is a bool flag.
    summary: dict = {  # nosec B105
        "role_name": role_name,
        "policies_updated": [],
        "secret_added": False,
        "cert_added": False,
    }

    for policy_name in names:
        try:
            resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        except Exception as exc:
            raise AwsError(
                f"Could not read inline policy {policy_name!r}: {exc}"
            ) from exc

        doc = resp.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        statements = doc.get("Statement")
        if not isinstance(statements, list):
            continue

        changed_secret = _append_resource_to_statement(
            statements, sid="SecretsManagerGetStatement",
            action="secretsmanager:GetSecretValue", resource=secret_arn,
        )
        changed_cert = False
        if cert_bucket and (cert_key or cert_key_prefix):
            bucket_arn = f"arn:aws:s3:::{cert_bucket}"
            if cert_key_prefix:
                normalized = cert_key_prefix.strip("/")
                resources = [bucket_arn, f"{bucket_arn}/{normalized}/*"]
            else:
                resources = [
                    bucket_arn,
                    f"{bucket_arn}/{cert_key}",
                    f"{bucket_arn}/{cert_key}.metadata.json",
                ]
            for r in resources:
                if _append_resource_to_statement(
                    statements, sid="S3GetObjectStatement",
                    action="s3:GetObject", resource=r,
                ):
                    changed_cert = True

        if changed_secret or changed_cert:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(doc),
            )
            summary["policies_updated"].append(policy_name)
            if changed_secret:
                summary["secret_added"] = True
            if changed_cert:
                summary["cert_added"] = True

    # Nothing matched by Sid — e.g. a hand-rolled role, or one the console
    # created with a different statement layout. Rather than guessing which
    # existing statement to widen, attach a separate, clearly-named policy
    # holding exactly the grants this connector needs. An operator reviewing
    # the role can see precisely what the tool added and delete just that.
    resolved_account = account_id or _account_from_arn(secret_arn)
    resolved_region = region or _region_from_arn(secret_arn)

    if (
        not summary["secret_added"]
        and resolved_account
        and resolved_region
        and not (
            cert_bucket and (cert_key or cert_key_prefix) and summary["cert_added"]
        )
    ):
        added_policy = _attach_supplemental_access_policy(
            iam,
            role_name=role_name,
            account_id=resolved_account,
            region=resolved_region,
            secret_arn=secret_arn if not summary["secret_added"] else None,
            cert_bucket=cert_bucket if not summary["cert_added"] else None,
            cert_key=cert_key if not summary["cert_added"] else None,
            cert_key_prefix=cert_key_prefix if not summary["cert_added"] else None,
            kms_key_arn=kms_key_arn,
        )
        if added_policy:
            summary["policies_updated"].append(added_policy)
            if secret_arn and not summary["secret_added"]:
                summary["secret_added"] = True
            if cert_bucket and not summary["cert_added"]:
                summary["cert_added"] = True

    return summary


def _account_from_arn(arn: str | None) -> str | None:
    """Pull the account id out of an ARN (field 4), or None if unparseable."""
    if not arn:
        return None
    parts = arn.split(":")
    return parts[4] if len(parts) > 5 and parts[4] else None


def _region_from_arn(arn: str | None) -> str | None:
    """Pull the region out of an ARN (field 3), or None if unparseable."""
    if not arn:
        return None
    parts = arn.split(":")
    return parts[3] if len(parts) > 4 and parts[3] else None


def _attach_supplemental_access_policy(
    iam: Any,
    *,
    role_name: str,
    account_id: str,
    region: str,
    secret_arn: str | None,
    cert_bucket: str | None,
    cert_key: str | None,
    cert_key_prefix: str | None,
    kms_key_arn: str | None,
    policy_name: str = "kb-connector-supplemental-access",
) -> str | None:
    """Attach a self-contained policy granting this connector's credential reads.

    Used when an existing KB role has no statement the tool recognizes. Returns
    the policy name on success, or None when there was nothing to grant.
    """
    if not secret_arn and not cert_bucket:
        return None

    policy = build_inline_policy(
        account_id=account_id,
        region=region,
        secret_arn=secret_arn,
        cert_bucket=cert_bucket,
        cert_key=cert_key,
        cert_key_prefix=cert_key_prefix,
        kms_key_arn=kms_key_arn,
    )
    # build_inline_policy always emits the CloudWatch statement; the existing
    # role already has metric permissions, so drop it to keep this policy to
    # only what is genuinely missing.
    policy["Statement"] = [
        s
        for s in policy.get("Statement", [])
        if s.get("Sid") != "CloudWatchWritePermissionStatement"
    ]
    if not policy["Statement"]:
        return None

    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
        )
    except Exception as exc:
        raise AwsError(
            f"Could not attach supplemental access policy to role "
            f"{role_name!r}: {exc}"
        ) from exc
    return policy_name


def _append_resource_to_statement(
    statements: list, *, sid: str, action: str, resource: str
) -> bool:
    """Append a resource ARN to an existing statement; idempotent."""
    target = _find_statement(statements, sid=sid, action=action)
    if target is None:
        return False
    existing = target.get("Resource")
    if isinstance(existing, str):
        existing = [existing]
    elif not isinstance(existing, list):
        return False
    if resource in existing or "*" in existing:
        return False
    existing.append(resource)
    target["Resource"] = existing
    return True


def _find_statement(statements: list, *, sid: str, action: str) -> dict | None:
    """Locate an Allow statement by Sid.

    Matching is Sid-only and deliberately narrow. Falling back to matching on
    Action would mean that on a role whose statements use different Sids, the
    extension could append a resource ARN to whatever unrelated statement
    happened to mention `secretsmanager:GetSecretValue` or `s3:GetObject` —
    widening a policy the tool did not author. When no Sid matches, the caller
    adds its own statement instead (see `extend_kb_role_for_secret`), which is
    both safer and easier to audit.

    `action` is retained for signature compatibility with callers and is used
    only to sanity-check that a Sid-matched statement really covers the action.
    """
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Sid") != sid:
            continue
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        actions = stmt.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(actions, list) and action not in actions:
            continue
        return stmt
    return None
