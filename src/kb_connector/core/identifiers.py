"""Validators for AWS identifiers that arrive from local files.

The state file and handoff documents are plain JSON the tool reads back and
acts on. TB-1 treats them as trusted for endpoint URLs, resource names and API
payloads — but some of these values become the *target* of a destructive call:
teardown force-deletes the secret named by `secret_arn`, deletes the S3 object
named by `cert_s3_bucket`/`cert_s3_key`, and deletes the role named by
`kb_role_arn`. A value that never came from a real provisioning run should not
reach those calls just because it parsed as JSON.

These validators are deliberately shape-only. They cannot tell whether the
caller *should* own a resource — that is what the ownership tags in
core/tagging.py are for. What they do is refuse a value that provisioning
could not have produced, so a hand-edited or attacker-supplied file fails with
a clear message instead of silently retargeting an AWS API call.

Each raises ConnectorError (or a subclass supplied by the caller) with a
message naming the offending field, since the operator's next step is to fix
or remove the entry.
"""

from __future__ import annotations

import re

from kb_connector.core.errors import ConnectorError

# ARN grammar: arn:partition:service:region:account:resource
# Partition is aws | aws-cn | aws-us-gov. Region and account may be empty for
# global services (IAM), so they are validated per-service below.
_ARN_RE = re.compile(
    r"^arn:(aws|aws-cn|aws-us-gov):"      # partition
    r"([a-z0-9-]{2,63}):"                  # service
    r"([a-z0-9-]{0,30}):"                  # region (empty for global)
    r"(\d{12}|):"                          # account (empty for some services)
    r"(.+)$"                               # resource
)

# S3 bucket naming rules, the restrictive subset: lowercase alphanumerics,
# hyphens and dots, 3-63 chars, must start and end alphanumeric. Excludes the
# legacy uppercase/underscore forms, which cannot be created today.
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

# AWS region: two-or-more lowercase letter groups then a digit (us-east-1,
# ap-southeast-2, us-gov-west-1, cn-north-1).
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")

# Bedrock knowledge base / data source ids are short opaque alphanumerics.
_BEDROCK_ID_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")

# Entra tenant / application ids are GUIDs.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _fail(field: str, value: object, expected: str) -> None:
    raise ConnectorError(
        f"{field} is {value!r}, which is not {expected}. This value came from "
        f"a local state or handoff file rather than from AWS, and it is about "
        f"to be used against your account, so it is refused rather than "
        f"guessed at. Fix or remove the entry, or act on the resource directly."
    )


def validate_arn(value: object, *, field: str, service: str) -> str:
    """Require a well-formed ARN for `service`. Returns it stripped.

    `service` is checked exactly: a Secrets Manager delete must not accept an
    ARN for some other service that happens to parse.
    """
    raw = value.strip() if isinstance(value, str) else ""
    if not raw:
        _fail(field, value, "a non-empty ARN")
    match = _ARN_RE.match(raw)
    if match is None:
        _fail(field, value, f"a well-formed {service} ARN")
    elif match.group(2) != service:
        _fail(field, value, f"an ARN for service {service!r}")
    return raw


def validate_secret_arn(value: object, *, field: str = "secret_arn") -> str:
    """Require a Secrets Manager secret ARN.

    Teardown deletes this with ForceDeleteWithoutRecovery, so there is no
    recovery window to fall back on if the target is wrong.
    """
    raw = validate_arn(value, field=field, service="secretsmanager")
    resource = raw.split(":", 5)[5]
    if not resource.startswith("secret:") or resource == "secret:":
        _fail(field, value, "a Secrets Manager ARN naming a secret")
    return raw


def validate_s3_bucket(value: object, *, field: str = "cert_s3_bucket") -> str:
    """Require a syntactically valid S3 bucket name."""
    raw = value.strip() if isinstance(value, str) else ""
    if not _S3_BUCKET_RE.match(raw) or ".." in raw:
        _fail(field, value, "a valid S3 bucket name")
    return raw


def validate_s3_key(value: object, *, field: str = "cert_s3_key") -> str:
    """Require a plausible S3 object key.

    S3 keys are near-arbitrary bytes, so this only rejects the shapes that
    indicate the value did not come from a provisioning run: empty, absolute,
    or containing a `..` traversal segment. The point is to catch a corrupted
    or crafted entry, not to constrain legitimate keys.
    """
    raw = value if isinstance(value, str) else ""
    if not raw or raw.startswith("/") or raw.endswith("/"):
        _fail(field, value, "a non-empty relative S3 key")
    if ".." in raw.split("/"):
        _fail(field, value, "an S3 key without a '..' segment")
    return raw


def validate_region(value: object, *, field: str = "region") -> str:
    """Require an AWS region identifier."""
    raw = value.strip() if isinstance(value, str) else ""
    if not _REGION_RE.match(raw):
        _fail(field, value, "an AWS region such as 'us-east-1'")
    return raw


def validate_bedrock_id(value: object, *, field: str) -> str:
    """Require a Bedrock knowledge base or data source id."""
    raw = value.strip() if isinstance(value, str) else ""
    if not _BEDROCK_ID_RE.match(raw):
        _fail(field, value, "a Bedrock identifier (6-32 alphanumerics)")
    return raw


def validate_guid(value: object, *, field: str) -> str:
    """Require a GUID, as used for Entra tenant and application ids."""
    raw = value.strip() if isinstance(value, str) else ""
    if not _GUID_RE.match(raw):
        _fail(field, value, "a GUID")
    return raw


# --- Config values that become AWS resource names -----------------------------

# Safe for an IAM role name, a Secrets Manager name segment and an S3 key
# segment simultaneously. Notably excludes `*` and `?`, which are IAM policy
# wildcards, and `/`, which would add an unintended path segment.
_NAME_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_NAME_COMPONENT_RULE = (
    "1-64 characters, starting with a letter or digit, and otherwise limited to "
    "letters, digits, dot, underscore and hyphen"
)


def validate_name_component(value: object, *, field: str) -> str:
    """Require a value safe to interpolate into a derived AWS resource name.

    The connector name and `resource_prefix` are interpolated straight into an
    IAM role name, a Secrets Manager secret name, an S3 object key and a
    knowledge base name — and those names are then interpolated into the
    `Resource` ARNs of the inline policy built by
    provisioning.build_inline_policy.

    That last step is why this is a security check and not just input hygiene:
    `*` and `?` are IAM policy wildcards, so a connector named `x*` produces an
    S3 object ARN of `arn:aws:s3:::bucket/kb-connector/x*.p12` and grants the KB
    role read access to every object matching that pattern rather than the one
    certificate it needs. Characters IAM rejects outright (spaces, most
    punctuation, non-ASCII) are also refused here so the failure is a clear
    local message instead of a late, partially-provisioned run: Secrets Manager
    and S3 accept names that IAM will not, so the secret and certificate can be
    created before the role fails.
    """
    raw = value.strip() if isinstance(value, str) else ""
    if not _NAME_COMPONENT_RE.match(raw):
        raise ConnectorError(
            f"{field} is {value!r}, which cannot be used to derive AWS resource "
            f"names. Expected {_NAME_COMPONENT_RULE}.\n\n"
            f"These names are interpolated into IAM policy Resource ARNs, where "
            f"'*' and '?' act as wildcards and would widen the knowledge base "
            f"role's access beyond the resources this connector owns."
        )
    return raw


def validate_s3_key_prefix(value: object, *, field: str) -> str:
    """Require an S3 key prefix safe to interpolate into a policy Resource ARN.

    Unlike a name component this may contain `/`, since that is what makes it a
    prefix. Wildcards are still refused: the prefix lands in both the
    `s3:prefix` condition and the object ARN of `S3GetObjectStatement`.
    """
    raw = value.strip() if isinstance(value, str) else ""
    if not raw:
        raise ConnectorError(f"{field} is empty; omit it instead of setting a blank value.")
    if any(ch in raw for ch in "*?"):
        raise ConnectorError(
            f"{field} is {value!r}, which contains an IAM policy wildcard "
            f"('*' or '?'). This prefix is interpolated into the S3 object ARN "
            f"granted to the knowledge base role, so a wildcard would widen "
            f"that grant beyond this connector's certificate."
        )
    segments = raw.strip("/").split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ConnectorError(
            f"{field} is {value!r}, which has an empty or relative path segment. "
            f"Expected a plain prefix such as 'kb-connector' or 'certs/prod'."
        )
    for seg in segments:
        if not _NAME_COMPONENT_RE.match(seg):
            raise ConnectorError(
                f"{field} is {value!r}; the segment {seg!r} is not usable. Each "
                f"segment must be {_NAME_COMPONENT_RULE}."
            )
    return raw
