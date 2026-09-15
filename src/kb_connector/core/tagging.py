"""Resource tagging and tag-verified adoption.

Why this exists: the tool derives resource names from the connector name
(`kb-connector-<name>-role`, `kb-connector/<name>-credentials`, ...). Those
names are predictable, and several accounts run this tool more than once —
multiple connectors, multiple operators, sometimes a shared sandbox account.
Without a way to tell "did I create this?" from "does this merely have the
name I wanted?", the create-or-update paths silently adopt whatever they
find: `ensure_kb_role` would overwrite a stranger's trust policy, `put_secret`
would overwrite a stranger's secret value, and `teardown` would later delete
both.

Tags are the ownership record. Every resource the tool creates carries:

    ManagedBy        = kb-connector     (this tool created it)
    KbConnectorName  = <connector name>        (which connector owns it)

Before touching anything that already exists, callers classify it:

    CREATED          we just created it now
    OURS             tagged for this tool *and* this connector — safe to update
    OTHER_CONNECTOR  this tool made it, but for a different connector — refuse
    UNMANAGED        no ownership tag — someone else's resource, refuse
    UNVERIFIABLE     we couldn't read the tags (missing permission, or
                     tagging disabled) — refuse, because absence of evidence
                     is not evidence of ownership

Only CREATED and OURS are safe to mutate. Everything else requires the
operator to opt in explicitly (`--adopt-existing-resources`), and adopted
resources are recorded in state as "external" so teardown leaves them alone.

Tagging degrades gracefully. `iam:CreateRole` with `Tags` also needs
`iam:TagRole`, and `secretsmanager:CreateSecret` with `Tags` needs
`secretsmanager:TagResource`. Callers that hit an access-denied on the tagging
portion retry untagged and warn, so a narrowly-scoped caller policy can still
run setup — it just loses ownership tracking, which downgrades later
classifications to UNVERIFIABLE.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

MANAGED_BY_KEY = "ManagedBy"
MANAGED_BY_VALUE = "kb-connector"
CONNECTOR_KEY = "KbConnectorName"

# Ownership is decided by matching the ManagedBy tag, which makes this value part
# of the tool's lasting contract with every account it runs in: a resource tagged
# with a value not in this set classifies as UNMANAGED, so the tool refuses to
# reuse resources it created itself and teardown stops reclaiming them.
#
# Reads therefore accept a set while writes emit exactly MANAGED_BY_VALUE. If the
# value ever changes, add the previous one here rather than replacing it — that
# keeps already-tagged resources recognizable instead of orphaning them.
_ACCEPTED_MANAGED_BY = frozenset({MANAGED_BY_VALUE})

# Operators may add their own tags, but not these two: they are the ownership
# record that the refusal logic and teardown rely on.
RESERVED_TAG_KEYS = frozenset({MANAGED_BY_KEY, CONNECTOR_KEY})

# AWS limits, enforced locally so a bad value fails before the API call.
_MAX_TAG_KEY_LEN = 128
_MAX_TAG_VALUE_LEN = 256


class Ownership(str, Enum):
    """How a resource relates to this tool and the current connector."""

    CREATED = "created"
    OURS = "ours"
    OTHER_CONNECTOR = "other-connector"
    UNMANAGED = "unmanaged"
    UNVERIFIABLE = "unverifiable"

    @property
    def safe_to_mutate(self) -> bool:
        """True when the tool may update this resource without an opt-in."""
        return self in (Ownership.CREATED, Ownership.OURS)

    @property
    def tool_created(self) -> bool:
        """True when this tool provisioned the resource (vs. adopted it)."""
        return self in (Ownership.CREATED, Ownership.OURS)


@dataclass(frozen=True)
class ProvisionedResource:
    """A resource the tool ensured, plus how it came to be.

    `ownership` drives two downstream decisions: whether it was safe to
    mutate, and whether `teardown` may delete it. `state_marker` is what
    lands in ConnectorState.created_resources.
    """

    arn: str
    ownership: Ownership
    tagged: bool = True

    @property
    def created(self) -> bool:
        return self.ownership is Ownership.CREATED

    @property
    def state_marker(self) -> str:
        """The ownership marker to persist for this resource.

        Three values rather than two. A resource this tool created but could
        not tag is still ours and teardown must still reclaim it, but the tag
        that would prove that on a later run is absent — so the distinction
        has to survive in state, or the next run reads the missing tag as
        someone else's resource and refuses to touch it.

        Mirrors OWNER_TOOL / OWNER_TOOL_UNTAGGED / OWNER_EXTERNAL in
        core.state, which this module does not import in order to keep tag
        classification free of any dependency on local state.
        """
        if not self.ownership.tool_created:
            return "external"
        return "tool" if self.tagged else "tool-untagged"


def validate_extra_tags(raw: Any) -> dict[str, str]:
    """Validate operator-supplied tags and return them normalized.

    Organizations commonly mandate tags (CostCenter, Owner, DataClassification)
    and enforce them with an SCP or tag policy, which would otherwise make the
    tool's create calls fail outright with no way to comply. Operators supply
    them via a `[tags]` table; these are merged into every resource the tool
    creates, alongside the ownership tags.

    Ownership keys are rejected rather than silently ignored: allowing an
    operator to set ManagedBy or KbConnectorName would let a config file forge
    the ownership record that T-02 and T-03 depend on.

    Raises ValueError with an actionable message. Callers surface it as a
    ConfigError so a bad table fails before any AWS call is made.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError('tags must be a table of key = "value" pairs.')

    out: dict[str, str] = {}
    for key, value in raw.items():
        k = str(key).strip()
        if not k:
            raise ValueError("tag keys cannot be empty.")
        if k.lower().startswith("aws:"):
            raise ValueError(
                f"tag key {k!r} uses the 'aws:' prefix, which AWS reserves."
            )
        if k in RESERVED_TAG_KEYS:
            raise ValueError(
                f"tag key {k!r} is reserved for ownership tracking; the tool "
                f"sets it itself. Choose a different key."
            )
        if len(k) > _MAX_TAG_KEY_LEN:
            raise ValueError(
                f"tag key {k!r} exceeds {_MAX_TAG_KEY_LEN} characters."
            )
        if isinstance(value, (dict, list)):
            raise ValueError(
                f"tag {k!r} must be a string, not {type(value).__name__}. "
                f"Nested tables are not supported."
            )
        v = "" if value is None else str(value)
        if len(v) > _MAX_TAG_VALUE_LEN:
            raise ValueError(
                f"tag {k!r} value exceeds {_MAX_TAG_VALUE_LEN} characters."
            )
        out[k] = v
    return out


def build_tag_dict(
    connector_name: str | None, extra: Any = None
) -> dict[str, str]:
    """Ownership tags as a flat mapping (Bedrock KB `tags`, S3 bucket tagging).

    Operator-supplied `extra` tags are applied first so the ownership keys
    overwrite them, never the other way around.
    """
    tags: dict[str, str] = dict(extra or {})
    tags[MANAGED_BY_KEY] = MANAGED_BY_VALUE
    if connector_name:
        tags[CONNECTOR_KEY] = connector_name
    return tags


def build_tag_list(
    connector_name: str | None, extra: Any = None
) -> list[dict[str, str]]:
    """Ownership tags in the [{"Key":..., "Value":...}] shape (IAM, Secrets Manager)."""
    return [
        {"Key": key, "Value": value}
        for key, value in build_tag_dict(connector_name, extra).items()
    ]


def build_tag_query_string(connector_name: str | None, extra: Any = None) -> str:
    """Ownership tags as the URL-encoded string S3 PutObject `Tagging` wants."""
    from urllib.parse import urlencode

    return urlencode(build_tag_dict(connector_name, extra))


def normalize_tags(raw: Any) -> dict[str, str]:
    """Coerce any AWS tag representation into a plain dict.

    Accepts the [{"Key":..,"Value":..}] list shape (IAM, Secrets Manager, S3
    TagSet) and the flat-mapping shape (Bedrock). Anything unrecognized
    yields an empty dict, which classifies as UNMANAGED rather than
    accidentally reading as ownership.
    """
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}


def classify_ownership(
    raw_tags: Any,
    connector_name: str | None,
    *,
    verifiable: bool = True,
) -> Ownership:
    """Classify an existing resource from its tags.

    `verifiable=False` means we could not read the tags at all (missing
    permission, or the resource predates tagging). That is reported as
    UNVERIFIABLE rather than UNMANAGED so the operator-facing message can
    explain the difference: one is "this belongs to someone else", the other
    is "I can't tell, and I won't guess".
    """
    if not verifiable:
        return Ownership.UNVERIFIABLE

    tags = normalize_tags(raw_tags)
    if tags.get(MANAGED_BY_KEY) not in _ACCEPTED_MANAGED_BY:
        return Ownership.UNMANAGED

    owner = tags.get(CONNECTOR_KEY)
    if connector_name and owner and owner != connector_name:
        return Ownership.OTHER_CONNECTOR
    return Ownership.OURS


def is_tagging_access_error(exc: Exception) -> bool:
    """True when an exception looks like a missing *tagging* permission.

    Used to decide whether to retry a create call without tags. Matches on
    the tagging-specific action names so a general AccessDenied on the
    create itself still surfaces as a real failure.
    """
    text = str(exc)
    if "AccessDenied" not in text and "not authorized" not in text:
        return False
    return any(
        action in text
        for action in ("TagRole", "TagResource", "PutObjectTagging", "PutBucketTagging", "Tagging")
    )


def describe_conflict(
    *,
    resource_kind: str,
    identifier: str,
    ownership: Ownership,
    connector_name: str | None,
    override_flag: str = "--adopt-existing-resources",
    rename_hint: str = "",
) -> str:
    """Build the operator-facing message for a refused adoption.

    The message has to answer three questions: what did I find, why won't
    you touch it, and what are my two ways forward (rename, or opt in).
    """
    if ownership is Ownership.OTHER_CONNECTOR:
        reason = (
            f"it is tagged {CONNECTOR_KEY}=<another connector>, so another "
            f"connector in this account owns it"
        )
    elif ownership is Ownership.UNMANAGED:
        reason = (
            f"it has no {MANAGED_BY_KEY}={MANAGED_BY_VALUE} tag, so this tool "
            f"did not create it"
        )
    else:  # UNVERIFIABLE
        reason = (
            "its tags could not be read, so ownership cannot be confirmed "
            "(grant the matching Get*Tag*/List*Tags permission, or re-run "
            "with tagging enabled)"
        )

    # Bound to a name rather than written as two adjacent literals inside the
    # list. Implicit concatenation across lines is indistinguishable from a
    # missing comma at a glance, and in a list of user-facing lines a missing
    # comma silently merges two of them.
    refusal = (
        "Refusing to modify it: overwriting a resource this tool does not own "
        "can break another connector or another team's workload."
    )
    lines = [
        f"{resource_kind} {identifier!r} already exists and {reason}.",
        "",
        refusal,
        "",
        "Choose one:",
    ]
    if rename_hint:
        lines.append(f"  • Use a different name: {rename_hint}")
    lines.append(
        f"  • Adopt it deliberately: re-run with {override_flag}. Adopted "
        f"resources are recorded as external and are never deleted by teardown."
    )
    if connector_name:
        lines.append(
            f"  • Or set a resource_prefix for connector {connector_name!r} in "
            f"config so its derived names don't collide."
        )
    return "\n".join(lines)
