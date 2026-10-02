"""Delete operations for the resources setup creates.

Each function deletes one resource and raises on failure. Identifiers come from
the state file, which is editable and can be populated from a handoff document,
so every destructive target is shape-checked before the call (T-24 in
THREAT-MODEL.md). Ownership decisions are made by the caller, not here.
"""

from __future__ import annotations

import re
import time
from typing import Any

from kb_connector.core.errors import ConnectorError
from kb_connector.core.identifiers import (
    validate_s3_bucket,
    validate_s3_key,
    validate_secret_arn,
)

TERMINAL_INGESTION_STATES = frozenset({"COMPLETE", "COMPLETED", "FAILED", "STOPPED"})

# IAM's RoleName charset and length limit, applied to reject a role name that
# state does not actually justify before it reaches DeleteRole.
_IAM_ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")


# --- Ingestion jobs ------------------------------------------------------------


def find_active_ingestion_job(target: Any, kb_id: str, ds_id: str) -> str | None:
    """Return the most recent non-terminal ingestion job id, or None.

    Only the five most recent jobs are read: running jobs sort to the top, and
    ListIngestionJobs does not filter by status. Raises if the list call fails.
    """
    resp = target.list_ingestion_jobs(kb_id, ds_id, max_results=5)
    for job in resp.get("ingestionJobSummaries", [])[:5]:
        status = (job.get("status") or "").upper()
        if status not in TERMINAL_INGESTION_STATES:
            job_id = job.get("ingestionJobId")
            # The caller passes this to StopIngestionJob, so a summary missing
            # its id is no better than finding no job at all.
            return job_id if isinstance(job_id, str) else None
    return None


def stop_and_wait(
    target: Any,
    kb_id: str,
    ds_id: str,
    job_id: str,
    *,
    timeout_seconds: int = 180,
    poll_interval_seconds: int = 10,
) -> str | None:
    """Stop an ingestion job and wait for it to reach a terminal state.

    Returns the terminal status, or None if the job is still stopping at the
    deadline or its status could not be read. StopIngestionJob is asynchronous:
    the job moves to STOPPING and reaches STOPPED on its own. Raises if the stop
    request itself fails.
    """
    target.stop_ingestion_job(kb_id, ds_id, job_id)
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            resp = target.get_ingestion_job(kb_id, ds_id, job_id)
        except Exception:  # noqa: BLE001 - an unreadable status ends the wait
            return None
        status = (resp.get("ingestionJob", {}).get("status") or "").upper()
        if status in TERMINAL_INGESTION_STATES:
            return status
        time.sleep(poll_interval_seconds)  # nosemgrep: arbitrary-sleep -- poll interval for ingestion stop
    return None


# --- AWS resources -------------------------------------------------------------


def delete_secret(session: Any, secret_arn: str) -> None:
    """Force-delete a Secrets Manager secret, with no recovery window.

    The secret holds credentials this tool minted for one connector and can mint
    again, so the 7-day default buys no recoverability worth having and blocks
    re-running setup under the same connector name. Because there is no recovery
    window, the target is checked to be a secret ARN first.
    """
    sm = session.client("secretsmanager")
    sm.delete_secret(
        SecretId=validate_secret_arn(secret_arn),
        ForceDeleteWithoutRecovery=True,
    )


def role_name_from_arn(role_arn: str) -> str:
    """Extract a role name from an IAM role ARN, or refuse.

    A full ARN is required rather than whatever a permissive split yields:
    trimming from a `:role/` marker would pass a bare string straight through,
    letting a state entry of "OrganizationAccountAccessRole" aim DeleteRole at
    that role. Handles role paths (`:role/some/path/Name` -> `Name`).
    """
    raw = (role_arn or "").strip()
    marker = ":role/"
    if not raw.startswith("arn:") or marker not in raw:
        raise ConnectorError(
            f"Tracked kb_role_arn {raw!r} is not an IAM role ARN, so teardown "
            f"cannot tell which role it names. Expected something like "
            f"arn:aws:iam::123456789012:role/kb-connector-<name>-role. Fix or "
            f"remove the entry in the state file, or delete the role manually."
        )
    name = raw.split(marker, 1)[1].rsplit("/", 1)[-1]
    if not _IAM_ROLE_NAME_RE.match(name):
        raise ConnectorError(
            f"Tracked kb_role_arn {raw!r} yields role name {name!r}, which is "
            f"not a valid IAM role name. Refusing to use it as a delete "
            f"target. Fix the state file, or delete the role manually."
        )
    return name


def delete_role(session: Any, role_arn: str) -> None:
    """Delete a KB service role the tool created.

    Every reason to refuse is checked before anything is removed. Inline
    policies have to go before DeleteRole, and deleting the recognized ones
    before discovering a reason to stop would leave the role in place with its
    permissions stripped. Three read-only refusals run first:

    * Managed policies attached: the role is used beyond this connector.
    * The role is in an instance profile: an EC2 workload depends on it.
    * Inline policies this tool did not author.

    Recognition is by exact name against TOOL_INLINE_POLICY_NAMES, not a
    `kb-connector` prefix, which would also match policies the tool never wrote.
    """
    from kb_connector.core.provisioning import TOOL_INLINE_POLICY_NAMES

    iam = session.client("iam")
    role_name = role_name_from_arn(role_arn)

    attached = iam.list_attached_role_policies(RoleName=role_name).get(
        "AttachedPolicies", []
    )
    if attached:
        names = ", ".join(p.get("PolicyName", "?") for p in attached)
        raise ConnectorError(
            f"IAM role {role_name!r} has managed policies attached ({names}), "
            f"so it is in use beyond this connector. Nothing was removed. "
            f"Detach them and re-run, or delete the role manually."
        )

    profiles = iam.list_instance_profiles_for_role(RoleName=role_name).get(
        "InstanceProfiles", []
    )
    if profiles:
        names = ", ".join(p.get("InstanceProfileName", "?") for p in profiles)
        raise ConnectorError(
            f"IAM role {role_name!r} belongs to instance profile(s) ({names}), "
            f"so an EC2 workload is using it. Nothing was removed. Remove it "
            f"from the profile(s) and re-run, or delete the role manually."
        )

    all_policies = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    ours = [p for p in all_policies if p in TOOL_INLINE_POLICY_NAMES]
    foreign = [p for p in all_policies if p not in TOOL_INLINE_POLICY_NAMES]

    if foreign:
        names = ", ".join(foreign)
        raise ConnectorError(
            f"IAM role {role_name!r} has inline policies this tool did not "
            f"create ({names}), so something else is using it. Nothing was "
            f"removed — the role and all its policies are intact. Delete it "
            f"manually if that's wrong."
        )

    for policy_name in ours:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

    iam.delete_role(RoleName=role_name)


def delete_cert(session: Any, bucket: str | None, key: str | None) -> None:
    """Delete the certificate object from S3.

    The bucket is shared across connectors and is left in place. Bucket and key
    are shape-checked before the delete; a missing value fails the same check.
    """
    s3 = session.client("s3")
    s3.delete_object(
        Bucket=validate_s3_bucket(bucket),
        Key=validate_s3_key(key),
    )


# --- Entra ---------------------------------------------------------------------


def delete_entra_app(
    *,
    tenant_id: str | None,
    object_id: str | None,
    auth_method: str = "az",
    device_client_id: str | None = None,
) -> None:
    """Delete the Entra app registration via Microsoft Graph.

    The Graph DELETE endpoint takes the directory object id, not the
    application (client) id.
    """
    if not object_id:
        raise ConnectorError(
            "No client_app_object_id in state. The app exists in your tenant "
            "but the tool doesn't know its directory id; delete it manually "
            "in the Azure portal."
        )
    if not tenant_id:
        raise ConnectorError(
            "No tenant_id in state; cannot build a Graph client for app deletion."
        )
    from kb_connector.providers.microsoft.apps import delete_application
    from kb_connector.providers.microsoft.client import GraphClient

    graph = GraphClient.from_auth(
        method=auth_method, tenant_id=tenant_id, device_client_id=device_client_id,
    )
    delete_application(graph, object_id)
