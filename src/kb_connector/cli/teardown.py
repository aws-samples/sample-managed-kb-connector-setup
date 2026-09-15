"""teardown subcommand — clean up resources created by setup.

Conservative by default: only deletes what the tool created (tracked in state),
prompts for confirmation on every destructive action.
"""

from __future__ import annotations

import argparse
import re
import sys

from kb_connector.core.config import load_config
from kb_connector.core.errors import ConfigError, ConnectorError
from kb_connector.core.identifiers import (
    validate_s3_bucket,
    validate_s3_key,
    validate_secret_arn,
)
from kb_connector.core.state import load_state, save_state


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the teardown subcommand."""
    parser = subparsers.add_parser(
        "teardown",
        help="Clean up resources created by setup",
        description=(
            "Remove resources tracked in state. Conservative by default: "
            "only deletes what the tool created, prompts for confirmation."
        ),
    )
    parser.add_argument("connector", nargs="?", help="Connector name from config")
    parser.add_argument("--kb", metavar="KB_ID", help="Knowledge base ID (override)")
    parser.add_argument(
        "--only",
        choices=["ds", "kb", "secret", "role", "app", "cert"],
        help="Tear down only a specific resource type",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be deleted"
    )
    parser.add_argument(
        "--yes", action="store_true", help="Skip confirmation prompts"
    )
    parser.add_argument(
        "--force", action="store_true",
        help=(
            "Stop any running ingestion job before deleting (default: refuse "
            "if a job is in progress)"
        ),
    )
    parser.add_argument(
        "--include-adopted", action="store_true",
        help=(
            "Also delete resources this tool adopted rather than created (an "
            "existing knowledge base passed via --kb, that KB's own IAM role, "
            "or anything taken over with --adopt-existing-resources). Skipped "
            "by default because they may predate this connector and be shared "
            "with other workloads."
        ),
    )
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    parser.add_argument(
        "--auth-method", choices=["az", "device_code"], default="az",
        help="Graph token method for Entra app deletion (default: az)",
    )
    parser.add_argument(
        "--device-client-id",
        help="Public client app id for device_code Graph auth",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the teardown subcommand."""
    try:
        return _run_teardown(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_teardown(args: argparse.Namespace) -> int:
    config = load_config(getattr(args, "config", None))
    state_file = load_state()

    connector_name = args.connector
    if not connector_name:
        names = config.connector_names()
        if len(names) == 1:
            connector_name = names[0]
        else:
            raise ConfigError(
                "Specify which connector to tear down: kb-connector teardown <name>"
            )

    cs = state_file.get(connector_name)
    if not any([cs.knowledge_base_id, cs.data_source_id, cs.secret_arn,
                cs.kb_role_arn, cs.client_app_id]):
        print(f"No resources tracked in state for '{connector_name}'. Nothing to tear down.")
        return 0

    print(f"Teardown for connector: {connector_name}")
    print(f"  type: {cs.connector_type or 'unknown'}")

    # Build the candidate list, then split it by recorded ownership. Anything
    # the tool adopted rather than created is held back unless the operator
    # asks for it: deleting a pre-existing knowledge base, or the role it
    # shares with its other data sources, breaks workloads this connector
    # never owned.
    candidates: list[tuple[str, str, str]] = []  # (type, id/arn, description)
    only = args.only

    if cs.data_source_id and (not only or only == "ds"):
        candidates.append(("ds", cs.data_source_id,
                           f"Data source {cs.data_source_id}"))
    if cs.knowledge_base_id and (not only or only == "kb"):
        candidates.append(("kb", cs.knowledge_base_id,
                           f"Knowledge base {cs.knowledge_base_id}"))
    if cs.secret_arn and (not only or only == "secret"):
        candidates.append(("secret", cs.secret_arn,
                           f"Secret {cs.secret_arn}"))
    if cs.kb_role_arn and (not only or only == "role"):
        candidates.append(("role", cs.kb_role_arn,
                           f"IAM role {cs.kb_role_arn}"))
    if cs.cert_s3_bucket and cs.cert_s3_key and (not only or only == "cert"):
        candidates.append(("cert", f"s3://{cs.cert_s3_bucket}/{cs.cert_s3_key}",
                           f"Certificate s3://{cs.cert_s3_bucket}/{cs.cert_s3_key}"))
    if cs.client_app_id and (not only or only == "app"):
        candidates.append(("app", cs.client_app_id,
                           f"Entra app {cs.client_app_id}"))

    resources = [r for r in candidates if cs.is_tool_owned(r[0]) or args.include_adopted]
    skipped = [r for r in candidates if r not in resources]

    if not resources and not skipped:
        print("  No matching resources to tear down.")
        return 0

    # Display plan
    if resources:
        print(f"\n  Resources to {'delete' if not args.dry_run else 'delete (DRY RUN)'}:")
        for rtype, rid, desc in resources:
            adopted = " [ADOPTED — deleting because --include-adopted]" if not cs.is_tool_owned(rtype) else ""
            print(f"    • {desc}{adopted}")

    if skipped:
        print("\n  Kept (adopted by this tool, not created by it):")
        for rtype, rid, desc in skipped:
            print(f"    • {desc}")
        print(
            "    These were pre-existing when the connector was set up. Use "
            "--include-adopted to delete them too, or remove them yourself."
        )

    if not resources:
        # Reaching here means `resources` is empty but `skipped` is not — the
        # both-empty case returned above. So every candidate is an adopted
        # resource that is still live and still referenced by this state entry.
        # Dropping the entry would discard the only record that this connector
        # is attached to them, which is the same reason the post-teardown block
        # below keeps the entry when `skipped` is non-empty.
        print(
            f"\n  Nothing to delete: all {len(skipped)} tracked resource(s) were "
            f"adopted rather than created by this tool."
        )
        print(
            "  Keeping tracked state so the attachment stays recorded. Use "
            "--include-adopted to delete them, or remove them yourself."
        )
        return 0

    if args.dry_run:
        print("\n  Dry run — no changes made.")
        return 0

    # Confirm
    if not args.yes:
        print()
        response = input("  Proceed with teardown? (y/N): ").strip().lower()
        if response not in ("y", "yes"):
            print("  Cancelled.")
            return 0

    # Execute deletions (AWS-side)
    import boto3
    region = args.region or cs.region
    profile = args.profile

    if region:
        session = boto3.Session(region_name=region, profile_name=profile)
    else:
        session = boto3.Session(profile_name=profile)

    # Precheck: refuse to teardown while an ingestion job is in progress.
    # Without this, the DS/KB delete fails 4xx and the rest of the loop
    # would still strip the credentials the running job depends on.
    if cs.knowledge_base_id and cs.data_source_id:
        active_job = _find_active_ingestion_job(
            session, region, cs.knowledge_base_id, cs.data_source_id,
        )
        if active_job:
            if not args.force:
                print(
                    f"\n  Refusing to tear down: ingestion job {active_job} is "
                    f"in progress on data source {cs.data_source_id}."
                )
                print(
                    f"  Re-run with --force to stop the job first, or run "
                    f"`aws bedrock-agent stop-ingestion-job --knowledge-base-id "
                    f"{cs.knowledge_base_id} --data-source-id "
                    f"{cs.data_source_id} --ingestion-job-id {active_job} "
                    f"--region {region}` and wait for it to finish."
                )
                return 1
            print(f"\n  --force: stopping ingestion job {active_job}...")
            _stop_and_wait_for_terminal(
                session, region, cs.knowledge_base_id, cs.data_source_id, active_job,
            )

    # Order matters: AWS-side resources (DS, KB) need their credentials to
    # exist while delete is in flight. We split the loop so a failure on
    # DS or KB halts before we strip the secret/role/cert/app the running
    # KB might still need.
    aws_managed = {"ds", "kb"}
    aws_steps = [r for r in resources if r[0] in aws_managed]
    cred_steps = [r for r in resources if r[0] not in aws_managed]

    aws_failed = False
    for rtype, rid, desc in aws_steps + cred_steps:
        if aws_failed and rtype not in aws_managed:
            print(
                f"    ⊘ Skipping {desc} — AWS-side delete failed earlier; "
                f"upstream credentials left intact for retry."
            )
            continue
        try:
            if rtype == "ds" and cs.knowledge_base_id:
                _delete_data_source(session, region, cs.knowledge_base_id, rid)
                cs.data_source_id = None
                print(f"    ✓ Deleted data source {rid}")
            elif rtype == "kb":
                _delete_knowledge_base(session, region, rid)
                cs.knowledge_base_id = None
                print(f"    ✓ Deleted knowledge base {rid}")
            elif rtype == "secret":
                _delete_secret(session, rid)
                cs.secret_arn = None
                print(f"    ✓ Deleted secret: {rid}")
            elif rtype == "role":
                _delete_role(session, rid)
                cs.kb_role_arn = None
                print(f"    ✓ Deleted IAM role: {rid}")
            elif rtype == "cert":
                _delete_cert(session, cs.cert_s3_bucket, cs.cert_s3_key)
                cs.cert_s3_bucket = None
                cs.cert_s3_key = None
                print(f"    ✓ Deleted certificate from {rid}")
            elif rtype == "app":
                _delete_entra_app(args, cs)
                cs.client_app_id = None
                cs.client_app_object_id = None
                print(f"    ✓ Deleted Entra app {rid}")
        except Exception as exc:
            print(f"    ✗ Failed to delete {desc}: {exc}")
            if rtype in aws_managed:
                aws_failed = True

    # On a full, fully-successful teardown, drop the connector's stanza
    # entirely. Otherwise the resource IDs get nulled but descriptive fields
    # (cert thumbprint/expiry, tenant id, last ingestion job id) linger and can
    # mislead a later `diagnose` into thinking a cert still exists. A scoped
    # teardown (--only) or a partial failure keeps the stanza so the remaining
    # resources stay tracked.
    full_teardown = not args.only
    nothing_left = not any([
        cs.knowledge_base_id, cs.data_source_id, cs.secret_arn,
        cs.kb_role_arn, cs.client_app_id, cs.cert_s3_bucket,
    ])
    if skipped:
        # Adopted resources are still live and still referenced by state, so the
        # stanza has to stay — dropping it would lose the only record that this
        # connector is attached to them.
        print(
            f"\n  Keeping tracked state for {connector_name!r}: "
            f"{len(skipped)} adopted resource(s) still exist."
        )
    if full_teardown and nothing_left and not aws_failed and not skipped:
        state_file.connectors.pop(connector_name, None)
        save_state(state_file)
        print("\n  Teardown complete. Connector state cleared.")
    else:
        state_file.set(connector_name, cs)
        save_state(state_file)
        print("\n  Teardown complete. State updated.")
    return 0


def _delete_data_source(session, region, kb_id, ds_id):
    from kb_connector.targets import get_target
    target = get_target("bmkb", session=session, region=region)
    target.delete_data_source(kb_id, ds_id)


_TERMINAL_INGESTION_STATES = {"COMPLETE", "COMPLETED", "FAILED", "STOPPED"}

# Inline policy names this tool authors on a KB role live in
# provisioning.TOOL_INLINE_POLICY_NAMES — an exact-name set, single-sourced
# next to the code that writes them. See _delete_role.

# IAM's RoleName charset and length limit, applied to reject a role name that
# state does not actually justify before it reaches DeleteRole.
_IAM_ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")


def _role_name_from_arn(role_arn: str) -> str:
    """Extract a role name from an IAM role ARN, or refuse.

    State is an input, not a fact: it is a plain JSON file, and this value is
    about to become the target of DeleteRole. So a full ARN is required rather
    than whatever a permissive split happens to yield. Trimming from a marker
    (`split(":role/")[-1]`) would pass a string with no `:role/` in it straight
    through, letting a state file holding the bare name
    "OrganizationAccountAccessRole" aim teardown at that role.

    Handles role paths (`:role/some/path/Name` -> `Name`), which IAM allows.
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


def _find_active_ingestion_job(session, region, kb_id, ds_id) -> str | None:
    """Return the most recent non-terminal ingestion job ID, or None.

    Used as the precheck that gates teardown: if a job is in progress,
    plowing ahead deletes credentials the job still needs. We bail
    cleanly and let the caller decide between waiting and --force.
    """
    from kb_connector.targets import get_target
    target = get_target("bmkb", session=session, region=region)
    try:
        # Look at the most recent few jobs only — running jobs are always
        # near the top, and ListIngestionJobs is unfiltered by status.
        resp = target.list_ingestion_jobs(kb_id, ds_id, max_results=5)
        for job in resp.get("ingestionJobSummaries", [])[:5]:
            status = (job.get("status") or "").upper()
            if status not in _TERMINAL_INGESTION_STATES:
                return job.get("ingestionJobId")
    except Exception as exc:
        # This lookup is the gate that keeps teardown from deleting credentials
        # out from under a running ingestion job, so a failure here disables a
        # safety check rather than merely losing information. Teardown still
        # proceeds — blocking on a transient ListIngestionJobs error would be
        # its own foot-gun — but say so, because the operator is about to lose
        # the guard and may want to check the console first.
        print(
            f"  WARNING: could not check for a running ingestion job on data "
            f"source {ds_id}: {exc}\n"
            f"  Proceeding without that check. If a job is in flight, deleting "
            f"its credentials now will fail the job.",
            file=sys.stderr,
        )
        return None
    return None


def _stop_and_wait_for_terminal(session, region, kb_id, ds_id, job_id) -> None:
    """Stop the ingestion job and poll briefly for a terminal state.

    The Bedrock API's stop is asynchronous: STOPPING transitions to
    STOPPED on its own. We wait up to ~3 minutes for that transition;
    after that we proceed with the deletes anyway, since the credentials
    are about to go regardless.
    """
    import time
    from kb_connector.targets import get_target
    target = get_target("bmkb", session=session, region=region)
    try:
        target.stop_ingestion_job(kb_id, ds_id, job_id)
    except Exception as exc:
        print(f"    (stop request failed: {exc} — proceeding anyway)")
        return

    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            resp = target.get_ingestion_job(kb_id, ds_id, job_id)
            status = (resp.get("ingestionJob", {}).get("status") or "").upper()
            if status in _TERMINAL_INGESTION_STATES:
                print(f"    ingestion job reached {status}")
                return
        except Exception:
            return
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- poll interval for ingestion stop
    print("    (ingestion still STOPPING after 3 minutes — proceeding anyway)")


def _delete_knowledge_base(session, region, kb_id):
    from kb_connector.targets import get_target
    target = get_target("bmkb", session=session, region=region)
    target.delete_knowledge_base(kb_id)


def _delete_secret(session, secret_arn):
    sm = session.client("secretsmanager")
    # Force delete (no recovery window). The secret holds credentials this tool
    # minted for one connector and can mint again, so the 7-day default buys no
    # recoverability worth having and does block re-running setup under the same
    # connector name. If you want the recovery window, delete the secret
    # yourself instead of using teardown.
    #
    # Because there is no recovery window, the target is checked first: this
    # ARN comes from the state file, which is editable and can be populated
    # from a handoff document written by someone else.
    sm.delete_secret(
        SecretId=validate_secret_arn(secret_arn),
        ForceDeleteWithoutRecovery=True,
    )


def _delete_role(session, role_arn):
    """Delete a KB service role the tool created.

    Every reason to refuse is checked *before* anything is removed. Inline
    policies have to go before DeleteRole, so the temptation is to delete the
    ones we recognize and then complain about the rest — but that leaves the
    role in place with its permissions stripped, which is strictly worse than
    both deleting it and leaving it alone. Since this function is reachable for
    a role carrying unrelated policies, the refusals run first and the deletes
    only start once the role is known to be safe to remove entirely.

    Three refusals, all read-only, all ahead of the first mutation:

    * Managed policies attached — the role is used beyond this connector.
    * The role is in an instance profile — DeleteRole will refuse anyway, and
      an EC2 workload is depending on it.
    * Inline policies this tool did not author — same reasoning as above.

    Recognition is by exact name against TOOL_INLINE_POLICY_NAMES, not a
    `kb-connector` prefix: a prefix also matches policies the tool never wrote.
    """
    from kb_connector.core.provisioning import TOOL_INLINE_POLICY_NAMES

    iam = session.client("iam")
    role_name = _role_name_from_arn(role_arn)

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


def _delete_cert(session, bucket: str, key: str) -> None:
    """Delete the certificate object from S3.

    The cert bucket itself is shared across connectors and is left in place;
    only the per-connector .p12 object is removed.

    Bucket and key come from the state file, so both are shape-checked before
    the delete: an unchecked pair aims DeleteObject at any object the caller's
    credentials can reach.
    """
    s3 = session.client("s3")
    s3.delete_object(
        Bucket=validate_s3_bucket(bucket),
        Key=validate_s3_key(key),
    )


def _delete_entra_app(args: argparse.Namespace, cs) -> None:
    """Delete the Entra app registration via Microsoft Graph.

    Requires a Graph token from `az login` or device-code auth. The state
    file's stored object id is used (the Graph DELETE endpoint takes the
    directory object id, not the application/client id).
    """
    if not cs.client_app_object_id:
        raise ConnectorError(
            "No client_app_object_id in state. The app exists in your tenant "
            "but the tool doesn't know its directory id; delete it manually "
            "in the Azure portal."
        )
    if not cs.tenant_id:
        raise ConnectorError(
            "No tenant_id in state; cannot build a Graph client for app deletion."
        )
    from kb_connector.providers.microsoft.apps import delete_application
    from kb_connector.providers.microsoft.client import GraphClient

    graph = GraphClient.from_auth(
        method=getattr(args, "auth_method", "az"),
        tenant_id=cs.tenant_id,
        device_client_id=getattr(args, "device_client_id", None),
    )
    delete_application(graph, cs.client_app_object_id)
