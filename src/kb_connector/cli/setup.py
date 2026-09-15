"""setup subcommand — provider-aware identity + AWS setup.

Runs the full setup flow for a connector:
  Stage 1 (source-side): Configure the 3P identity provider (Entra for SP/OD)
  Stage 2 (AWS-side): Create KB resources (secret, cert upload, role, KB, DS)

Resumable: re-running skips completed steps (reads state on start).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets as _secrets
import sys
import time
from dataclasses import dataclass, field as dataclass_field
from getpass import getpass
from typing import Any

from kb_connector.core import state as state_mod

from kb_connector.core.config import ConnectorConfig, load_config
from kb_connector.core.errors import AwsError, ConfigError, ConnectorError, StateError
from kb_connector.core.state import ConnectorState, load_state, save_state


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the setup subcommand."""
    parser = subparsers.add_parser(
        "setup",
        help="Set up a connector (source-side identity + AWS resources)",
        description=(
            "Run the full setup flow for a connector: Stage 1 (source-side identity "
            "provider) and Stage 2 (AWS resources). Resumable — re-running skips "
            "completed steps."
        ),
    )
    parser.add_argument("connector", nargs="?", help="Connector name from config")
    parser.add_argument(
        "--from-handoff", metavar="FILE", help="Import handoff file (skip source-side)"
    )
    parser.add_argument(
        "--stage", choices=["1", "2", "both"], default="both",
        help="Run only a specific stage (default: both)",
    )
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    # Source-side options
    parser.add_argument("--auth-method", choices=["az", "device_code"], default="az",
                        help="Graph token acquisition (default: az)")
    parser.add_argument("--device-client-id", help="Public client app id for device_code")
    parser.add_argument("--app-name", help="Entra app display name override")
    parser.add_argument("--cert-valid-days", type=int, default=365,
                        help="Certificate validity in days (default: 365)")
    parser.add_argument("--sites-selected", action="store_true",
                        help="Use Sites.Selected (SharePoint least-privilege)")
    # AWS-side options
    parser.add_argument("--knowledge-base-id", "--kb", metavar="KB_ID",
                        help="Reuse an existing KB (skip KB creation)")
    parser.add_argument("--kb-name", help="Name for new KB (default: auto)")
    parser.add_argument("--kb-role-name", help="IAM role name for the KB")
    parser.add_argument("--kb-role-arn", help="Use an existing IAM role ARN")
    parser.add_argument("--secret-name", help="Secrets Manager secret name")
    parser.add_argument("--cert-s3-bucket", help="S3 bucket for certificate")
    parser.add_argument("--cert-s3-key", help="S3 key for certificate")
    parser.add_argument("--ds-name", help="Data source name (default: auto)")
    parser.add_argument("--no-create-kb-role", action="store_true",
                        help="Don't create a KB service role (requires --kb-role-arn)")
    # Ownership + protection options
    parser.add_argument(
        "--no-tags", action="store_true",
        help=(
            "Don't tag created resources. Tags are how the tool proves it owns "
            "a resource before updating it and how teardown knows what is safe "
            "to delete, so disabling them means later runs will refuse to reuse "
            "resources without --adopt-existing-resources."
        ),
    )
    parser.add_argument(
        "--adopt-existing-resources", action="store_true",
        help=(
            "Modify pre-existing resources whose ownership can't be confirmed "
            "by tag (an untagged role/secret/bucket with the derived name, or "
            "one owned by a different connector). Adopted resources are "
            "recorded as external and are never deleted by teardown."
        ),
    )
    parser.add_argument(
        "--kms-key-arn",
        help=(
            "Customer-managed KMS key for the connector secret and certificate "
            "object. Default is the AWS-managed key (no extra cost). A CMK adds "
            "a key-policy gate on top of IAM; the KB role is granted kms:Decrypt "
            "on it automatically."
        ),
    )
    parser.add_argument(
        "--allow-unhardened-cert-bucket", action="store_true",
        help=(
            "Proceed even if public-access-block and default encryption can't "
            "be applied to the certificate bucket. Only use this when those "
            "controls are enforced another way."
        ),
    )
    parser.add_argument(
        "--sync", action="store_true",
        help="Start an ingestion job after setup and poll to completion",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=15,
        help="Seconds between status checks when --sync is set (default: 15)",
    )
    parser.add_argument(
        "--timeout", type=int, default=1800,
        help="Max seconds to wait for ingestion when --sync is set (default: 1800)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the setup subcommand."""
    try:
        return _run_setup(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _aws_session_and_account(cfg: ConnectorConfig) -> tuple[Any, str]:
    """Open a boto3 session, print the resolved profile + caller, return account.

    The profile is printed before the first AWS call (STS) so a missing or
    expired credential is attributable to a specific profile. Creating the
    Session makes no network call, so the profile line always prints ahead of
    any credential error.
    """
    import boto3

    print(f"  AWS profile: {cfg.profile or 'default credential chain'}")
    session = boto3.Session(region_name=cfg.region, profile_name=cfg.profile)
    caller = session.client("sts").get_caller_identity()
    print(f"  AWS caller: {caller['Arn']}")
    return session, caller["Account"]


def _tracked_resource_summary(cs: ConnectorState) -> list[str]:
    """List the AWS resources currently tracked in state, for display.

    Used on a failed setup to report what was created before the failure so the
    resources can be cleaned up rather than left orphaned.
    """
    lines: list[str] = []
    if cs.knowledge_base_id:
        lines.append(f"Knowledge base {cs.knowledge_base_id}")
    if cs.data_source_id:
        lines.append(f"Data source {cs.data_source_id}")
    if cs.secret_arn:
        lines.append(f"Secret {cs.secret_arn}")
    if cs.kb_role_arn:
        lines.append(f"IAM role {cs.kb_role_arn}")
    if cs.cert_s3_bucket and cs.cert_s3_key:
        lines.append(f"Certificate s3://{cs.cert_s3_bucket}/{cs.cert_s3_key}")
    if cs.client_app_id:
        lines.append(f"Entra app {cs.client_app_id}")
    return lines


def _deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge `overrides` into `base`, returning a new dict.

    Used to apply a TOML-supplied connector_params_overrides table onto the
    params built by a connector builder. Nested dicts merge key-by-key; any
    other value at a key replaces what was there. Lists replace, they don't
    concatenate, since concatenation rarely matches user intent for fields
    like inclusionItemPaths.
    """
    out = dict(base)
    for key, val in overrides.items():
        if (
            key in out
            and isinstance(out[key], dict)
            and isinstance(val, dict)
        ):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = val
    return out


@dataclass
class _ProvisionOptions:
    """Cross-cutting provisioning choices, resolved once per run.

    Threaded into every core.provisioning call so ownership tagging, adoption
    policy, and encryption choice stay consistent across the four connector
    setup paths instead of being re-derived at each call site.
    """

    tags_enabled: bool = True
    adopt_existing: bool = False
    kms_key_arn: str | None = None
    allow_unhardened: bool = False
    tags: dict = dataclass_field(default_factory=dict)


def _provision_options(args: argparse.Namespace, cfg: ConnectorConfig) -> _ProvisionOptions:
    """Resolve provisioning options from CLI flags + config."""
    from kb_connector.core.tagging import validate_extra_tags

    # Validated here rather than at each call site so a malformed [tags] table
    # fails once, before the first AWS call, instead of partway through
    # provisioning.
    try:
        extra_tags = validate_extra_tags(cfg.tags)
    except ValueError as exc:
        raise ConfigError(f"Invalid [tags] entry for this connector: {exc}") from exc

    opts = _ProvisionOptions(
        tags_enabled=not getattr(args, "no_tags", False),
        adopt_existing=getattr(args, "adopt_existing_resources", False),
        kms_key_arn=getattr(args, "kms_key_arn", None) or cfg.kms_key_arn,
        allow_unhardened=getattr(args, "allow_unhardened_cert_bucket", False),
        tags=extra_tags,
    )
    if extra_tags and opts.tags_enabled:
        print(f"  Applying {len(extra_tags)} operator tag(s): {', '.join(sorted(extra_tags))}")
    elif extra_tags and not opts.tags_enabled:
        print(
            "  NOTE: [tags] are configured but --no-tags is set, so no tags "
            "(including yours) will be applied."
        )
    if not opts.tags_enabled:
        print(
            "  NOTE: --no-tags is set. Resources will not carry ownership tags, "
            "so teardown and future runs cannot verify what this tool created."
        )
    if opts.adopt_existing:
        print(
            "  NOTE: --adopt-existing-resources is set. Pre-existing resources "
            "may be modified; they will be recorded as external and left alone "
            "by teardown."
        )
    if opts.kms_key_arn:
        print(f"  Using customer-managed KMS key: {opts.kms_key_arn}")
    return opts


def _derived_name(cfg: ConnectorConfig, base: str) -> str:
    """Apply the connector's resource_prefix to a derived resource name.

    Derived names are predictable by design (they have to be stable across
    re-runs), which means two independent uses of this tool in one account can
    land on the same name. resource_prefix is the escape hatch that keeps them
    apart without forcing a connector rename.
    """
    prefix = (cfg.resource_prefix or "").strip().strip("-/")
    if not prefix:
        return base
    return f"{prefix}-{base}"


def _derive_aws_names(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    connector_name: str,
    account_id: str,
    *,
    uses_cert: bool,
) -> dict:
    """Derive the AWS resource names the AWS stage will use.

    Shared with the ownership preflight so both look at exactly the same names.
    If these drifted, the preflight would clear one set of resources and setup
    would then refuse a different one.
    """
    cert_bucket = args.cert_s3_bucket or cfg.cert_s3_bucket
    if uses_cert and not cert_bucket:
        # Default scoped to account + region; ensure_cert_bucket creates it if
        # missing and reuses it if present, so re-runs stay idempotent.
        cert_bucket = f"kb-connector-certs-{account_id}-{cfg.region}"
    return {
        "secret_name": args.secret_name
        or _derived_name(cfg, f"kb-connector/{connector_name}-credentials"),
        "kb_role_name": args.kb_role_name
        or _derived_name(cfg, f"kb-connector-{connector_name}-role"),
        "cert_bucket": cert_bucket,
        "cert_key": args.cert_s3_key
        or f"{cfg.cert_s3_key_prefix or 'kb-connector'}/{connector_name}.p12",
    }


def _preflight_aws_ownership(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    *,
    uses_cert: bool,
) -> None:
    """Refuse unowned AWS resources before any source-side work happens.

    The AWS stage already refuses to modify resources this tool doesn't own, but
    by then Stage 1 has registered an Entra app, granted tenant-wide admin
    consent, and replaced the app's certificate. Those are not rolled back, so a
    run that could never succeed still leaves live directory objects behind.
    Checking first turns that into a clean, no-op failure.
    """
    from kb_connector.core import provisioning

    if not cfg.region:
        return  # The AWS stage raises its own clear error for a missing region.
    if getattr(args, "adopt_existing_resources", False):
        return  # The operator has already opted in to modifying what's there.

    try:
        session, account_id = _aws_session_and_account(cfg)
    except Exception:
        # Credential and region problems produce better messages in the AWS
        # stage; failing here would just report them earlier and less clearly.
        return

    names = _derive_aws_names(args, cfg, connector_name, account_id, uses_cert=uses_cert)

    # Only check the role when the AWS stage would actually create or update
    # one. Attaching to an existing KB extends that KB's own role instead, which
    # is a deliberately unowned path (see extend_kb_role_for_secret).
    kb_id = args.knowledge_base_id or cs.knowledge_base_id
    check_role = not kb_id and not args.no_create_kb_role

    try:
        conflicts = provisioning.preflight_ownership(
            session=session,
            connector_name=connector_name,
            tags_enabled=not getattr(args, "no_tags", False),
            cert_bucket=names["cert_bucket"] if uses_cert else None,
            secret_name=names["secret_name"],
            role_name=names["kb_role_name"] if check_role else None,
        )
    except Exception as exc:
        # A preflight that cannot run must not block a setup that would work.
        print(f"  NOTE: ownership preflight skipped ({exc})", file=sys.stderr)
        return

    if conflicts:
        raise AwsError(
            "Ownership preflight failed — nothing has been created.\n\n"
            + "\n\n".join(conflicts)
        )


def _run_setup(args: argparse.Namespace) -> int:
    """Main setup logic."""
    # Load config + state
    config = load_config(getattr(args, "config", None))
    state_file = load_state()

    connector_name = args.connector
    if not connector_name:
        names = config.connector_names()
        if len(names) == 1:
            connector_name = names[0]
        elif not names:
            raise ConfigError(
                "No connectors configured. Run 'kb-connector init' first, "
                "or pass a connector name."
            )
        else:
            raise ConfigError(
                f"Multiple connectors in config: {', '.join(names)}. "
                "Specify which one: kb-connector setup <name>"
            )

    cli_overrides = {}
    if args.region:
        cli_overrides["region"] = args.region
    if args.profile:
        cli_overrides["profile"] = args.profile

    try:
        cfg = config.resolve_connector(connector_name, cli_overrides=cli_overrides)
    except ConfigError:
        # Maybe they passed connector name directly without a config file
        raise

    cs = state_file.get(connector_name)
    stage = args.stage

    print(f"Setting up connector: {connector_name} (type: {cfg.type})")
    print(f"  region: {cfg.region or 'default'}")

    # Dispatch to the appropriate setup path. Persist state in a finally block
    # so that resources created before a mid-flight failure are still tracked
    # (and therefore cleanable by `teardown`). Setup is resumable: re-running
    # reads this state and skips completed steps.
    failed = False
    try:
        if cfg.type in ("sharepoint", "onedrive"):
            _setup_microsoft(args, cfg, cs, connector_name, stage)
        elif cfg.type == "s3":
            _setup_s3(args, cfg, cs, connector_name, stage)
        elif cfg.type == "web":
            _setup_web(args, cfg, cs, connector_name, stage)
        elif cfg.type == "confluence":
            _setup_guided(args, cfg, cs, connector_name, stage, "confluence")
        elif cfg.type == "googledrive":
            _setup_guided(args, cfg, cs, connector_name, stage, "googledrive")
        else:
            raise ConfigError(f"Connector type {cfg.type!r} setup not yet implemented.")
    except BaseException:
        failed = True
        raise
    finally:
        # Always persist whatever was created so far, so that resources created
        # before a mid-flight failure are still tracked (and cleanable by
        # `teardown`). The message differs on failure so "State saved" isn't
        # mistaken for "setup succeeded".
        state_file.set(connector_name, cs)
        path = save_state(state_file)
        if failed:
            partial = _tracked_resource_summary(cs)
            if partial:
                print(
                    f"\nSetup did not complete. Partial state (tracked "
                    f"resources) saved to {path}:"
                )
                for line in partial:
                    print(f"    • {line}")
                print(
                    f"  To remove what was created, run: "
                    f"kb-connector teardown {connector_name}"
                )
            else:
                print(
                    f"\nSetup did not complete. No AWS resources were created; "
                    f"state saved to {path}."
                )
        else:
            print(f"\nState saved to {path}")

    print("Setup complete.")

    if args.sync:
        return _run_sync(args, connector_name)

    print(f"  Next: kb-connector monitor {connector_name}    # start ingestion + watch it")
    return 0


def _run_sync(args: argparse.Namespace, connector_name: str) -> int:
    """Kick off an ingestion job and poll to completion.

    Wraps service.monitor with start=True so --sync is a one-line follow-on
    to setup. A non-zero return surfaces ingestion failures (status not
    COMPLETE) so the overall setup --sync exit code reflects the full path.
    """
    from kb_connector import service

    print("\n── Sync ──")
    try:
        result = service.monitor(
            connector_name=connector_name,
            region=args.region,
            profile=args.profile,
            start=True,
            poll_interval_seconds=args.poll_interval,
            timeout_seconds=args.timeout,
            config_path=getattr(args, "config", None),
        )
    except ConnectorError as exc:
        print(f"\nSync error: {exc}", file=sys.stderr)
        return 1

    stats = result.stats
    if result.timed_out:
        print("  (timed out waiting for terminal state)")
    print(f"\nIngestion (job {result.job_id}):")
    print(f"  status:  {stats.status}")
    print(f"  scanned: {stats.scanned}")
    print(f"  indexed: {stats.indexed_total} (new={stats.new_indexed}, modified={stats.modified_indexed})")
    print(f"  failed:  {stats.failed}")
    print(f"  skipped: {stats.skipped}")
    if stats.has_acl_warning:
        print(
            f"\n  WARNING: {stats.skipped}/{stats.scanned} documents skipped. "
            "Common cause: ACL crawling enabled but the connector app is "
            "missing the permissions needed to read item-level access."
        )
    return 0 if stats.status in ("COMPLETE", "COMPLETED") else 1


# --- Shared AWS-side helpers (route through the target abstraction) ----------


def _build_target(cfg: ConnectorConfig, session):
    """Construct the control-plane target for this connector's config."""
    from kb_connector.targets import get_target
    return get_target(
        "bmkb",
        session=session,
        region=cfg.region,
        buildtime_endpoint=cfg.endpoint_url,
        runtime_endpoint=cfg.runtime_endpoint_url,
    )


def _provision_kb_and_ds(
    *,
    target,
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    kb_role_arn: str | None,
    connector_parameters: dict | None = None,
    raw_ds_payload: dict | None = None,
) -> None:
    """Create-or-reuse the KB, then create the DS and wait for AVAILABLE.

    Routes every control-plane call through the Target so a different backend
    (e.g. Quick) can be swapped in without touching this logic. Updates
    connector state (cs) in place.

    Pass `connector_parameters` for managed-connector data sources, or
    `raw_ds_payload` for connectors with a non-managed shape (e.g. S3).

    Applies any [connectors.<name>.connector_params_overrides] dict from
    config as a deep-merge onto `connector_parameters`. This is the escape
    hatch for fields the curated builders don't surface (filterConfiguration,
    advanced indexing, deletion policy, etc.) — see KNOWN-LIMITATIONS.md.
    """
    kb_id = args.knowledge_base_id or cs.knowledge_base_id

    if not kb_id:
        if not kb_role_arn:
            raise ConfigError(
                "No KB role available. Provide --kb-role-arn or let the tool create one."
            )
        kb_name = args.kb_name or f"kb-connector-{connector_name}"
        created = target.create_knowledge_base(name=kb_name, role_arn=kb_role_arn)
        kb_obj = created.get("knowledgeBase", created)
        kb_id = kb_obj.get("knowledgeBaseId") or kb_obj.get("id")
        print(f"  Created knowledge base: {kb_id}")
        print("  Waiting for KB to become ACTIVE...")
        target.wait_until_kb_active(kb_id)
        print("  KB is ACTIVE")
        cs.record_owned(state_mod.RESOURCE_KB)
    else:
        # The operator pointed us at this KB; it predates the connector and may
        # carry other data sources. Recording it as external is what stops a
        # later teardown from deleting someone else's knowledge base.
        print(f"  Using existing KB: {kb_id} (external — teardown will not delete it)")
        cs.record_external(state_mod.RESOURCE_KB)

    cs.knowledge_base_id = kb_id

    # Apply user-provided connector parameter overrides as a deep-merge.
    overrides = cfg.get("connector_params_overrides")
    if overrides and connector_parameters is not None:
        connector_parameters = _deep_merge(connector_parameters, overrides)
        print(f"  Applied connector_params_overrides ({len(overrides)} top-level field(s))")

    ds_name = args.ds_name or f"{connector_name}-ds"

    # If a data source is already tracked in state, reconcile it before
    # creating a new one. A data source in a terminal-bad state is neither
    # complete nor recoverable, so it's recreated rather than reused.
    existing_ds_id = cs.data_source_id
    if existing_ds_id and raw_ds_payload is None:
        reuse_id = _reconcile_existing_data_source(target, kb_id, existing_ds_id)
        if reuse_id:
            print(f"  Reusing existing data source: {reuse_id} (AVAILABLE)")
            cs.data_source_id = reuse_id
            cs.region = cfg.region
            return

    ds_id = _create_data_source_with_diagnostics(
        target=target,
        kb_id=kb_id,
        ds_name=ds_name,
        connector_parameters=connector_parameters,
        raw_ds_payload=raw_ds_payload,
    )
    print(f"  Created data source: {ds_id}")
    # Record the DS id immediately so a failed AVAILABLE wait is still tracked
    # (and therefore cleanable by teardown).
    cs.data_source_id = ds_id
    cs.record_owned(state_mod.RESOURCE_DS)
    cs.region = cfg.region
    print("  Waiting for data source to become AVAILABLE...")
    target.wait_until_ds_available(kb_id, ds_id)
    print("  Data source is AVAILABLE")


# Data source statuses from which there is no forward path: recreate instead of
# reuse. Mirrors core.knowledge_base._DS_TERMINAL_BAD.
_DS_TERMINAL_BAD = {"FAILED", "DELETE_UNSUCCESSFUL"}


def _reconcile_existing_data_source(target, kb_id: str, ds_id: str) -> str | None:
    """Decide what to do with a data source already tracked in state.

    Returns the DS id to reuse if it's healthy (AVAILABLE), or None if the
    caller should create a fresh one. A DS in a terminal-bad state is deleted
    here so the create path can replace it. A DS the service no longer knows
    about (stale state) also yields None.
    """
    try:
        resp = target.get_data_source(kb_id, ds_id)
    except Exception as exc:
        # Most likely a stale id (deleted out from under us) — fall through to
        # recreation rather than failing the whole run.
        print(f"  Tracked data source {ds_id} not retrievable ({exc}); recreating.")
        return None

    ds = resp.get("dataSource", resp)
    status = (ds.get("status") or "").upper()

    if status == "AVAILABLE":
        return ds_id
    if status in _DS_TERMINAL_BAD:
        print(
            f"  Tracked data source {ds_id} is in terminal state {status}; "
            f"deleting and recreating so the current config takes effect."
        )
        try:
            target.delete_data_source(kb_id, ds_id)
        except Exception as exc:
            raise AwsError(
                f"Data source {ds_id} is {status} and could not be deleted "
                f"automatically: {exc}. Remove it and re-run: "
                f"kb-connector teardown --only ds"
            ) from exc
        return None
    # CREATING / DELETING / other transient states: let the create path attempt
    # and surface a clear error if the name is still reserved.
    print(f"  Tracked data source {ds_id} is {status or 'UNKNOWN'}; will recreate.")
    return None


def _create_data_source_with_diagnostics(
    *,
    target,
    kb_id: str,
    ds_name: str,
    connector_parameters: dict | None,
    raw_ds_payload: dict | None,
) -> str:
    """Create the data source, translating a name-collision 409 into guidance.

    Bedrock data-source deletion is asynchronous: the name stays reserved for a
    short window after a delete returns. A setup run that immediately recreates
    a DS with the same derived name can hit a 409 "already exists"; that case
    returns an actionable message rather than the raw API error.
    """
    try:
        if raw_ds_payload is not None:
            ds_resp = target.create_data_source_raw(kb_id, raw_ds_payload)
        else:
            ds_resp = target.create_data_source(
                kb_id, name=ds_name, connector_parameters=connector_parameters or {}
            )
    except AwsError as exc:
        text = str(exc)
        if "409" in text and "already exists" in text.lower():
            raise AwsError(
                f"A data source named {ds_name!r} already exists on knowledge "
                f"base {kb_id}. If you just ran teardown, Bedrock deletes data "
                f"sources asynchronously and the name stays reserved briefly — "
                f"wait a minute and re-run. Otherwise pass a different name with "
                f"--ds-name, or reuse the existing one with `monitor`."
            ) from exc
        raise

    ds_obj = ds_resp.get("dataSource", ds_resp)
    ds_id = ds_obj.get("dataSourceId") or ds_obj.get("id")
    if not ds_id:
        raise AwsError(f"CreateDataSource returned no data source id: {ds_resp}")
    return ds_id


# --- Microsoft (SharePoint / OneDrive) setup ---------------------------------


def _setup_microsoft(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    stage: str,
) -> None:
    """Full SP/OD setup: Stage 1 (Entra) + Stage 2 (AWS)."""
    from kb_connector.connectors.sharepoint import (
        filter_config_from_config as sp_filter_config,
        build_connector_params as sp_params,
        build_secret_body as sp_secret,
    )
    from kb_connector.connectors.onedrive import (
        build_connector_params as od_params,
        build_secret_body as od_secret,
    )
    from kb_connector.providers.microsoft.client import GraphClient
    from kb_connector.providers.microsoft import apps, certs, permissions, sites_selected
    from kb_connector.core import provisioning

    tenant_id = cfg.tenant_id
    if not tenant_id:
        raise ConfigError("tenant_id is required for SharePoint/OneDrive connectors.")

    credential = cfg.credential or "cert"
    acl = cfg.acl
    uses_cert = credential.strip().lower() == "cert"

    # Validate combination
    if acl and not uses_cert:
        raise ConfigError(
            "ACL requires 'cert' credential (the ACL verification path is "
            "certificate-only). Use credential = 'cert' or disable ACL."
        )

    # SharePoint is certificate-only here. 'client_secret' can't supply the
    # certificateS3Path the connector requires, so it produces a data source the
    # service rejects; 'ropc' is a mode the connector supports but this tool
    # doesn't automate (see KNOWN-LIMITATIONS.md). Rejected before the Entra app,
    # secret, role, or KB is created so a run can't leave orphaned resources.
    if cfg.type == "sharepoint" and not uses_cert:
        raise ConfigError(
            f"SharePoint requires credential = 'cert' (got {credential!r}). "
            "'client_secret' can't provide the certificateS3Path the connector "
            "needs, and 'ropc' is not automated by this tool. See "
            "KNOWN-LIMITATIONS.md."
        )

    # Check AWS-side ownership before doing any irreversible Entra work. Only
    # meaningful when both stages run in this process: a standalone `--stage 1`
    # legitimately has no AWS credentials (the split-admin workflow), and
    # --from-handoff skips Stage 1 entirely, so there is nothing to protect.
    if stage == "both" and not args.from_handoff:
        _preflight_aws_ownership(args, cfg, cs, connector_name, uses_cert=uses_cert)

    # --- Stage 1: Source-side (Entra) ----------------------------------------
    if stage in ("1", "both") and not args.from_handoff:
        print("\n── Stage 1: Source-side (Entra) ──")

        auth_method = args.auth_method or cfg.auth_method or "az"
        graph = GraphClient.from_auth(
            method=auth_method,
            tenant_id=tenant_id,
            device_client_id=args.device_client_id,
        )

        # App registration
        app_name = args.app_name or f"kb-connector-{connector_name}"
        existing = apps.find_application_by_name(graph, app_name)
        if existing:
            app_id = existing["appId"]
            object_id = existing["id"]
            sp = apps.ensure_service_principal(graph, app_id)
            reg = apps.AppRegistration(app_id, object_id, sp["id"])
            print(f"  Reusing existing app '{app_name}' (appId {app_id})")
        else:
            reg = apps.create_application(graph, app_name)
            print(f"  Created app '{app_name}' (appId {reg.app_id})")

        # Permissions + consent
        sites_sel = args.sites_selected or cfg.get("sites_selected", False)
        plan = permissions.build_plan(
            source=cfg.type,
            acl=acl,
            sites_selected=sites_sel,
            credential=credential,
        )
        grants = apps.resolve_grants(graph, plan)
        apps.grant_admin_consent(graph, reg.service_principal_id, grants)
        apps.declare_required_resource_access(graph, reg.object_id, grants)
        print(f"  Granted {len(grants)} permission(s) with admin consent")
        for note in plan.notes:
            print(f"    note: {note}")

        # Certificate
        cert_thumbprint = None
        cert_not_after = None
        p12_bytes = None
        cert_password = None
        private_key_b64 = None
        if uses_cert:
            cert_password = _secrets.token_urlsafe(24)
            cert = certs.generate_self_signed(
                common_name=app_name,
                valid_days=args.cert_valid_days,
                pkcs12_password=cert_password,
            )
            apps.upload_certificate(graph, reg.object_id, cert)
            cert_thumbprint = cert.thumbprint_b64url
            cert_not_after = cert.not_after
            p12_bytes = cert.pkcs12_bytes
            private_key_b64 = cert.private_key_b64_pkcs8
            print(f"  Generated + uploaded certificate (expires {cert.not_after})")

        # OneDrive needs a client secret even in cert mode (its ACL path mints a
        # Graph token with it), and the non-cert modes use it as the primary
        # credential. SharePoint cert auth doesn't use it: the certificate signs
        # both the Graph and SharePoint REST tokens.
        client_secret = None
        if not uses_cert or cfg.type == "onedrive":
            client_secret = apps.add_client_secret(graph, reg.object_id)
            print("  Created client secret")

        # Sites.Selected per-site grants
        if sites_sel and cfg.type == "sharepoint":
            site_urls = cfg.get("site_urls", [])
            if site_urls:
                admin_app_name = f"{app_name}-granter"
                admin = sites_selected.create_admin_granter_app(graph, admin_app_name)
                role = plan.site_role or "read"
                # The granter app holds SharePoint Sites.FullControl.All plus a
                # live client secret — the most privileged object this tool ever
                # creates. Its deletion must happen even when granting fails
                # partway (an unresolvable site URL is enough to raise), because
                # otherwise a failed run leaves a tenant-wide full-control app
                # with working credentials behind in the directory.
                try:
                    results = sites_selected.grant_sites(
                        tenant_id=tenant_id,
                        admin=admin,
                        connector_app_id=reg.app_id,
                        connector_app_name=app_name,
                        site_urls=site_urls,
                        role=role,
                    )
                    for r in results:
                        print(f"    granted {role} on {r['site_url']}")
                finally:
                    _delete_granter_app(graph, admin, admin_app_name)

        # Update state with source-side results
        cs.connector_type = cfg.type
        cs.tenant_id = tenant_id
        cs.client_app_id = reg.app_id
        cs.client_app_object_id = reg.object_id
        # `existing` is the app we found by display name rather than created.
        if existing:
            cs.record_external(state_mod.RESOURCE_APP)
        else:
            cs.record_owned(state_mod.RESOURCE_APP)
        cs.cert_thumbprint_b64url = cert_thumbprint
        cs.cert_not_after = cert_not_after

        # Stash secrets transiently for Stage 2 (not written to state file)
        cs._p12_bytes = p12_bytes  # type: ignore[attr-defined]
        cs._cert_password = cert_password  # type: ignore[attr-defined]
        cs._private_key_b64 = private_key_b64  # type: ignore[attr-defined]
        cs._client_secret = client_secret  # type: ignore[attr-defined]

        print("  Stage 1 complete")

    # Handle --from-handoff
    if args.from_handoff:
        _import_handoff(args.from_handoff, cs, cfg)

    # --- Stage 2: AWS-side ---------------------------------------------------
    if stage in ("2", "both"):
        print("\n── Stage 2: AWS-side ──")

        if not cfg.region:
            raise ConfigError("region is required for AWS-side setup.")

        session, account_id = _aws_session_and_account(cfg)
        opts = _provision_options(args, cfg)

        # Resolve names (shared with the ownership preflight above)
        names = _derive_aws_names(
            args, cfg, connector_name, account_id, uses_cert=uses_cert
        )
        secret_name = names["secret_name"]
        kb_role_name = names["kb_role_name"]
        cert_s3_bucket = names["cert_bucket"]
        cert_s3_key = names["cert_key"]
        if uses_cert and not (args.cert_s3_bucket or cfg.cert_s3_bucket):
            print(f"  No cert_s3_bucket configured; using default: {cert_s3_bucket}")

        # Get credential material (from Stage 1 or prior state)
        client_id = cs.client_app_id
        if not client_id:
            raise StateError(
                "No client_app_id in state. Run Stage 1 first, or use --from-handoff."
            )
        p12_bytes = getattr(cs, "_p12_bytes", None)
        cert_password = getattr(cs, "_cert_password", None)
        private_key_b64 = getattr(cs, "_private_key_b64", None)
        client_secret = getattr(cs, "_client_secret", None)

        # Stage 1 holds the freshly-created client secret only in memory;
        # secrets are never written to the state file. Run as separate
        # invocations (`--stage 1` then `--stage 2`), Stage 2 reloads state from
        # disk where the secret isn't present. This is caught here so the
        # failure is an actionable message rather than a ValueError from the
        # secret builder later. Cert mode is covered by the p12 check below;
        # this covers the non-cert app-only modes.
        if not uses_cert and not client_secret:
            raise StateError(
                "The client secret created in Stage 1 isn't available in this "
                "process. Client-secret and OAuth SharePoint/OneDrive setup "
                "requires Stage 1 and Stage 2 to run in the same process — "
                "re-run with `--stage both`. The secret is never written to the "
                "state file, so it can't cross a process or machine boundary."
            )

        # Upload certificate to S3
        if uses_cert:
            if not p12_bytes:
                raise StateError(
                    "Certificate material not available. Run Stage 1 in this "
                    "session, or re-run setup."
                )

            bucket_res = provisioning.ensure_cert_bucket(
                session=session,
                bucket=cert_s3_bucket,
                region=cfg.region,
                connector_name=connector_name,
                tags_enabled=opts.tags_enabled,
                extra_tags=opts.tags,
                adopt_existing=opts.adopt_existing,
                allow_unhardened=opts.allow_unhardened,
            )
            cs.record_ownership(
                state_mod.RESOURCE_CERT_BUCKET, bucket_res.state_marker
            )
            provisioning.upload_certificate_to_s3(
                session=session, bucket=cert_s3_bucket,
                key=cert_s3_key, pkcs12_bytes=p12_bytes,
                connector_name=connector_name,
                tags_enabled=opts.tags_enabled,
                extra_tags=opts.tags,
                kms_key_arn=opts.kms_key_arn,
            )
            print(f"  Uploaded certificate to s3://{cert_s3_bucket}/{cert_s3_key}")
            cs.cert_s3_bucket = cert_s3_bucket
            cs.cert_s3_key = cert_s3_key
            cs.record_owned(state_mod.RESOURCE_CERT)

        # Write the connector secret
        if cfg.type == "sharepoint":
            secret_body = sp_secret(
                credential=credential,
                client_id=client_id,
                client_secret=client_secret,
                certificate_password=cert_password,
                private_key_b64_pkcs8=private_key_b64,
            )
        else:  # onedrive
            secret_body = od_secret(
                credential=credential,
                client_id=client_id,
                client_secret=client_secret,
                certificate_password=cert_password,
                private_key_b64_pkcs8=private_key_b64,
            )

        secret_res = provisioning.put_secret(
            session=session, name=secret_name, body=secret_body,
            description=f"KB connector credentials for {connector_name}",
            connector_name=connector_name,
            tags_enabled=opts.tags_enabled,
            extra_tags=opts.tags,
            adopt_existing=opts.adopt_existing,
            kms_key_arn=opts.kms_key_arn,
            created_untagged=cs.created_untagged(state_mod.RESOURCE_SECRET),
        )
        secret_arn = secret_res.arn
        print(f"  Wrote secret: {secret_arn}")
        cs.secret_arn = secret_arn
        cs.record_ownership(state_mod.RESOURCE_SECRET, secret_res.state_marker)

        # IAM role
        kb_id = args.knowledge_base_id or cs.knowledge_base_id
        kb_role_arn = args.kb_role_arn or cs.kb_role_arn

        if kb_id and not args.no_create_kb_role:
            # Reusing existing KB — extend its role
            _extend_existing_kb_role(session, cfg, cs, kb_id, secret_arn,
                                    cert_s3_bucket, cert_s3_key, uses_cert,
                                    account_id=account_id, opts=opts)
        elif not args.no_create_kb_role:
            role_res = provisioning.ensure_kb_role(
                session=session,
                role_name=kb_role_name,
                account_id=account_id,
                region=cfg.region,
                secret_arn=secret_arn,
                cert_bucket=cert_s3_bucket if uses_cert else None,
                cert_key=cert_s3_key if uses_cert else None,
                cert_key_prefix=cfg.cert_s3_key_prefix if uses_cert else None,
                kms_key_arn=opts.kms_key_arn,
                connector_name=connector_name,
                tags_enabled=opts.tags_enabled,
                extra_tags=opts.tags,
                adopt_existing=opts.adopt_existing,
                created_untagged=cs.created_untagged(state_mod.RESOURCE_ROLE),
            )
            kb_role_arn = role_res.arn
            print(f"  Provisioned IAM role: {kb_role_arn}")
            cs.kb_role_arn = kb_role_arn
            cs.record_ownership(state_mod.RESOURCE_ROLE, role_res.state_marker)
            # IAM propagation
            print("  Waiting for IAM propagation...")
            time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
        elif kb_role_arn:
            # Operator supplied the role; the tool did not create it.
            cs.record_external(state_mod.RESOURCE_ROLE)

        # Create KB (if needed) + data source via the target abstraction
        target = _build_target(cfg, session)

        if cfg.type == "sharepoint":
            site_urls = cfg.get("site_urls", [])
            connector_params = sp_params(
                credential=credential,
                tenant_id=tenant_id,
                secret_arn=secret_arn,
                acl=acl,
                site_urls=site_urls,
                cert_s3_bucket=cert_s3_bucket if uses_cert else None,
                cert_s3_key=cert_s3_key if uses_cert else None,
                crawl_files=cfg.get("crawl_files", True),
                crawl_pages=cfg.get("crawl_pages", True),
                filter_config=sp_filter_config(cfg),
            )
        else:  # onedrive
            connector_params = od_params(
                credential=credential,
                tenant_id=tenant_id,
                secret_arn=secret_arn,
                acl=acl,
                cert_s3_bucket=cert_s3_bucket if uses_cert else None,
                cert_s3_key=cert_s3_key if uses_cert else None,
                crawl_personal_drives=cfg.get("crawl_personal_drives", True),
                crawl_shared_with_me=cfg.get("crawl_shared_with_me", False),
                inclusion_user_emails=cfg.get("inclusion_user_emails"),
            )

        _provision_kb_and_ds(
            target=target,
            args=args,
            cfg=cfg,
            cs=cs,
            connector_name=connector_name,
            kb_role_arn=kb_role_arn,
            connector_parameters=connector_params,
        )

        print("  Stage 2 complete")


def _delete_granter_app(graph, admin, admin_app_name: str) -> None:
    """Delete the temporary Sites.Selected granter app.

    Runs in a finally block, so it must not mask the original exception: a
    failure here is reported loudly with the manual cleanup command rather than
    raised. Leaving this app in place is a real finding — it carries
    Sites.FullControl.All and a client secret valid for two days.
    """
    try:
        graph.delete(f"/applications/{admin.object_id}")
        print(f"  Deleted temporary granter app '{admin_app_name}'")
    except Exception as exc:  # noqa: BLE001 - must not mask the original error
        print(
            f"\n  !! COULD NOT DELETE the temporary granter app "
            f"'{admin_app_name}' (object id {admin.object_id}): {exc}\n"
            f"  !! This app holds SharePoint Sites.FullControl.All and a client "
            f"secret valid for ~2 days. Delete it now:\n"
            f"  !!   az ad app delete --id {admin.object_id}\n"
            f"  !! or in the Entra portal: App registrations -> "
            f"'{admin_app_name}' -> Delete.",
            file=sys.stderr,
        )


def _extend_existing_kb_role(
    session, cfg, cs, kb_id, secret_arn, cert_s3_bucket, cert_s3_key, uses_cert,
    *, account_id=None, opts=None,
):
    """Extend an existing KB's role to cover the new secret + cert.

    The role belongs to a knowledge base the operator pointed us at, so it is
    recorded as external: teardown must never delete a role that predates this
    connector and may be shared with other data sources on the same KB.
    """
    from kb_connector.core import provisioning

    target = _build_target(cfg, session)
    try:
        resp = target.get_knowledge_base(kb_id)
        kb_obj = resp.get("knowledgeBase", resp)
        role_arn = kb_obj.get("roleArn")
    except Exception as exc:
        print(f"  WARNING: could not read KB {kb_id} to discover role: {exc}")
        return

    if not role_arn:
        print(f"  WARNING: KB {kb_id} has no roleArn; skipping role extension.")
        return

    # Extract role name from ARN
    role_name = role_arn.split(":role/")[-1].rsplit("/", 1)[-1]
    print(f"  Extending existing KB role: {role_name}")

    try:
        summary = provisioning.extend_kb_role_for_secret(
            session=session,
            role_name=role_name,
            secret_arn=secret_arn,
            cert_bucket=cert_s3_bucket if uses_cert else None,
            cert_key=cert_s3_key if uses_cert else None,
            cert_key_prefix=cfg.cert_s3_key_prefix if uses_cert else None,
            account_id=account_id,
            region=cfg.region,
            kms_key_arn=opts.kms_key_arn if opts else None,
        )
        if summary["secret_added"] or summary["cert_added"]:
            print(f"  Extended role policy ({', '.join(summary['policies_updated'])})")
            time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
        else:
            print("  Role policy already covers these credentials")
    except AwsError as exc:
        print(f"  WARNING: could not extend role: {exc}")

    cs.kb_role_arn = role_arn
    cs.record_external(state_mod.RESOURCE_ROLE)


def _import_handoff(handoff_path: str, cs: ConnectorState, cfg: ConnectorConfig) -> None:
    """Import a handoff file into connector state.

    The document is validated by handoff.parse_handoff before anything is
    copied into state: it arrives from another admin, every field becomes
    connector state, and `secret_arn` in particular later becomes the target
    of a force-delete during teardown.
    """
    from kb_connector.core.handoff import (
        DIRECTION_AWS_TO_SOURCE,
        DIRECTION_SOURCE_TO_AWS,
        parse_handoff,
    )

    if not os.path.isfile(handoff_path):
        raise ConfigError(f"Handoff file not found: {handoff_path}")
    try:
        with open(handoff_path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Failed to read handoff file: {exc}") from exc

    handoff = parse_handoff(raw)
    direction = handoff["direction"]

    if direction == DIRECTION_SOURCE_TO_AWS:
        # Source admin completed Stage 1; we have source-side details
        source = handoff.get("source", {})
        cs.tenant_id = source.get("tenant_id") or cs.tenant_id
        cs.client_app_id = source.get("client_id") or cs.client_app_id
        cs.connector_type = handoff.get("type") or cs.connector_type
        # Cert material would need to come from the file referenced in handoff
        print("  Imported handoff (direction: source -> AWS)")
    elif direction == DIRECTION_AWS_TO_SOURCE:
        aws = handoff.get("aws", {})
        cs.knowledge_base_id = aws.get("knowledge_base_id") or cs.knowledge_base_id
        cs.data_source_id = aws.get("data_source_id") or cs.data_source_id
        cs.secret_arn = aws.get("secret_arn") or cs.secret_arn
        cs.region = aws.get("region") or cs.region
        print("  Imported handoff (direction: AWS -> source)")
    else:  # pragma: no cover - parse_handoff restricts direction to the two above
        raise ConfigError(f"Unsupported handoff direction {direction!r}.")


# --- S3 connector setup (no provider) ----------------------------------------


def _setup_s3(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    stage: str,
) -> None:
    """S3 connector setup — AWS-side only (no provider needed)."""
    if stage == "1":
        print("  S3 connector has no source-side setup; skipping Stage 1.")
        return

    print("\n── AWS-side setup (S3) ──")

    from kb_connector.connectors.s3 import build_connector_params as s3_params
    from kb_connector.core import provisioning

    if not cfg.region:
        raise ConfigError("region is required for AWS-side setup.")

    session, account_id = _aws_session_and_account(cfg)
    opts = _provision_options(args, cfg)

    cs.connector_type = "s3"

    # S3 connector needs no secret for basic setup (no auth).
    # ACL mode uses a globalAccessControlListS3Uri reference, not a secret.
    bucket_name = cfg.get("bucket_name")
    if not bucket_name:
        raise ConfigError("bucket_name is required for S3 connector.")

    # IAM role
    kb_id = args.knowledge_base_id or cs.knowledge_base_id
    kb_role_arn = args.kb_role_arn or cs.kb_role_arn
    kb_role_name = args.kb_role_name or _derived_name(
        cfg, f"kb-connector-{connector_name}-role"
    )

    if not kb_id and not args.no_create_kb_role and not kb_role_arn:
        # S3 connector: role needs s3:GetObject on the content bucket
        role_res = provisioning.ensure_kb_role(
            session=session,
            role_name=kb_role_name,
            account_id=account_id,
            region=cfg.region,
            secret_arn=None,  # no secret for S3
            cert_bucket=None,
            cert_key=None,
            kms_key_arn=opts.kms_key_arn,
            connector_name=connector_name,
            tags_enabled=opts.tags_enabled,
            extra_tags=opts.tags,
            adopt_existing=opts.adopt_existing,
            created_untagged=cs.created_untagged(state_mod.RESOURCE_ROLE),
        )
        kb_role_arn = role_res.arn
        # Add S3 read permissions for the content bucket
        _add_s3_content_policy(
            session, kb_role_name, bucket_name, account_id,
            inclusion_prefixes=cfg.get("inclusion_prefixes"),
        )
        print(f"  Provisioned IAM role: {kb_role_arn}")
        cs.kb_role_arn = kb_role_arn
        cs.record_ownership(state_mod.RESOURCE_ROLE, role_res.state_marker)
        print("  Waiting for IAM propagation...")
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
    elif kb_role_arn:
        cs.record_external(state_mod.RESOURCE_ROLE)

    # Create KB + S3 data source (managed-connector envelope, same as others)
    target = _build_target(cfg, session)
    connector_params = s3_params(
        bucket_name=bucket_name,
        # bucketOwnerAccountId is required by the service; default to the
        # caller's account for the common same-account case.
        bucket_owner_account_id=cfg.get("bucket_owner_account_id") or account_id,
        acl=cfg.acl,
        acl_s3_uri=cfg.get("acl_s3_uri"),
        inclusion_prefixes=cfg.get("inclusion_prefixes"),
        exclusion_prefixes=cfg.get("exclusion_prefixes"),
        inclusion_patterns=cfg.get("inclusion_patterns"),
        exclusion_patterns=cfg.get("exclusion_patterns"),
        max_file_size_mb=cfg.get("max_file_size_mb"),
        metadata_files_prefix=cfg.get("metadata_files_prefix"),
    )
    _provision_kb_and_ds(
        target=target,
        args=args,
        cfg=cfg,
        cs=cs,
        connector_name=connector_name,
        kb_role_arn=kb_role_arn,
        connector_parameters=connector_params,
    )
    print("  S3 setup complete")


def _resolve_web_basic_auth(
    cfg: ConnectorConfig, args: argparse.Namespace
) -> tuple[str | None, str | None]:
    """Get the web connector's basic-auth credentials, preferring a prompt.

    Reading these straight out of kb-connector.toml would put a live password in
    a plaintext file that sits in the project directory, next to the config an
    operator is likely to share or copy. Every other connector collects its
    secrets with getpass, so this one does too.

    A config-supplied password still works — some callers run unattended — but
    it warns, because the file it came from is not a credential store. In
    --non-interactive mode config is the only option, so a missing value is a
    configuration error rather than a hang on a prompt.
    """
    username = cfg.get("username")
    password = cfg.get("password")
    non_interactive = getattr(args, "non_interactive", False)

    if password:
        print(
            "  WARNING: using the basic-auth password from kb-connector.toml. "
            "That file is not a credential store — prefer omitting `password` "
            "and entering it when prompted, or move this connector to a secret "
            "you manage.",
            file=sys.stderr,
        )
        return username, password

    if non_interactive:
        raise ConfigError(
            "Web connector with basic_auth needs a password, and "
            "--non-interactive prevents prompting. Set `password` in config for "
            "this connector, or run without --non-interactive to be prompted."
        )

    print("  Basic-auth credentials for the crawl target:")
    if not username:
        username = input("    Username: ").strip()
    else:
        print(f"    Username: {username} (from config)")
    password = getpass("    Password (hidden): ").strip()
    if not (username and password):
        raise ConfigError("Both username and password are required for basic_auth.")
    return username, password


def _add_s3_content_policy(
    session,
    role_name: str,
    bucket_name: str,
    account_id: str,
    *,
    inclusion_prefixes: list[str] | None = None,
) -> None:
    """Add S3 read permissions for the content bucket to the KB role.

    Scoped to `inclusion_prefixes` when the connector declares them. The crawl
    is already prefix-limited via the data source configuration, so granting
    s3:GetObject on the whole bucket would give the role standing read access
    to objects it will never crawl — a wider grant than the connector's own
    configuration implies. With no prefixes configured the crawl really is
    bucket-wide, so the grant matches it.
    """
    import json as _json
    iam = session.client("iam")
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    prefixes = [p.strip().lstrip("/") for p in (inclusion_prefixes or []) if p.strip()]
    if prefixes:
        get_resources = [f"{bucket_arn}/{p.rstrip('/')}/*" for p in prefixes]
        list_condition = {
            "StringEquals": {"aws:ResourceAccount": [account_id]},
            "StringLike": {"s3:prefix": [f"{p.rstrip('/')}/*" for p in prefixes]},
        }
    else:
        get_resources = [f"{bucket_arn}/*"]
        list_condition = {"StringEquals": {"aws:ResourceAccount": [account_id]}}

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ContentBucketListStatement",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [bucket_arn],
                "Condition": list_condition,
            },
            {
                "Sid": "S3ContentBucketGetStatement",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": get_resources,
                "Condition": {"StringEquals": {"aws:ResourceAccount": [account_id]}},
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="kb-connector-s3-content-access",
        PolicyDocument=_json.dumps(policy),
    )
    if prefixes:
        print(f"  S3 read scoped to prefix(es): {', '.join(prefixes)}")


# --- Web connector setup (no provider for NO_AUTH) ----------------------------


def _setup_web(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    stage: str,
) -> None:
    """Web connector setup — AWS-side only for NO_AUTH, secret for BASIC_AUTH."""
    if stage == "1":
        auth_mode = cfg.get("auth_mode", "no_auth")
        if auth_mode == "no_auth":
            print("  Web connector (NO_AUTH) has no source-side setup; skipping Stage 1.")
        else:
            print(f"  Web connector ({auth_mode}) — ensure credentials are ready.")
        return

    print("\n── AWS-side setup (Web) ──")

    from kb_connector.connectors.web import build_connector_params as web_params, build_secret_body as web_secret
    from kb_connector.core import provisioning

    if not cfg.region:
        raise ConfigError("region is required for AWS-side setup.")

    session, account_id = _aws_session_and_account(cfg)
    opts = _provision_options(args, cfg)

    cs.connector_type = "web"

    seed_urls = cfg.get("seed_urls", [])
    sitemap_urls = cfg.get("sitemap_urls")
    if not seed_urls and not sitemap_urls:
        raise ConfigError("Web connector requires seed_urls or sitemap_urls.")

    auth_mode = cfg.get("auth_mode", "no_auth")
    secret_arn = None

    # Write secret if needed (BASIC_AUTH)
    if auth_mode != "no_auth":
        username, password = _resolve_web_basic_auth(cfg, args)
        secret_body = web_secret(
            auth_mode=auth_mode,
            username=username,
            password=password,
        )
        if secret_body:
            secret_name = args.secret_name or _derived_name(
                cfg, f"kb-connector/{connector_name}-credentials"
            )
            secret_res = provisioning.put_secret(
                session=session, name=secret_name, body=secret_body,
                description=f"KB connector credentials for {connector_name} (web)",
                connector_name=connector_name,
                tags_enabled=opts.tags_enabled,
                extra_tags=opts.tags,
                adopt_existing=opts.adopt_existing,
                kms_key_arn=opts.kms_key_arn,
                created_untagged=cs.created_untagged(state_mod.RESOURCE_SECRET),
            )
            secret_arn = secret_res.arn
            print(f"  Wrote secret: {secret_arn}")
            cs.secret_arn = secret_arn
            cs.record_ownership(state_mod.RESOURCE_SECRET, secret_res.state_marker)

    # IAM role
    kb_id = args.knowledge_base_id or cs.knowledge_base_id
    kb_role_arn = args.kb_role_arn or cs.kb_role_arn
    kb_role_name = args.kb_role_name or _derived_name(
        cfg, f"kb-connector-{connector_name}-role"
    )

    if not kb_id and not args.no_create_kb_role and not kb_role_arn:
        role_res = provisioning.ensure_kb_role(
            session=session,
            role_name=kb_role_name,
            account_id=account_id,
            region=cfg.region,
            secret_arn=secret_arn,
            cert_bucket=None,
            cert_key=None,
            kms_key_arn=opts.kms_key_arn,
            connector_name=connector_name,
            tags_enabled=opts.tags_enabled,
            extra_tags=opts.tags,
            adopt_existing=opts.adopt_existing,
            created_untagged=cs.created_untagged(state_mod.RESOURCE_ROLE),
        )
        kb_role_arn = role_res.arn
        print(f"  Provisioned IAM role: {kb_role_arn}")
        cs.kb_role_arn = kb_role_arn
        cs.record_ownership(state_mod.RESOURCE_ROLE, role_res.state_marker)
        print("  Waiting for IAM propagation...")
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
    elif kb_role_arn:
        cs.record_external(state_mod.RESOURCE_ROLE)

    # Create KB + Web data source via the target abstraction
    target = _build_target(cfg, session)
    connector_params = web_params(
        seed_urls=seed_urls,
        auth_mode=auth_mode,
        secret_arn=secret_arn,
        sitemap_urls=sitemap_urls,
        crawl_depth=cfg.get("crawl_depth"),
        max_links_per_url=cfg.get("max_links_per_url"),
        max_crawled_urls_per_minute=cfg.get("max_crawled_urls_per_minute"),
        sync_scope=cfg.get("sync_scope"),
        crawl_attachments=cfg.get("crawl_attachments", False),
        max_file_size_mb=cfg.get("max_file_size_mb"),
        inclusion_filters=cfg.get("inclusion_filters"),
        exclusion_filters=cfg.get("exclusion_filters"),
    )
    _provision_kb_and_ds(
        target=target,
        args=args,
        cfg=cfg,
        cs=cs,
        connector_name=connector_name,
        kb_role_arn=kb_role_arn,
        connector_parameters=connector_params,
    )
    print("  Web setup complete")


# --- Guided connector setup (Confluence / Google Drive) -----------------------


def _setup_guided(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    stage: str,
    connector_type: str,
) -> None:
    """Guided setup for connectors that need manual 3P configuration.

    Stage 1: Print instructions, wait for user to confirm, validate.
    Stage 2: Write secret + create AWS resources (automated).
    """
    from kb_connector.connectors.confluence import (
        ConfluenceConnector,
        build_connector_params as conf_params,
        build_secret_body as conf_secret,
    )
    from kb_connector.connectors.googledrive import (
        GoogleDriveConnector,
        build_connector_params as gd_params,
        build_secret_body as gd_secret,
    )
    from kb_connector.core import provisioning

    cs.connector_type = connector_type

    # --- Stage 1: Guided source-side setup -----------------------------------
    if stage in ("1", "both"):
        print(f"\n── Stage 1: Source-side ({connector_type}) — GUIDED ──")

        if connector_type == "confluence":
            connector_impl = ConfluenceConnector()
        else:
            connector_impl = GoogleDriveConnector()

        steps = connector_impl.setup_steps(cfg.raw)
        for step in steps:
            print(f"\n  Step: {step.description}")
            step.execute(cfg.raw)

            # Prompt user to confirm they've completed the step
            print("  When you've completed the steps above, provide the credentials:")
            # Secret values are read with getpass so they don't echo to the
            # terminal or persist in scrollback. Identifiers and file paths are
            # not secrets and stay on input().
            if connector_type == "confluence":
                cred = cfg.get("credential", "oauth2")
                if cred == "oauth2":
                    cs._client_id = input("    Client ID: ").strip()  # type: ignore[attr-defined]
                    cs._client_secret = getpass("    Client Secret (hidden): ").strip()  # type: ignore[attr-defined]
                else:
                    cs._username = input("    Username/Email: ").strip()  # type: ignore[attr-defined]
                    cs._api_token = getpass("    API Token (hidden): ").strip()  # type: ignore[attr-defined]
            else:  # googledrive
                cred = cfg.get("credential", "oauth2")
                if cred == "service_account":
                    sa_path = input("    Service account JSON file path: ").strip()
                    with open(sa_path, encoding="utf-8") as f:
                        cs._sa_json = f.read()  # type: ignore[attr-defined]
                else:
                    cs._client_id = input("    Client ID: ").strip()  # type: ignore[attr-defined]
                    cs._client_secret = getpass("    Client Secret (hidden): ").strip()  # type: ignore[attr-defined]
                    cs._refresh_token = getpass("    Refresh Token (hidden): ").strip()  # type: ignore[attr-defined]

        print("  Stage 1 complete (credentials collected)")

    # --- Stage 2: AWS-side ---------------------------------------------------
    if stage in ("2", "both"):
        print(f"\n── Stage 2: AWS-side ({connector_type}) ──")

        if not cfg.region:
            raise ConfigError("region is required for AWS-side setup.")

        session, account_id = _aws_session_and_account(cfg)
        opts = _provision_options(args, cfg)

        # Write secret
        secret_name = args.secret_name or _derived_name(
            cfg, f"kb-connector/{connector_name}-credentials"
        )
        if connector_type == "confluence":
            cred = cfg.get("credential", "oauth2")
            secret_body = conf_secret(
                credential=cred,
                client_id=getattr(cs, "_client_id", None),
                client_secret=getattr(cs, "_client_secret", None),
                username=getattr(cs, "_username", None),
                api_token=getattr(cs, "_api_token", None),
            )
        else:  # googledrive
            cred = cfg.get("credential", "oauth2")
            secret_body = gd_secret(
                credential=cred,
                client_id=getattr(cs, "_client_id", None),
                client_secret=getattr(cs, "_client_secret", None),
                refresh_token=getattr(cs, "_refresh_token", None),
                service_account_json=getattr(cs, "_sa_json", None),
            )

        secret_res = provisioning.put_secret(
            session=session, name=secret_name, body=secret_body,
            description=f"KB connector credentials for {connector_name} ({connector_type})",
            connector_name=connector_name,
            tags_enabled=opts.tags_enabled,
            extra_tags=opts.tags,
            adopt_existing=opts.adopt_existing,
            kms_key_arn=opts.kms_key_arn,
            created_untagged=cs.created_untagged(state_mod.RESOURCE_SECRET),
        )
        secret_arn = secret_res.arn
        print(f"  Wrote secret: {secret_arn}")
        cs.secret_arn = secret_arn
        cs.record_ownership(state_mod.RESOURCE_SECRET, secret_res.state_marker)

        # IAM role
        kb_id = args.knowledge_base_id or cs.knowledge_base_id
        kb_role_arn = args.kb_role_arn or cs.kb_role_arn
        kb_role_name = args.kb_role_name or _derived_name(
            cfg, f"kb-connector-{connector_name}-role"
        )

        if not kb_id and not args.no_create_kb_role and not kb_role_arn:
            role_res = provisioning.ensure_kb_role(
                session=session,
                role_name=kb_role_name,
                account_id=account_id,
                region=cfg.region,
                secret_arn=secret_arn,
                cert_bucket=None,
                cert_key=None,
                kms_key_arn=opts.kms_key_arn,
                connector_name=connector_name,
                tags_enabled=opts.tags_enabled,
                extra_tags=opts.tags,
                adopt_existing=opts.adopt_existing,
                created_untagged=cs.created_untagged(state_mod.RESOURCE_ROLE),
            )
            kb_role_arn = role_res.arn
            print(f"  Provisioned IAM role: {kb_role_arn}")
            cs.kb_role_arn = kb_role_arn
            cs.record_ownership(state_mod.RESOURCE_ROLE, role_res.state_marker)
            print("  Waiting for IAM propagation...")
            time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
        elif kb_role_arn:
            cs.record_external(state_mod.RESOURCE_ROLE)

        # Create KB + data source via the target abstraction
        target = _build_target(cfg, session)

        if connector_type == "confluence":
            connector_params = conf_params(
                host_url=cfg.get("host_url", ""),
                credential=cfg.get("credential", "oauth2"),
                secret_arn=secret_arn,
                acl=cfg.acl,
                hosting_type=cfg.get("hosting_type", "SAAS"),
                space_keys=cfg.get("space_keys"),
            )
        else:  # googledrive
            connector_params = gd_params(
                credential=cfg.get("credential", "oauth2"),
                secret_arn=secret_arn,
                acl=cfg.acl,
                shared_drive_ids=cfg.get("shared_drives"),
            )

        _provision_kb_and_ds(
            target=target,
            args=args,
            cfg=cfg,
            cs=cs,
            connector_name=connector_name,
            kb_role_arn=kb_role_arn,
            connector_parameters=connector_params,
        )
        print(f"  {connector_type.title()} setup complete")
