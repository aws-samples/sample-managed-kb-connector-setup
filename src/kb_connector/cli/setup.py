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
from typing import TYPE_CHECKING, Any

from kb_connector.connectors import get_spec
from kb_connector.connectors.base import BuildContext, ConnectorSpec
from kb_connector.core import overrides as request_overrides
from kb_connector.core import state as state_mod
from kb_connector.core.diagnostics import describe_endpoints
from kb_connector.core.knowledge_base import build_data_source_payload

from kb_connector.core.config import ConnectorConfig, load_config
from kb_connector.core.errors import (
    AwsError,
    ConfigError,
    ConnectorError,
    ProviderError,
    StateError,
)
from kb_connector.core.state import ConnectorState, load_state, save_state

if TYPE_CHECKING:
    # Annotation-only: boto3 and the Graph provider stay off the import path
    # for --help and pure-logic runs.
    from boto3 import Session

    from kb_connector.providers.microsoft.apps import AppRegistration
    from kb_connector.providers.microsoft.client import GraphClient
    from kb_connector.providers.microsoft.sites_selected import AdminAppCredentials
    from kb_connector.quick.client import QuickClient
    from kb_connector.targets.base import Target


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the setup subcommand."""
    parser = subparsers.add_parser(
        "setup",
        help="Set up a connector (source-side identity + AWS resources)",
        description=(
            "Run the full setup flow for a connector: Stage 1 (source-side identity "
            "provider) and Stage 2 (AWS resources; with target = 'quick', the "
            "Amazon Quick data source and knowledge base). Resumable — re-running "
            "skips completed steps."
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
    parser.add_argument("--cert-valid-days", type=int,
                        default=_DEFAULT_CERT_VALID_DAYS,
                        help=(
                            f"Certificate validity in days (default: "
                            f"{_DEFAULT_CERT_VALID_DAYS}). Can also be set as "
                            f"cert_valid_days in config."
                        ))
    parser.add_argument("--rotate-cert", action="store_true",
                        help="Issue a new certificate instead of keeping the "
                             "one already installed on the app. Replaces the "
                             "app's certificate and rewrites the secret and the "
                             "S3 copy, so an ingestion running at the time will "
                             "fail to authenticate; start it when no crawl is "
                             "in flight.")
    parser.add_argument("--sites-selected", action="store_true",
                        help="Use Sites.Selected (SharePoint least-privilege)")
    # AWS-side options
    parser.add_argument("--knowledge-base-id", "--kb", metavar="KB_ID",
                        help=(
                            "Reuse an existing KB (skip KB creation). With "
                            "target = 'quick', a Quick knowledge base whose data "
                            "source uses this connector's Entra app; both are "
                            "recorded and nothing is created."
                        ))
    parser.add_argument("--kb-name",
                        help="Name for a new Bedrock or Quick KB (default: auto)")
    parser.add_argument("--kb-role-name", help="IAM role name for the KB")
    parser.add_argument("--kb-role-arn", help="Use an existing IAM role ARN")
    parser.add_argument("--secret-name", help="Secrets Manager secret name")
    parser.add_argument("--cert-s3-bucket", help="S3 bucket for certificate")
    parser.add_argument("--cert-s3-key", help="S3 key for certificate")
    parser.add_argument("--ds-name",
                        help="Name for a new Bedrock or Quick data source (default: auto)")
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
        "--target", choices=sorted(_target_choices()),
        help=(
            "Which control plane creates the knowledge base: 'bmkb' (Bedrock "
            "managed KB, the default) or 'quick' (Amazon Quick: creates the "
            "Quick data source and knowledge base). Overrides the target set in "
            "config."
        ),
    )
    parser.add_argument(
        "--signing-key-arn",
        help=(
            "[--target quick] Existing KMS asymmetric signing key (RSA_2048, "
            "SIGN_VERIFY) to sign Entra assertions with. Default is to create "
            "one. Not the same thing as --kms-key-arn, which encrypts."
        ),
    )
    parser.add_argument(
        "--signing-key-alias",
        help=(
            "[--target quick] Alias for the KMS signing key this tool creates "
            "(default: derived from the connector name). Ignored when "
            "--signing-key-arn names an existing key."
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


# Shorter than the Quick guide's 730-day example. The certificate is a public
# wrapper around a key that outlives it, so reissuing costs one Entra upload and
# no change to the KMS key ARN or to Quick's configuration, which makes a
# shorter default cheap. Override per connector with cert_valid_days.
_DEFAULT_CERT_VALID_DAYS = 365


def _target_choices() -> frozenset[str]:
    """Target names for the --target flag.

    Read from targets.TARGET_NAMES rather than repeated here, so adding a target
    does not leave the flag silently rejecting it. Imported inside the function
    to keep `--help` off the import path of anything heavier.
    """
    from kb_connector.targets import TARGET_NAMES
    return TARGET_NAMES


def run(args: argparse.Namespace) -> int:
    """Execute the setup subcommand."""
    return _run_setup(args)


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
    for line in describe_endpoints(session, cfg.region):
        print(f"  {line}")
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
    if getattr(args, "target", None):
        cli_overrides["target"] = args.target
    if getattr(args, "signing_key_arn", None):
        cli_overrides["signing_key_arn"] = args.signing_key_arn
    if getattr(args, "signing_key_alias", None):
        cli_overrides["signing_key_alias"] = args.signing_key_alias

    try:
        cfg = config.resolve_connector(connector_name, cli_overrides=cli_overrides)
    except ConfigError:
        # Maybe they passed connector name directly without a config file
        raise

    cs = state_file.get(connector_name)
    stage = args.stage

    # Recorded for every connector, not just Quick: teardown and monitor resolve
    # the control plane from state, because a knowledge base id alone does not
    # say which service holds it.
    cs.target = cfg.target
    _record_region(cs, cfg)

    print(f"Setting up connector: {connector_name} (type: {cfg.type})")
    print(f"  region: {cfg.region or 'default'}")
    if cfg.target != "bmkb":
        print(f"  target: {cfg.target}")

    # Checked before any Graph or AWS call, so a malformed or misspelled
    # override, or a value the service rejects, fails here rather than after
    # resources exist.
    if cfg.target == "bmkb":
        loaded_overrides = request_overrides.load(cfg.raw)
        request_overrides.check_against_model(loaded_overrides)
        spec = get_spec(cfg.type)
        if spec is not None:
            spec.check(cfg, loaded_overrides)

    # Dispatch to the appropriate setup path. Persist state in a finally block
    # so that resources created before a mid-flight failure are still tracked
    # (and therefore cleanable by `teardown`). Setup is resumable: re-running
    # reads this state and skips completed steps.
    failed = False
    unfinished: str | None = None
    try:
        if cfg.type in ("sharepoint", "onedrive"):
            unfinished = _setup_microsoft(args, cfg, cs, connector_name, stage)
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

    if unfinished:
        # Exit 0: the first Quick run always stops here, because the console
        # step needs the key ARN this run created, and scripts written for
        # credential-only Quick setup expect 0.
        print(f"Setup is not finished: {unfinished}")
        return 0

    print("Setup complete.")

    if cfg.target == "quick":
        # No ingestion to start: Quick has no sync API.
        if args.sync:
            print(
                "\n  NOTE: --sync has no effect with target = 'quick'. Quick "
                "starts the first sync itself after it creates the knowledge "
                "base.",
                file=sys.stderr,
            )
        print(f"  Next: kb-connector validate {connector_name}")
        return 0

    if args.sync:
        return _run_sync(args, connector_name)

    print(f"  Next: kb-connector monitor {connector_name}    # start ingestion + watch it")
    return 0


# State fields naming a regional AWS resource. If any is set, state already
# records where this connector lives.
_REGIONAL_STATE_FIELDS = (
    "knowledge_base_id", "data_source_id", "secret_arn", "cert_s3_key",
    "signing_key_arn",
)


def _record_region(cs: ConnectorState, cfg: ConnectorConfig) -> None:
    """Record the region this run creates resources in, before it creates any.

    Teardown deletes in the region state records, so it is recorded before the
    first resource exists and a run that fails at any step leaves it set.

    A run whose region differs from the one state already records is refused:
    it would create resources in one region while state tracks others in
    another, and teardown can only reach one of them.
    """
    if not cfg.region:
        return
    tracked = any(getattr(cs, f) for f in _REGIONAL_STATE_FIELDS)
    if tracked and cs.region and cs.region != cfg.region:
        raise ConfigError(
            f"State records this connector's resources in {cs.region}, but this "
            f"run would use {cfg.region}. Tear the connector down first "
            f"(kb-connector teardown {cfg.name} --region {cs.region}), use a "
            f"different connector name for the new region, or set region back "
            f"to {cs.region}."
        )
    cs.region = cfg.region


def _spec(cfg: ConnectorConfig) -> ConnectorSpec:
    spec = get_spec(cfg.type)
    if spec is None:
        raise ConfigError(f"Connector type {cfg.type!r} setup not yet implemented.")
    return spec


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


def _build_target(cfg: ConnectorConfig, session: Session) -> Target:
    """Construct the control-plane target for this connector's config."""
    from kb_connector.targets import get_target
    return get_target(cfg.target, session=session, region=cfg.region)


def _provision_kb_and_ds(
    *,
    target: Target,
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    kb_role_arn: str | None,
    connector_parameters: dict,
) -> None:
    """Create-or-reuse the KB, then create the DS and wait for AVAILABLE.

    Routes every control-plane call through the Target so a different backend
    (e.g. Quick) can be swapped in without touching this logic. Updates
    connector state (cs) in place.

    The connector's request overrides (core.overrides) deep-merge into the
    CreateKnowledgeBase and CreateDataSource bodies. They apply when a
    resource is created; a reused KB or data source is left as it is.
    """
    kb_id = args.knowledge_base_id or cs.knowledge_base_id
    overrides = request_overrides.load(cfg.raw)

    if not kb_id:
        if not kb_role_arn:
            raise ConfigError(
                "No KB role available. Provide --kb-role-arn or let the tool create one."
            )
        kb_name = args.kb_name or f"kb-connector-{connector_name}"
        created = _create_knowledge_base(
            target, args, cfg, connector_name,
            name=kb_name, role_arn=kb_role_arn,
            overrides=overrides.create_knowledge_base,
        )
        kb_obj = created.get("knowledgeBase", created)
        kb_id = kb_obj.get("knowledgeBaseId") or kb_obj.get("id")
        print(f"  Created knowledge base: {kb_id}")
        # Recorded before the wait, as the data source is below, so a timeout or
        # FAILED status leaves the KB tracked for teardown and for the next run.
        # An encrypted KB can take more than five minutes to become ACTIVE.
        cs.knowledge_base_id = kb_id
        cs.record_owned(state_mod.RESOURCE_KB)
        cs.region = cfg.region
        print("  Waiting for KB to become ACTIVE...")
        target.wait_until_kb_active(kb_id)
        print("  KB is ACTIVE")
    else:
        # `kb_id` came from --kb or from state. If the operator pointed us at
        # this KB it predates the connector and may carry other data sources, so
        # recording it external is what stops a later teardown from deleting
        # someone else's knowledge base. But a re-run reads the id back out of
        # state, and disowning a KB this tool created strands it: teardown
        # reports it as pre-existing and skips it.
        if _record_reused_resource(cs, state_mod.RESOURCE_KB, kb_id):
            print(f"  Using existing KB: {kb_id}")
        else:
            print(
                f"  Using existing KB: {kb_id} "
                f"(external — teardown will not delete it)"
            )
        if overrides.create_knowledge_base:
            print(
                "  NOTE: overrides.create_knowledge_base applies only when the "
                "knowledge base is created; the existing one is unchanged."
            )

    cs.knowledge_base_id = kb_id

    ds_name = args.ds_name or f"{connector_name}-ds"

    # If a data source is already tracked in state, reconcile it before
    # creating a new one. A data source in a terminal-bad state is neither
    # complete nor recoverable, so it's recreated rather than reused.
    existing_ds_id = cs.data_source_id
    if existing_ds_id:
        reuse_id = _reconcile_existing_data_source(target, kb_id, existing_ds_id)
        if reuse_id:
            print(f"  Reusing existing data source: {reuse_id} (AVAILABLE)")
            if overrides.create_data_source:
                print(
                    "  NOTE: data source overrides apply only when the data "
                    "source is created. To apply changes, run `teardown --only "
                    "ds` and then setup again."
                )
            cs.data_source_id = reuse_id
            cs.region = cfg.region
            return

    payload = build_data_source_payload(
        name=ds_name, connector_parameters=connector_parameters
    )
    if overrides.create_data_source:
        payload = request_overrides.deep_merge(payload, overrides.create_data_source)
        print("  Applied data source overrides")
    ds_id = _create_data_source_with_diagnostics(
        target=target, kb_id=kb_id, ds_name=ds_name, payload=payload,
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


def _create_knowledge_base(
    target: Target,
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    connector_name: str,
    *,
    name: str,
    role_arn: str,
    overrides: dict,
) -> Any:
    """Create the knowledge base with the ownership and operator tags.

    Tagging on create needs bedrock:TagResource. If that is denied, the KB
    is created untagged with a warning, as the role and secret are. Tags from
    `overrides.create_knowledge_base` are dropped on that retry too.
    `--no-tags` sends no tool tags at all.
    """
    from kb_connector.core.tagging import (
        build_tag_dict,
        is_tagging_access_error,
        validate_extra_tags,
    )

    kms_key_arn = getattr(args, "kms_key_arn", None) or cfg.kms_key_arn
    tags = None
    if not getattr(args, "no_tags", False):
        tags = build_tag_dict(connector_name, validate_extra_tags(cfg.tags))
    try:
        return target.create_knowledge_base(
            name=name, role_arn=role_arn, kms_key_arn=kms_key_arn,
            tags=tags, overrides=overrides,
        )
    except AwsError as exc:
        if not (tags or overrides.get("tags")) or not is_tagging_access_error(exc):
            raise
        print(
            f"  WARNING: created knowledge base without tags "
            f"(bedrock:TagResource denied): {exc}",
            file=sys.stderr,
        )
        untagged = {k: v for k, v in overrides.items() if k != "tags"}
        return target.create_knowledge_base(
            name=name, role_arn=role_arn, kms_key_arn=kms_key_arn,
            tags=None, overrides=untagged,
        )


# Data source statuses from which there is no forward path: recreate instead of
# reuse. Mirrors core.knowledge_base._DS_TERMINAL_BAD.
_DS_TERMINAL_BAD = {"FAILED", "DELETE_UNSUCCESSFUL"}


def _reconcile_existing_data_source(
    target: Target, kb_id: str, ds_id: str
) -> str | None:
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
    target: Target,
    kb_id: str,
    ds_name: str,
    payload: dict,
) -> str:
    """Create the data source, translating a name-collision 409 into guidance.

    Bedrock data-source deletion is asynchronous: the name stays reserved for a
    short window after a delete returns. A setup run that immediately recreates
    a DS with the same derived name can hit a 409 "already exists"; that case
    returns an actionable message rather than the raw API error.
    """
    try:
        ds_resp = target.create_data_source_raw(kb_id, payload)
    except AwsError as exc:
        text = str(exc)
        conflict = exc.code == "ConflictException" or "409" in text
        if conflict and "already exists" in text.lower():
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
    if not isinstance(ds_id, str) or not ds_id:
        raise AwsError(f"CreateDataSource returned no data source id: {ds_resp}")
    return ds_id


# --- Microsoft (SharePoint / OneDrive) setup ---------------------------------


def _setup_microsoft(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    stage: str,
) -> str | None:
    """Full SP/OD setup: Stage 1 (Entra) + Stage 2 (AWS).

    Returns why setup is not finished, or None when it is. Only target = 'quick'
    returns a reason: Quick is not yet authorized to sign with the KMS key, or
    several Quick data sources or knowledge bases match and none is recorded.
    """
    from kb_connector.connectors.sharepoint import (
        build_secret_body as sp_secret,
    )
    from kb_connector.connectors.onedrive import (
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
    # Quick's admin-managed flow keeps the private key in KMS, which changes what
    # Stage 1 produces (a certificate over an exported public key, no p12) and
    # what Stage 2 needs (no secret, no S3 object, no KB service role).
    uses_kms_signing = cfg.target == "quick"

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

    if uses_kms_signing:
        # Quick's admin-managed setup is certificate-based by definition: the
        # credential is a KMS-held key pair, and there is nowhere in the flow for
        # a client secret to go.
        if not uses_cert:
            raise ConfigError(
                f"target = 'quick' requires credential = 'cert' (got "
                f"{credential!r}). Quick's admin-managed setup authenticates "
                f"with a certificate whose private key lives in AWS KMS; it has "
                f"no client-secret path."
            )
        if cfg.type not in ("sharepoint", "onedrive"):
            raise ConfigError(
                f"target = 'quick' supports SharePoint and OneDrive connectors "
                f"(got type = {cfg.type!r})."
            )
        if cfg.type == "onedrive":
            if not acl:
                # Not an error, because there is no alternative to select:
                # Quick's admin-managed OneDrive setup crawls every user's
                # content and always enforces document-level access control.
                # Honoring acl = false would request a permission set that
                # cannot support the crawl Quick runs.
                print(
                    "  NOTE: acl = false is ignored for OneDrive with "
                    "target = 'quick'. Admin-managed OneDrive always enforces "
                    "document-level access control."
                )
                acl = True
            if args.sites_selected or cfg.get("sites_selected", False):
                # Said out loud rather than ignored: the operator asked for
                # least privilege and is not getting it. There is no OneDrive
                # equivalent of Sites.Selected. The admin-managed OneDrive
                # setup has no per-site grant step, so the app necessarily
                # holds tenant-wide Files.Read.All.
                print(
                    "  WARNING: sites_selected has no effect for OneDrive. "
                    "There is no per-site grant for OneDrive, so the app holds "
                    "tenant-wide read across every user's drive.",
                    file=sys.stderr,
                )
            from kb_connector.quick import templates as quick_templates

            for key in quick_templates.ignored_keys(cfg):
                # The Quick OneDrive knowledge base template has no per-user
                # filter, so the setting cannot narrow the crawl.
                print(
                    f"  WARNING: {key} has no effect for OneDrive with "
                    f"target = 'quick'. The Quick OneDrive knowledge base has "
                    f"no field for it, so Quick crawls every user's drive.",
                    file=sys.stderr,
                )
        # The KMS key is created during Stage 1, before the certificate that
        # wraps its public half, so a region is needed earlier than the Bedrock
        # path needs one. Quick also requires the account and the Quick instance
        # to be in the same Region.
        if not cfg.region:
            raise ConfigError(
                "region is required for target = 'quick': the KMS signing key "
                "is created before the certificate that embeds its public key. "
                "It must be the same Region as your Quick instance."
            )

    # Stage 1 mints the connector's credential — a certificate private key, or a
    # client secret — and holds it only in memory. It is never written to state
    # and never travels in a handoff document, both of which carry identifiers
    # only. So Stage 2 in a second process has nothing to write to Secrets
    # Manager, and a Stage 1 that runs alone cannot lead to a working connector
    # for any Microsoft credential mode.
    #
    # Refused up front rather than allowed to half-run, because Stage 1 replaces
    # the application's certificate on the way: an operator who runs it against a
    # working connector leaves the directory trusting a certificate whose private
    # key AWS does not have, and the next ingestion fails to authenticate.
    if stage == "1":
        raise ConfigError(
            f"`--stage 1` alone cannot set up a {cfg.type} connector. The "
            f"credential Stage 1 creates exists only in memory — it is never "
            f"written to the state file or a handoff document — so Stage 2 in a "
            f"separate process has nothing to store in Secrets Manager. Run "
            f"`--stage both` instead. If the identity and AWS work must be done "
            f"by different people, see the split-admin notes in "
            f"KNOWN-LIMITATIONS.md."
        )

    # Check AWS-side ownership before doing any irreversible Entra work.
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
            # Before any Graph write: everything below grants this app admin
            # consent, so it must be one this tool can show it created.
            _check_app_reuse(
                cs, existing, app_name=app_name,
                adopt=getattr(args, "adopt_existing_resources", False),
            )
            app_id = existing["appId"]
            object_id = existing["id"]
            sp = apps.ensure_service_principal(graph, app_id)
            reg = apps.AppRegistration(app_id, object_id, sp["id"])
            print(f"  Reusing existing app '{app_name}' (appId {app_id})")
        else:
            reg = apps.create_application(graph, app_name)
            print(f"  Created app '{app_name}' (appId {reg.app_id})")

        # Recorded before consent, certificate and site grants, any of which can
        # fail, so the next run recognizes the app as one this tool created.
        _record_app(cs, cfg, tenant_id, reg, reused=bool(existing))

        # Permissions + consent
        sites_sel = args.sites_selected or cfg.get("sites_selected", False)
        plan = permissions.build_plan(
            source=cfg.type,
            acl=acl,
            sites_selected=sites_sel,
            credential=credential,
            target=cfg.target,
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
            # Ask the directory which certificates the app actually carries. A
            # failure here is not fatal: it only means reuse cannot be confirmed,
            # and issuing a new certificate is the outcome that leaves both halves
            # of the credential in step.
            try:
                installed = apps.list_certificate_thumbprints(graph, reg.object_id)
            except Exception as exc:  # noqa: BLE001 - degrade to issuing a new cert
                print(f"  Could not read the app's certificates ({exc});")
                print("  issuing a new certificate.")
                installed = []

            if uses_kms_signing:
                # Quick admin-managed: the private key is generated in KMS and
                # never exists here, so this branch produces no p12, no password
                # and no private key to carry into Stage 2.
                cert_thumbprint, cert_not_after = _ensure_kms_backed_certificate(
                    args, cfg, cs, connector_name,
                    graph=graph,
                    app_object_id=reg.object_id,
                    app_name=app_name,
                    installed_thumbprints=installed,
                )
            elif _should_reuse_certificate(
                cs, installed_thumbprints=installed, rotate=args.rotate_cert
            ):
                cert_thumbprint = cs.cert_thumbprint_b64url
                cert_not_after = cs.cert_not_after
                print(
                    f"  Keeping the existing certificate (expires {cert_not_after}). "
                    f"Pass --rotate-cert to replace it."
                )
            else:
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
        #
        # Never for Quick, whichever source: the credential is the KMS key pair,
        # Quick has no field to receive a client secret, and there is no Secrets
        # Manager secret in this flow to store one. Creating one anyway would
        # leave a live, unused credential on the app registration.
        client_secret = None
        if not uses_kms_signing and (not uses_cert or cfg.type == "onedrive"):
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

        # Update state with source-side results. The app itself was recorded
        # when it was created or found, above.
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
    if stage in ("2", "both") and uses_kms_signing:
        # Stage 1 made the signing key and the certificate, which are the whole
        # credential. Stage 2 creates the Quick data source and knowledge base.
        return _setup_quick_resources(args, cfg, cs, connector_name)

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

        # Set only when the recorded certificate is being kept, in which case it
        # names the secret already holding the matching private key. Stage 1 keeps
        # the certificate when it is still installed on the app and both AWS-side
        # copies are recorded, so there is no new material to write and the stored
        # copies already match what the directory trusts. Rewriting them is not
        # possible anyway: the private key and its password exist only in the
        # process that generated them.
        kept_secret_arn: str | None = None
        if uses_cert and not p12_bytes and cs.cert_thumbprint_b64url and cs.cert_s3_key:
            kept_secret_arn = cs.secret_arn

        # Upload certificate to S3
        if uses_cert and kept_secret_arn:
            print(
                f"  Certificate and secret unchanged "
                f"(s3://{cs.cert_s3_bucket}/{cs.cert_s3_key})"
            )
        elif uses_cert:
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

        # Write the connector secret. Skipped alongside the certificate: its whole
        # contents for cert auth are the certificate password and private key, so
        # keeping one means keeping the other.
        if kept_secret_arn:
            secret_arn = kept_secret_arn
        else:
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

        kb_role_arn = _ensure_kb_role(
            args=args, cfg=cfg, cs=cs, connector_name=connector_name,
            session=session, account_id=account_id, opts=opts,
            secret_arn=secret_arn,
            cert_s3_bucket=cert_s3_bucket if uses_cert else None,
            cert_s3_key=cert_s3_key if uses_cert else None,
        )

        # Create KB (if needed) + data source via the target abstraction
        target = _build_target(cfg, session)

        connector_params = _spec(cfg).build_connector_params(cfg, BuildContext(
            account_id=account_id,
            secret_arn=secret_arn,
            cert_s3_bucket=cert_s3_bucket if uses_cert else None,
            cert_s3_key=cert_s3_key if uses_cert else None,
            acl=acl,
        ))

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
    return None


def _cert_valid_days(args: argparse.Namespace, cfg: ConnectorConfig) -> int:
    """Certificate lifetime, from --cert-valid-days or config.

    The flag keeps its own default, so config only applies when the flag was left
    at that default. Config is the better home for this: certificate lifetime is
    a standing policy decision, not something to remember on each run.
    """
    from_flag = getattr(args, "cert_valid_days", None)
    if from_flag is not None and from_flag != _DEFAULT_CERT_VALID_DAYS:
        return int(from_flag)
    from_config = cfg.cert_valid_days
    if from_config is not None:
        return int(from_config)
    return int(from_flag or _DEFAULT_CERT_VALID_DAYS)


def _derive_signing_key_alias(
    args: argparse.Namespace, cfg: ConnectorConfig, connector_name: str
) -> str:
    """Alias for this connector's KMS signing key."""
    explicit = getattr(args, "signing_key_alias", None) or cfg.signing_key_alias
    if explicit:
        return str(explicit)
    return _derived_name(cfg, f"kb-connector-{connector_name}-signing")


def _should_reuse_kms_certificate(
    cs: ConnectorState,
    *,
    signing_key_arn: str,
    installed_thumbprints: list[str],
    rotate: bool,
) -> bool:
    """Whether the recorded KMS-backed certificate can be kept.

    Simpler than the Bedrock equivalent because the credential is not split in
    half. There is no private key in Secrets Manager and no object in S3 to fall
    out of step with the directory, because the private key sits in KMS the whole
    time.
    So reuse only needs the recorded certificate to still be installed on the
    app, and to have been built from the key this run is using.

    That last condition is the one that matters: reissuing a certificate is
    cheap and harmless here, but keeping one built from a *different* KMS key
    silently leaves Entra validating assertions against a public key that no
    longer matches the signer, which fails at sync time.
    """
    if rotate:
        return False
    recorded = cs.cert_thumbprint_b64url
    if not recorded or cs.signing_key_arn != signing_key_arn:
        return False
    return recorded in installed_thumbprints


def _ensure_kms_backed_certificate(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    *,
    graph: Any,
    app_object_id: str,
    app_name: str,
    installed_thumbprints: list[str],
) -> tuple[str | None, str | None]:
    """Create/reuse the KMS signing key and the Entra certificate over it.

    Returns (thumbprint_b64url, not_after). Records the signing key and its
    ownership in state.

    Ordering is forced by the credential's shape: the certificate embeds the
    KMS public key, so the key has to exist first. That makes this the one AWS
    resource the source-side stage creates.
    """
    from kb_connector.core import kms_signing
    from kb_connector.providers.microsoft import apps, certs

    session, _account_id = _aws_session_and_account(cfg)
    opts = _provision_options(args, cfg)

    explicit_arn = getattr(args, "signing_key_arn", None) or cfg.signing_key_arn
    if explicit_arn:
        # An operator-supplied key is read, never created or tagged, so it is
        # recorded external: teardown reports it and leaves it be.
        signing_key_arn = str(explicit_arn)
        _record_reused_resource(
            cs, state_mod.RESOURCE_SIGNING_KEY, signing_key_arn
        )
        print(f"  Using existing KMS signing key: {signing_key_arn}")
        alias = None
    else:
        alias = _derive_signing_key_alias(args, cfg, connector_name)
        key_res = kms_signing.ensure_signing_key(
            session=session,
            alias=alias,
            connector_name=connector_name,
            tags_enabled=opts.tags_enabled,
            extra_tags=opts.tags,
            adopt_existing=opts.adopt_existing,
            created_untagged=cs.created_untagged(state_mod.RESOURCE_SIGNING_KEY),
        )
        signing_key_arn = key_res.arn
        cs.record_ownership(
            state_mod.RESOURCE_SIGNING_KEY, key_res.state_marker
        )
        verb = "Created" if key_res.created else "Using"
        print(f"  {verb} KMS signing key ({alias}): {signing_key_arn}")

    cs.signing_key_arn = signing_key_arn
    cs.signing_key_alias = alias

    if _should_reuse_kms_certificate(
        cs,
        signing_key_arn=signing_key_arn,
        installed_thumbprints=installed_thumbprints,
        rotate=args.rotate_cert,
    ):
        print(
            f"  Keeping the existing certificate (expires {cs.cert_not_after}). "
            f"Pass --rotate-cert to replace it."
        )
        return cs.cert_thumbprint_b64url, cs.cert_not_after

    public_key_der = kms_signing.get_public_key_der(
        session=session, key_id=signing_key_arn
    )
    cert = certs.generate_kms_backed_cert(
        public_key_der=public_key_der,
        signing_key_arn=signing_key_arn,
        sign=kms_signing.make_signer(session=session, key_id=signing_key_arn),
        common_name=app_name,
        valid_days=_cert_valid_days(args, cfg),
    )
    apps.upload_certificate(graph, app_object_id, cert)
    cs.record_owned(state_mod.RESOURCE_CERT)
    print(
        f"  Generated + uploaded certificate over the KMS public key "
        f"(expires {cert.not_after})"
    )
    if cs.data_source_id:
        _warn_quick_data_source_keeps_old_certificate(cs, connector_name)
    return cert.thumbprint_b64url, cert.not_after


def _warn_quick_data_source_keeps_old_certificate(
    cs: ConnectorState, connector_name: str
) -> None:
    """A new certificate leaves the recorded Quick data source on the old one.

    The data source holds the key ARN and certificate thumbprint it was created
    with, and setup does not modify a data source it finds. After the upload the
    Entra app has only the new certificate, so the data source's syncs
    cannot authenticate until it is recreated.
    """
    print(
        f"  WARNING: Quick data source {cs.data_source_id} keeps the certificate "
        f"thumbprint it was created with, and setup does not update it. After this "
        f"upload the Entra app has only the new certificate, so syncs of this "
        f"data source will fail to authenticate.\n"
        f"  To recover, delete and recreate the knowledge base and the data source:\n"
        f"    kb-connector teardown {connector_name} --only kb\n"
        f"    kb-connector teardown {connector_name} --only ds\n"
        f"    kb-connector setup {connector_name}\n"
        f"  Teardown deletes only what this tool created. A knowledge base or data "
        f"source recorded as external is kept: delete it in the Quick console "
        f"first.",
        file=sys.stderr,
    )


_QUICK_DOCS = "https://docs.aws.amazon.com/quick/latest/userguide"

# Retries after the operator says the key is saved in the Quick console. The
# authorization took 20-30 s to reach CreateDataSource in live runs.
_QUICK_AUTH_RETRIES = 4
_QUICK_AUTH_RETRY_SECONDS = 15


def _setup_quick_resources(
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
) -> str | None:
    """Stage 2 for target = 'quick': the Quick data source and knowledge base.

    Finds what already exists before creating anything, in this order: the ids
    in state, the derived ids, then anything else made for this Entra app (a
    data source by ClientId, a knowledge base by data source ARN). Nothing found
    is modified. `--kb` names a knowledge base outright. A data source or
    knowledge base that is found is waited on until it is usable, and one that
    failed stops setup with the service's error.

    Returns why setup is not finished, or None when it is. Not finished means
    Quick is not yet authorized to sign with the KMS key, or several data
    sources or knowledge bases match and none is recorded. The authorization is
    a Quick console step ("Select keys"), so the first run always stops there:
    the step needs the key ARN this run has just created. Setup never writes a
    key policy, a grant or an IAM policy.
    """
    from kb_connector.core import kms_signing
    from kb_connector.quick import templates
    from kb_connector.quick.client import QuickClient

    missing = [
        label for label, value in (
            ("signing_key_arn", cs.signing_key_arn),
            ("cert_thumbprint_b64url", cs.cert_thumbprint_b64url),
            ("client_app_id", cs.client_app_id),
            ("tenant_id", cs.tenant_id),
        ) if not value
    ]
    if missing:
        raise StateError(
            f"State has no {', '.join(missing)} for connector {connector_name!r}, "
            f"so the Quick data source cannot be created. Run "
            f"`kb-connector setup {connector_name} --stage both`."
        )
    key_arn = str(cs.signing_key_arn)
    client_id = str(cs.client_app_id)

    print("\n── Stage 2: Amazon Quick ──")
    session, account_id = _aws_session_and_account(cfg)
    quick = QuickClient(session=session, region=cfg.region, account_id=account_id)

    # Built before any write, so a config problem (no SharePoint domain, no
    # site_urls) stops the run with nothing created.
    ds_type, ds_params = templates.data_source_request(
        cfg, tenant_id=str(cs.tenant_id), client_id=client_id
    )
    kb_template = templates.knowledge_base_template(cfg)
    acl = templates.quick_acl(cfg)
    tags = _quick_tags(args, cfg, connector_name)
    adopt = getattr(args, "adopt_existing_resources", False)
    owner = _QuickOwner(cfg, quick, session)

    if args.knowledge_base_id:
        _print_quick_kb_status(_record_quick_kb_from_flag(
            quick, cs, args.knowledge_base_id, client_id=client_id
        ))
        _print_quick_finish(cs, kms_signing)
        return None

    ds = _find_quick_data_source(
        quick, cs, cfg, connector_name, client_id=client_id, adopt=adopt
    )
    if ds is _SEVERAL:
        return (
            f"several Quick data sources use this Entra app (listed above), so "
            f"setup recorded none and created no knowledge base. Pick the "
            f"knowledge base to use and pass --kb: "
            f"`kb-connector setup {connector_name} --kb <id>`."
        )
    if ds is None:
        ds_id = _derived_name(cfg, f"kb-connector-{connector_name}-ds")
        owner_arn = owner.arn()
        _print_quick_key_step(cfg, quick, key_arn, kms_signing)

        def create_ds(with_tags: list[dict[str, str]] | None) -> str:
            return quick.create_data_source(
                ds_id=ds_id,
                name=args.ds_name or f"{connector_name}-ds",
                ds_type=ds_type,
                parameters=ds_params,
                key_arn=key_arn,
                thumbprint=str(cs.cert_thumbprint_b64url),
                owner_arn=owner_arn,
                tags=with_tags,
            )

        created = _create_quick_data_source_when_authorized(
            create_ds, tags, connector_name=connector_name, key_arn=key_arn
        )
        if created is None:
            return (
                f"Amazon Quick is not yet authorized to sign with the KMS key. "
                f"Save the key in the Quick console (Select keys, above), then "
                f"re-run `kb-connector setup {connector_name}`."
            )
        ds_arn, marker = created
        # Recorded before the wait, so a failed wait leaves the data source
        # tracked for teardown and for the next run.
        cs.data_source_id = ds_id
        cs.record_ownership(state_mod.RESOURCE_DS, marker)
        print(f"  Created Quick data source: {ds_id}")
        quick.wait_for_data_source(ds_id)
        print("  Quick data source is ready")
    else:
        ds_arn = str(ds.get("Arn"))
        _ready_quick_data_source(quick, ds)

    kb = _find_quick_knowledge_base(
        quick, cs, cfg, connector_name, ds_arn=ds_arn, adopt=adopt
    )
    if kb is _SEVERAL:
        return (
            f"several Quick knowledge bases use this data source (listed above), "
            f"so setup recorded none. Pass --kb <id> to validate and diagnose, or "
            f"record one: `kb-connector setup {connector_name} --kb <id>`."
        )
    if kb is None:
        kb_id = _derived_name(cfg, f"kb-connector-{connector_name}-kb")
        owner_arn = owner.arn()

        def create_kb(with_tags: list[dict[str, str]] | None) -> str:
            return quick.create_knowledge_base(
                kb_id=kb_id,
                name=args.kb_name or f"kb-connector-{connector_name}",
                description=f"Managed by kb-connector for connector {connector_name}.",
                ds_arn=ds_arn,
                template=kb_template,
                acl=acl,
                owner_arn=owner_arn,
                tags=with_tags,
            )

        _kb_arn, marker = _create_quick_tagged(create_kb, tags, what="knowledge base")
        # Recorded before the wait, as the data source is above.
        cs.knowledge_base_id = kb_id
        cs.record_ownership(state_mod.RESOURCE_KB, marker)
        print(f"  Created Quick knowledge base: {kb_id}")
        print("  Waiting for the knowledge base to become ACTIVE...")
        kb = quick.wait_until_kb_active(kb_id)
    else:
        kb_acl = (kb.get("AccessControlConfiguration") or {}).get("isACLEnabled")
        if kb_acl is not None and bool(kb_acl) != acl:
            print(
                f"  WARNING: Quick knowledge base {cs.knowledge_base_id} has "
                f"isACLEnabled = {str(bool(kb_acl)).lower()}, but this connector's "
                f"config asks for {str(acl).lower()}. ACL cannot be changed on an "
                f"existing knowledge base, and validate reports the mismatch.",
                file=sys.stderr,
            )
        kb = _ready_quick_knowledge_base(quick, kb)

    _print_quick_kb_status(kb)
    print("  Quick starts the first sync itself; there is no sync API.")
    _print_quick_finish(cs, kms_signing)
    return None


# Returned by the find helpers when several candidates match and none is picked.
_SEVERAL: dict = {}


def _ready_quick_data_source(quick: QuickClient, ds: dict) -> dict:
    """A found data source, once usable; raises with ErrorInfo when it failed."""
    from kb_connector.quick.client import DATA_SOURCE_READY

    if ds.get("Status") in DATA_SOURCE_READY:
        return ds
    print(
        f"  Quick data source {ds.get('DataSourceId')} is {ds.get('Status')}; "
        f"waiting for it..."
    )
    return quick.wait_for_data_source(str(ds.get("DataSourceId")))


def _ready_quick_knowledge_base(quick: QuickClient, kb: dict) -> dict:
    """A found knowledge base, once ACTIVE; raises when it failed."""
    if kb.get("Status") == "ACTIVE":
        return kb
    print(
        f"  Quick knowledge base {kb.get('KnowledgeBaseId')} is {kb.get('Status')}; "
        f"waiting for it to become ACTIVE..."
    )
    return quick.wait_until_kb_active(str(kb.get("KnowledgeBaseId")))


def _print_quick_kb_status(kb: dict) -> None:
    print("  KB is ACTIVE")
    ingestion = (kb.get("LatestIngestionSummary") or {}).get("IngestionStatus")
    if ingestion:
        print(f"  Latest sync: {ingestion}")


class _QuickOwner:
    """The Quick user or group that owns the data source and knowledge base.

    `quick_owner_arn` wins. Otherwise the Quick user of the identity running
    setup, found with DescribeUser. CreateKnowledgeBase never makes the caller
    the owner, and a knowledge base with no owner cannot be managed in the
    console. Resolved once, before the first create.
    """

    def __init__(self, cfg: ConnectorConfig, quick: QuickClient, session: Any) -> None:
        self._cfg = cfg
        self._quick = quick
        self._session = session
        self._arn: str | None = None

    def arn(self) -> str:
        if self._arn:
            return self._arn
        if self._cfg.quick_owner_arn:
            self._arn = str(self._cfg.quick_owner_arn)
            return self._arn
        from kb_connector.quick.client import quick_user_name

        caller = str(self._session.client("sts").get_caller_identity()["Arn"])
        user_name = quick_user_name(caller)
        found: str | None = None
        detail = "it has no Quick user name"
        if user_name:
            detail = f"there is no Quick user {user_name!r} in namespace default"
            try:
                found = self._quick.user_arn(user_name)
            except AwsError as exc:
                detail = f"DescribeUser failed ({exc.code or exc})"
        if not found:
            raise ConfigError(
                f"Cannot tell which Quick user should own the data source and "
                f"knowledge base: the caller {caller} is not usable because "
                f"{detail}. Set quick_owner_arn on connector {self._cfg.name!r} "
                f"to a Quick user or group ARN (for example "
                f"\"arn:aws:quicksight:us-east-1:123456789012:user/default/"
                f"jane\"). Nothing was created in Quick."
            )
        print(f"  Quick owner: {found}")
        self._arn = found
        return found


def _quick_tags(
    args: argparse.Namespace, cfg: ConnectorConfig, connector_name: str
) -> list[dict[str, str]] | None:
    """Ownership and operator tags for the Quick resources, or None for --no-tags."""
    from kb_connector.core.tagging import build_tag_list, validate_extra_tags

    if getattr(args, "no_tags", False):
        return None
    try:
        extra = validate_extra_tags(cfg.tags)
    except ValueError as exc:
        raise ConfigError(f"Invalid [tags] entry for this connector: {exc}") from exc
    return build_tag_list(connector_name, extra)


def _create_quick_tagged(
    create: Any, tags: list[dict[str, str]] | None, *, what: str
) -> tuple[str, str]:
    """Create with tags, retrying untagged when tagging is denied.

    Returns (ARN, ownership marker). A resource created without tags is still
    ours, so it is recorded `tool-untagged`.
    """
    from kb_connector.core.tagging import is_tagging_access_error

    try:
        arn = create(tags)
    except AwsError as exc:
        if tags is None or not is_tagging_access_error(exc):
            raise
        print(
            f"  WARNING: created the Quick {what} without tags "
            f"(quicksight:TagResource denied): {exc}",
            file=sys.stderr,
        )
        return create(None), state_mod.OWNER_TOOL_UNTAGGED
    return arn, (state_mod.OWNER_TOOL if tags is not None else state_mod.OWNER_TOOL_UNTAGGED)


def _create_quick_data_source_when_authorized(
    create: Any,
    tags: list[dict[str, str]] | None,
    *,
    connector_name: str,
    key_arn: str,
) -> tuple[str, str] | None:
    """Create the data source, or explain how to finish while the key is unauthorized.

    Returns (ARN, marker), or None when Quick still cannot sign with the key.
    On a terminal the operator can authorize the key and press Enter to retry;
    without one setup never prompts.
    """
    from kb_connector.quick.client import KeyNotAuthorized

    try:
        return _create_quick_tagged(create, tags, what="data source")
    except KeyNotAuthorized:
        pass
    print(
        f"\n  Amazon Quick is not yet authorized to sign with KMS key {key_arn}.\n"
        f"  CreateDataSource answered \"Failed to generate JWT assertion\": Quick\n"
        f"  cannot sign the Entra assertion until the key is saved in the Quick\n"
        f"  console (the \"Select keys\" step above)."
    )
    print(
        f"  To finish, do that step and re-run `kb-connector setup "
        f"{connector_name}`.\n"
        f"  The re-run reuses the KMS key, the certificate and the Entra app."
    )
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    while True:
        try:
            answer = input(
                "  Press Enter after saving the key in the Quick console to "
                "retry, or q to stop: "
            )
        except EOFError:
            return None
        if answer.strip().lower() == "q":
            return None
        for attempt in range(_QUICK_AUTH_RETRIES):
            if attempt:
                time.sleep(_QUICK_AUTH_RETRY_SECONDS)
            try:
                return _create_quick_tagged(create, tags, what="data source")
            except KeyNotAuthorized:
                print(
                    f"  Still not authorized (attempt {attempt + 1} of "
                    f"{_QUICK_AUTH_RETRIES})."
                )


def _print_quick_key_step(
    cfg: ConnectorConfig, quick: QuickClient, key_arn: str, kms_signing: Any
) -> None:
    """Print the console step that lets Quick sign with the key.

    For an account whose Quick service role is customer-managed, also print the
    kms:Sign statement for that role. Printed only; setup writes no policy.
    """
    slug = "sharepoint" if cfg.type == "sharepoint" else "onedrive"
    print(
        "\n  Quick must be allowed to sign with the KMS key. A Quick administrator\n"
        "  (Admin Pro) does this once in the Quick console:"
    )
    print("    Manage account -> Permissions -> AWS resources")
    print("      -> AWS Key Management Service -> Select keys -> Add:")
    print(f"        {key_arn}")
    print("    Then Finish, and Save at the bottom of the page.")
    print(f"    Docs: {_QUICK_DOCS}/{slug}-kb-admin-config.html")
    partition = key_arn.split(":")[1] if key_arn.count(":") >= 5 else "aws"
    signer = quick.signer_role(partition=partition, account_id=quick.account_id)
    if signer.role_type == "CUSTOMER_MANAGED" and signer.role_arn:
        print(
            f"\n  This account uses a customer-managed Quick service role\n"
            f"  ({signer.role_arn}). That role also needs kms:Sign on the key.\n"
            f"  A key administrator adds this statement to the key policy:"
        )
        grant = kms_signing.build_sign_grant_statement(
            signing_key_arn=key_arn, principal_arn=signer.role_arn
        )
        for line in json.dumps(grant, indent=2).splitlines():
            print(f"      {line}")
    elif signer.role_type is None and signer.detail:
        print(
            f"  NOTE: could not read which role Quick signs with "
            f"(DescribeResourcePermissions: {signer.detail})."
        )


def _print_quick_finish(cs: ConnectorState, kms_signing: Any) -> None:
    if cs.cert_not_after:
        print(
            f"\n  Certificate expires {cs.cert_not_after}. Re-run with "
            f"--rotate-cert to reissue it from the same KMS key."
        )
    print(f"\n  {kms_signing.describe_orphan_risk(cs.signing_key_arn or '(none)')}")


def _quick_client_id(ds: dict) -> str | None:
    params = ds.get("DataSourceParameters") or {}
    for key in ("SharePointParameters", "OneDriveParameters"):
        client_id = (params.get(key) or {}).get("ClientId")
        if client_id:
            return str(client_id)
    return None


def _classify_found_quick_resource(
    quick: QuickClient,
    cs: ConnectorState,
    connector_name: str,
    *,
    resource: str,
    kind: str,
    found_id: str,
    arn: str,
    adopt: bool,
) -> None:
    """Record a resource found under its derived id, or refuse it.

    Ours by tag: recorded `tool`. Anything else is refused unless
    --adopt-existing-resources, which records it `external`.
    """
    from kb_connector.core.tagging import Ownership, classify_ownership, describe_conflict

    raw_tags, readable = quick.tags(arn)
    ownership = classify_ownership(raw_tags, connector_name, verifiable=readable)
    if ownership is Ownership.OURS:
        cs.record_owned(resource)
        print(f"  Using Quick {kind} {found_id} (tagged as this connector's)")
        return
    if adopt:
        cs.record_external(resource)
        print(
            f"  Adopting Quick {kind} {found_id} (external — teardown will not "
            f"delete it)"
        )
        return
    raise AwsError(describe_conflict(
        resource_kind=f"Quick {kind}",
        identifier=found_id,
        ownership=ownership,
        connector_name=connector_name,
    ))


def _find_quick_data_source(
    quick: QuickClient,
    cs: ConnectorState,
    cfg: ConnectorConfig,
    connector_name: str,
    *,
    client_id: str,
    adopt: bool,
) -> dict | None:
    """The data source to use, recorded in state; None to create; _SEVERAL to stop."""
    if cs.data_source_id:
        found = quick.describe_data_source(cs.data_source_id)
        if found is not None:
            if _quick_client_id(found) != client_id:
                raise AwsError(
                    f"Quick data source {cs.data_source_id} recorded in state "
                    f"uses Entra app {_quick_client_id(found)}, not this "
                    f"connector's app {client_id}. Refusing to use it. Check "
                    f"the state file, or tear the connector down and set it up "
                    f"again."
                )
            print(f"  Using Quick data source {cs.data_source_id} (recorded in state)")
            return found
        print(
            f"  Quick data source {cs.data_source_id} recorded in state no "
            f"longer exists; looking for another."
        )
        cs.data_source_id = None
        cs.created_resources.pop(state_mod.RESOURCE_DS, None)

    derived = _derived_name(cfg, f"kb-connector-{connector_name}-ds")
    found = quick.describe_data_source(derived)
    if found is not None:
        if _quick_client_id(found) != client_id:
            raise AwsError(
                f"Quick data source {derived!r} already exists for another Entra "
                f"app ({_quick_client_id(found)}). Set resource_prefix for "
                f"connector {connector_name!r} in config so its derived ids do "
                f"not collide."
            )
        _classify_found_quick_resource(
            quick, cs, connector_name, resource=state_mod.RESOURCE_DS,
            kind="data source", found_id=derived, arn=str(found.get("Arn")),
            adopt=adopt,
        )
        cs.data_source_id = derived
        return found

    others = quick.data_sources_for_app(client_id)
    if len(others) == 1:
        (found,) = others
        cs.data_source_id = str(found.get("DataSourceId"))
        cs.record_external(state_mod.RESOURCE_DS)
        print(
            f"  Found Quick data source {cs.data_source_id} for this Entra app, "
            f"made outside this tool. Using it (external — teardown will not "
            f"delete it)."
        )
        return dict(found)
    if len(others) > 1:
        print(
            "  Several Quick data sources use this Entra app, so setup picks none "
            "and creates nothing:"
        )
        for other in others:
            print(f"    • {other.get('DataSourceId')} ({other.get('Name')})")
        return _SEVERAL
    return None


def _find_quick_knowledge_base(
    quick: QuickClient,
    cs: ConnectorState,
    cfg: ConnectorConfig,
    connector_name: str,
    *,
    ds_arn: str,
    adopt: bool,
) -> dict | None:
    """The knowledge base to use, recorded in state; None to create; _SEVERAL to stop."""
    if cs.knowledge_base_id:
        found = quick.describe_knowledge_base(cs.knowledge_base_id)
        if found is not None:
            if found.get("DataSourceArn") != ds_arn:
                raise AwsError(
                    f"Quick knowledge base {cs.knowledge_base_id} recorded in "
                    f"state uses data source {found.get('DataSourceArn')}, not "
                    f"{ds_arn}. Refusing to use it. Check the state file, or "
                    f"tear the connector down and set it up again."
                )
            print(f"  Using Quick knowledge base {cs.knowledge_base_id} (recorded in state)")
            return found
        print(
            f"  Quick knowledge base {cs.knowledge_base_id} recorded in state no "
            f"longer exists; looking for another."
        )
        cs.knowledge_base_id = None
        cs.created_resources.pop(state_mod.RESOURCE_KB, None)

    derived = _derived_name(cfg, f"kb-connector-{connector_name}-kb")
    found = quick.describe_knowledge_base(derived)
    if found is not None:
        if found.get("DataSourceArn") != ds_arn:
            raise AwsError(
                f"Quick knowledge base {derived!r} already exists on another data "
                f"source ({found.get('DataSourceArn')}). Set resource_prefix for "
                f"connector {connector_name!r} in config so its derived ids do "
                f"not collide."
            )
        _classify_found_quick_resource(
            quick, cs, connector_name, resource=state_mod.RESOURCE_KB,
            kind="knowledge base", found_id=derived,
            arn=str(found.get("KnowledgeBaseArn")), adopt=adopt,
        )
        cs.knowledge_base_id = derived
        return found

    others = quick.knowledge_bases_for_data_source(ds_arn)
    if len(others) == 1:
        kb_id = str(others[0].get("KnowledgeBaseId"))
        found = quick.describe_knowledge_base(kb_id) or dict(others[0])
        cs.knowledge_base_id = kb_id
        cs.record_external(state_mod.RESOURCE_KB)
        print(
            f"  Found Quick knowledge base {kb_id} on this data source, made "
            f"outside this tool. Using it (external — teardown will not delete it)."
        )
        return found
    if len(others) > 1:
        print(
            "  Several Quick knowledge bases use this data source, so setup "
            "records none and creates none:"
        )
        for other in others:
            print(f"    • {other.get('KnowledgeBaseId')} ({other.get('Name')})")
        return _SEVERAL
    return None


def _record_quick_kb_from_flag(
    quick: QuickClient, cs: ConnectorState, kb_id: str, *, client_id: str
) -> dict:
    """--kb with target = 'quick': record the named knowledge base and its data source.

    Both must already exist and the data source must use this connector's
    Entra app. Nothing is created. Unless state already records them as this
    tool's, both are recorded external. Returns the knowledge base once both
    are usable; raises when either failed.
    """
    kb = quick.describe_knowledge_base(kb_id)
    if kb is None:
        raise AwsError(f"Quick knowledge base {kb_id!r} (from --kb) does not exist.")
    ds_arn = str(kb.get("DataSourceArn") or "")
    ds_id = ds_arn.rsplit("/", 1)[-1]
    ds = quick.describe_data_source(ds_id) if ds_id else None
    if ds is None or _quick_client_id(ds) != client_id:
        raise AwsError(
            f"Quick knowledge base {kb_id!r} (from --kb) is on data source "
            f"{ds_arn or '(none)'}, which does not use this connector's Entra app "
            f"{client_id}. Pick a knowledge base whose data source uses this app."
        )
    owned_ds = (
        cs.data_source_id == ds_id
        and state_mod.RESOURCE_DS in cs.created_resources
        and cs.is_tool_owned(state_mod.RESOURCE_DS)
    )
    replaced_kb = cs.knowledge_base_id
    if (
        replaced_kb and replaced_kb != kb_id
        and state_mod.RESOURCE_KB in cs.created_resources
        and cs.is_tool_owned(state_mod.RESOURCE_KB)
    ):
        print(
            f"  WARNING: state records Quick knowledge base {replaced_kb} as created "
            f"by this tool. --kb replaces it with {kb_id}, so {replaced_kb} is no "
            f"longer tracked and teardown will not delete it. Delete it in the "
            f"Amazon Quick console if it is no longer needed.",
            file=sys.stderr,
        )
    if not _record_reused_resource(cs, state_mod.RESOURCE_KB, kb_id):
        print(f"  Using Quick knowledge base {kb_id} (external — teardown will not delete it)")
    else:
        print(f"  Using Quick knowledge base {kb_id}")
    cs.knowledge_base_id = kb_id
    if not owned_ds:
        cs.record_external(state_mod.RESOURCE_DS)
    cs.data_source_id = ds_id
    print(f"  Using Quick data source {ds_id}")
    _ready_quick_data_source(quick, ds)
    return _ready_quick_knowledge_base(quick, kb)


def _should_reuse_certificate(
    cs: ConnectorState, *, installed_thumbprints: list[str], rotate: bool
) -> bool:
    """Whether the recorded certificate can be kept instead of issuing a new one.

    A certificate is one credential split across two systems: the directory holds
    the public certificate, and Secrets Manager plus S3 hold the private key. They
    are only usable together, so replacing one half without the other breaks
    authentication. Issuing a new certificate is therefore something to do when
    asked for, not on every run.

    Reuse requires all three records to agree — the thumbprint, the S3 object, and
    the secret — plus confirmation from the directory that the recorded
    certificate is still installed. Anything missing means the halves may already
    disagree, and issuing a fresh certificate is what puts them back in step,
    since Stage 2 writes both sides from the same material.
    """
    if rotate:
        return False
    recorded = cs.cert_thumbprint_b64url
    if not recorded or not cs.cert_s3_key or not cs.secret_arn:
        return False
    return recorded in installed_thumbprints


def _check_app_reuse(
    cs: ConnectorState, existing: dict, *, app_name: str, adopt: bool
) -> None:
    """Refuse to reuse an Entra app this tool cannot show it created.

    The app is found by display name, and the name is predictable
    (`kb-connector-<connector>`). Entra lets ordinary users register apps by
    default, so anyone can create an app with that name and add their own
    client secret to it. Reusing it would then grant their app tenant-wide admin
    consent. Uploading our certificate replaces the app's certificates but not
    its client secrets, so their credential would keep working.

    So an app found by name is reused only when state records that exact object
    id as one this tool created. `--adopt-existing-resources` overrides, and in
    that case the credentials already on the app are listed, because whoever
    holds them gets the permissions consented next.
    """
    object_id = existing.get("id")
    if cs.is_recorded_ours(state_mod.RESOURCE_APP, object_id):
        return

    secrets = existing.get("passwordCredentials") or []
    certs_ = existing.get("keyCredentials") or []
    held = (
        f"It currently carries {len(secrets)} client secret(s) and "
        f"{len(certs_)} certificate(s)."
    )

    if adopt:
        print(
            f"  WARNING: adopting existing Entra app '{app_name}' (object id "
            f"{object_id}), which state does not record as created by this "
            f"tool. {held} Anyone holding one of those gets the permissions "
            f"about to be consented. Check its owners and credentials in the "
            f"Entra portal.",
            file=sys.stderr,
        )
        return

    raise ProviderError(
        f"An Entra app named '{app_name}' (object id {object_id}) already "
        f"exists, and state does not record it as created by this tool. {held}\n\n"
        f"Setup would grant this app tenant-wide admin consent, so it is not "
        f"reused on the strength of its name alone: anyone who can register "
        f"apps in the tenant can create one with this name.\n\n"
        f"Ways forward:\n"
        f"  • Pass --app-name with a distinct name to create a new app.\n"
        f"  • If an earlier run of this tool created it, or you have verified "
        f"its owners and credentials, re-run with --adopt-existing-resources. "
        f"It is then recorded as external, so teardown leaves it alone.\n"
        f"  • Otherwise, delete it: az ad app delete --id {object_id}"
    )


def _record_app(
    cs: ConnectorState,
    cfg: ConnectorConfig,
    tenant_id: str,
    reg: AppRegistration,
    *,
    reused: bool,
) -> None:
    """Record the connector's Entra app in state, with its ownership.

    For a reused app, ownership is evaluated before the ids are overwritten,
    so it compares against what an earlier pass recorded: an app found by
    display name stays ours only if state already records it as ours.
    """
    cs.connector_type = cfg.type
    cs.tenant_id = tenant_id
    if reused:
        _record_reused_resource(cs, state_mod.RESOURCE_APP, reg.object_id)
    else:
        cs.record_owned(state_mod.RESOURCE_APP)
    cs.client_app_id = reg.app_id
    cs.client_app_object_id = reg.object_id


def _record_reused_resource(
    cs: ConnectorState, resource: str, found_id: str | None
) -> bool:
    """Record ownership for a resource setup is reusing rather than creating.

    Returns True if it was recorded as ours. See
    `ConnectorState.is_recorded_ours` for why finding a resource is not enough
    to call it adopted: a resumed or repeated run rediscovers what an earlier
    pass created, and disowning it strands the resource beyond teardown's reach.
    """
    if cs.is_recorded_ours(resource, found_id):
        cs.record_owned(resource)
        return True
    cs.record_external(resource)
    return False


def _delete_granter_app(
    graph: GraphClient, admin: AdminAppCredentials, admin_app_name: str
) -> None:
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


def _ensure_kb_role(
    *,
    args: argparse.Namespace,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    connector_name: str,
    session: Session,
    account_id: str,
    opts: _ProvisionOptions,
    secret_arn: str | None,
    cert_s3_bucket: str | None = None,
    cert_s3_key: str | None = None,
    content_bucket: str | None = None,
) -> str | None:
    """Return the KB role, giving it access to this connector's credentials.

    * `--no-create-kb-role`: `--kb-role-arn`, or the role in state, as given.
    * A knowledge base this tool did not create (`--kb`, or one recorded as
      external): that KB's role, extended add-only with the connector's secret,
      certificate and S3 content bucket.
    * A role this tool did not create (`--kb-role-arn`): used as given.
    * Otherwise the connector's own role, created or updated in place. On a
      re-run that is the role state records, not a newly derived name.
    """
    from kb_connector.core import provisioning
    from kb_connector.core.teardown import role_name_from_arn

    if args.no_create_kb_role:
        role_arn = args.kb_role_arn or cs.kb_role_arn
        if role_arn:
            _record_reused_resource(cs, state_mod.RESOURCE_ROLE, role_arn)
        return role_arn

    kb_id = args.knowledge_base_id or cs.knowledge_base_id
    if kb_id and not cs.is_recorded_ours(state_mod.RESOURCE_KB, kb_id):
        return _extend_existing_kb_role(
            session, cfg, cs, kb_id, secret_arn, cert_s3_bucket, cert_s3_key,
            account_id=account_id, opts=opts, content_bucket=content_bucket,
        )

    given = args.kb_role_arn or cs.kb_role_arn
    if given and not cs.is_recorded_ours(state_mod.RESOURCE_ROLE, given):
        _record_reused_resource(cs, state_mod.RESOURCE_ROLE, given)
        return given

    role_name = (
        role_name_from_arn(cs.kb_role_arn) if cs.kb_role_arn
        else args.kb_role_name or _derived_name(cfg, f"kb-connector-{connector_name}-role")
    )
    cert_prefix = cfg.cert_s3_key_prefix if cert_s3_bucket else None
    role_res = provisioning.ensure_kb_role(
        session=session,
        role_name=role_name,
        account_id=account_id,
        region=cfg.region or "",
        secret_arn=secret_arn,
        cert_bucket=cert_s3_bucket,
        cert_key=cert_s3_key,
        cert_key_prefix=cert_prefix,
        kms_key_arn=opts.kms_key_arn,
        connector_name=connector_name,
        tags_enabled=opts.tags_enabled,
        extra_tags=opts.tags,
        adopt_existing=opts.adopt_existing,
        created_untagged=cs.created_untagged(state_mod.RESOURCE_ROLE),
    )
    if content_bucket:
        _add_s3_content_policy(
            session, role_name, content_bucket, account_id,
            inclusion_prefixes=cfg.get("inclusion_prefixes"),
        )
    print(f"  {'Provisioned' if role_res.created else 'Updated'} IAM role: {role_res.arn}")
    cs.kb_role_arn = role_res.arn
    cs.record_ownership(state_mod.RESOURCE_ROLE, role_res.state_marker)
    if role_res.created:
        print("  Waiting for IAM propagation...")
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay
    return role_res.arn


def _extend_existing_kb_role(
    session: Session,
    cfg: ConnectorConfig,
    cs: ConnectorState,
    kb_id: str,
    secret_arn: str | None,
    cert_s3_bucket: str | None,
    cert_s3_key: str | None,
    *,
    account_id: str,
    opts: _ProvisionOptions,
    content_bucket: str | None = None,
) -> str | None:
    """Extend an existing KB's role to reach this connector's credentials.

    Only adds: the secret and certificate go into statements recognized by Sid,
    or a separate supplemental policy, and S3 content read goes into its own
    policy named for this connector, so it cannot replace another connector's
    grant on the same role. The role belongs to the KB the operator pointed at,
    so it is recorded as external unless state already records it as ours. A failure is
    reported and setup continues, since the role may already grant access.
    """
    from kb_connector.core import provisioning
    from kb_connector.core.teardown import role_name_from_arn

    target = _build_target(cfg, session)
    try:
        resp = target.get_knowledge_base(kb_id)
        kb_obj = resp.get("knowledgeBase", resp)
        role_arn: str | None = kb_obj.get("roleArn")
    except Exception as exc:
        print(f"  WARNING: could not read KB {kb_id} to discover role: {exc}")
        return None
    if not role_arn:
        print(f"  WARNING: KB {kb_id} has no roleArn; skipping role extension.")
        return None

    role_name = role_name_from_arn(role_arn)
    print(f"  Extending existing KB role: {role_name}")
    changed = False
    if secret_arn:
        cert_prefix = cfg.cert_s3_key_prefix if cert_s3_bucket else None
        try:
            summary = provisioning.extend_kb_role_for_secret(
                session=session,
                role_name=role_name,
                secret_arn=secret_arn,
                cert_bucket=cert_s3_bucket,
                cert_key=cert_s3_key,
                cert_key_prefix=cert_prefix,
                account_id=account_id,
                region=cfg.region,
                kms_key_arn=opts.kms_key_arn,
            )
            if summary["secret_added"] or summary["cert_added"]:
                print("  Extended role policy to read this connector's credentials")
                changed = True
            else:
                print("  Role policy already covers these credentials")
        except AwsError as exc:
            print(f"  WARNING: could not extend role: {exc}")
    if content_bucket:
        try:
            _add_s3_content_policy(
                session, role_name, content_bucket, account_id,
                inclusion_prefixes=cfg.get("inclusion_prefixes"),
                policy_name=provisioning.s3_content_policy_name(cfg.name),
            )
            print(f"  Added read access to s3://{content_bucket}")
            changed = True
        except Exception as exc:  # noqa: BLE001 - reported; the role may already allow it
            print(f"  WARNING: could not add S3 read access to the role: {exc}")
    if changed:
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- IAM propagation delay

    # Recorded before kb_role_arn is overwritten, so it compares against what an
    # earlier pass stored.
    _record_reused_resource(cs, state_mod.RESOURCE_ROLE, role_arn)
    cs.kb_role_arn = role_arn
    return role_arn


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
        _import_handoff_resource(
            cs, state_mod.RESOURCE_APP, "client_app_id", source.get("client_id")
        )
        cs.connector_type = handoff.get("type") or cs.connector_type
        # Cert material would need to come from the file referenced in handoff
        print("  Imported handoff (direction: source -> AWS)")
    elif direction == DIRECTION_AWS_TO_SOURCE:
        aws = handoff.get("aws", {})
        _import_handoff_resource(
            cs, state_mod.RESOURCE_KB, "knowledge_base_id",
            aws.get("knowledge_base_id"),
        )
        _import_handoff_resource(
            cs, state_mod.RESOURCE_DS, "data_source_id", aws.get("data_source_id")
        )
        _import_handoff_resource(
            cs, state_mod.RESOURCE_SECRET, "secret_arn", aws.get("secret_arn")
        )
        cs.region = aws.get("region") or cs.region
        print("  Imported handoff (direction: AWS -> source)")
    else:  # pragma: no cover - parse_handoff restricts direction to the two above
        raise ConfigError(f"Unsupported handoff direction {direction!r}.")


def _import_handoff_resource(
    cs: ConnectorState, resource: str, field_name: str, value: str | None
) -> None:
    """Copy one identifier from a handoff document into state, as external.

    A handoff comes from another admin, so whatever it names was created by
    someone else's run. Teardown treats a resource with no ownership record as
    its own, so copying the id without a record would let it delete another
    admin's knowledge base or force-delete their secret. An id state already
    holds is left as recorded: importing the same value again is not evidence
    that ownership changed.
    """
    if not value or getattr(cs, field_name) == value:
        return
    setattr(cs, field_name, value)
    cs.record_external(resource)


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

    kb_role_arn = _ensure_kb_role(
        args=args, cfg=cfg, cs=cs, connector_name=connector_name,
        session=session, account_id=account_id, opts=opts,
        secret_arn=None, content_bucket=bucket_name,
    )

    # Create KB + S3 data source (managed-connector envelope, same as others)
    target = _build_target(cfg, session)
    connector_params = _spec(cfg).build_connector_params(
        cfg, BuildContext(account_id=account_id)
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
    session: Session,
    role_name: str,
    bucket_name: str,
    account_id: str,
    *,
    inclusion_prefixes: list[str] | None = None,
    policy_name: str = "kb-connector-s3-content-access",
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
        PolicyName=policy_name,
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

    from kb_connector.connectors.web import build_secret_body as web_secret
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

    kb_role_arn = _ensure_kb_role(
        args=args, cfg=cfg, cs=cs, connector_name=connector_name,
        session=session, account_id=account_id, opts=opts,
        secret_arn=secret_arn,
    )

    # Create KB + Web data source via the target abstraction
    target = _build_target(cfg, session)
    connector_params = _spec(cfg).build_connector_params(
        cfg, BuildContext(account_id=account_id, secret_arn=secret_arn)
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
    from kb_connector.connectors.confluence import build_secret_body as conf_secret
    from kb_connector.connectors.googledrive import build_secret_body as gd_secret
    from kb_connector.core import provisioning

    cs.connector_type = connector_type

    # --- Stage 1: Guided source-side setup -----------------------------------
    if stage in ("1", "both"):
        print(f"\n── Stage 1: Source-side ({connector_type}) — GUIDED ──")

        steps = _spec(cfg).setup_steps(cfg.raw)
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
                admin_account_email=cfg.get("admin_account_email"),
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

        kb_role_arn = _ensure_kb_role(
            args=args, cfg=cfg, cs=cs, connector_name=connector_name,
            session=session, account_id=account_id, opts=opts,
            secret_arn=secret_arn,
        )

        # Create KB + data source via the target abstraction
        target = _build_target(cfg, session)

        connector_params = _spec(cfg).build_connector_params(
            cfg, BuildContext(account_id=account_id, secret_arn=secret_arn)
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
