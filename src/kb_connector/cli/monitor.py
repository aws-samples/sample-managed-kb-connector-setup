"""monitor subcommand — start + poll ingestion, show stats."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from kb_connector.core.config import load_config
from kb_connector.core.errors import ConfigError, ConnectorError, StateError
from kb_connector.core.state import load_state, save_state

if TYPE_CHECKING:
    # Annotation-only: core.monitor pulls in botocore, and this module is on the
    # --help path.
    from kb_connector.core.monitor import MonitorResult


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the monitor subcommand."""
    parser = subparsers.add_parser(
        "monitor",
        help="Monitor ingestion job progress and stats",
        description=(
            "Start a new ingestion job or poll an existing one. Shows document "
            "counts, timing, and per-document status when available."
        ),
    )
    parser.add_argument("connector", nargs="?", help="Connector name from config")
    parser.add_argument("--kb", metavar="KB_ID", help="Knowledge base ID (override)")
    parser.add_argument("--ds", metavar="DS_ID", help="Data source ID (override)")
    parser.add_argument(
        "--start", action="store_true", default=True,
        help="Start a new ingestion job (default)",
    )
    parser.add_argument(
        "--no-start", action="store_true",
        help="Poll the latest job without starting a new one",
    )
    parser.add_argument(
        "--job", metavar="JOB_ID",
        help=(
            "Poll a specific ingestion job by ID (implies --no-start). Use this "
            "to resume watching a job without editing the state file."
        ),
    )
    parser.add_argument(
        "--poll-interval", type=int, default=10,
        help="Seconds between status checks (default: 10)",
    )
    parser.add_argument(
        "--timeout", type=int, default=1800,
        help="Max seconds to wait for completion (default: 1800)",
    )
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the monitor subcommand."""
    try:
        return _run_monitor(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_monitor(args: argparse.Namespace) -> int:
    from kb_connector.core.monitor import poll_job, start_and_poll
    from kb_connector.targets import get_target
    import boto3

    config = load_config(getattr(args, "config", None))
    state_file = load_state()

    # Resolve connector
    connector_name = args.connector
    if not connector_name:
        names = config.connector_names()
        if len(names) == 1:
            connector_name = names[0]
        elif not names:
            if not (args.kb and args.ds):
                raise ConfigError(
                    "No connectors configured and no --kb/--ds provided."
                )
            connector_name = "_direct"
        else:
            raise ConfigError(
                f"Multiple connectors: {', '.join(names)}. Specify one."
            )

    # Resolve KB/DS IDs
    cs = state_file.get(connector_name) if connector_name != "_direct" else None
    kb_id = args.kb or (cs.knowledge_base_id if cs else None)
    ds_id = args.ds or (cs.data_source_id if cs else None)
    if not kb_id or not ds_id:
        raise StateError(
            "Need --kb and --ds, or run setup first to populate state."
        )

    # Resolve region
    cli_overrides = {}
    if args.region:
        cli_overrides["region"] = args.region
    if args.profile:
        cli_overrides["profile"] = args.profile

    region = args.region
    profile = args.profile
    if connector_name != "_direct" and config.connector_names():
        cfg = config.resolve_connector(connector_name, cli_overrides=cli_overrides)
        region = region or cfg.region
        profile = profile or cfg.profile

    if not region:
        raise ConfigError("No region available. Pass --region or set it in config.")

    session = boto3.Session(region_name=region, profile_name=profile)
    target = get_target("bmkb", session=session, region=region)

    # An explicit --job means "resume this job" and implies --no-start.
    do_start = not args.no_start and not args.job
    print(f"Monitor: kb={kb_id}, ds={ds_id}")

    def _persist_job_id(job_id: str) -> None:
        """Save the job id to state the instant a job exists.

        Called before the first poll so a dropped poll loop never orphans the
        job — the operator can resume with `--no-start` or `--job <id>`.
        """
        if cs:
            cs.last_ingestion_job_id = job_id
            state_file.set(connector_name, cs)
            save_state(state_file)

    if do_start:
        print("Starting ingestion job...")
        result = start_and_poll(
            target, kb_id=kb_id, ds_id=ds_id,
            poll_interval_seconds=args.poll_interval,
            timeout_seconds=args.timeout,
            on_job_started=_persist_job_id,
        )
    else:
        job_id = args.job or (cs.last_ingestion_job_id if cs else None)
        if not job_id:
            raise StateError(
                "No job to poll. Pass --job <id> to resume a specific job, or "
                "run with --start (the default) to begin one. A job id is also "
                "read from state if setup/monitor recorded one."
            )
        print(f"Polling existing job: {job_id}")
        result = poll_job(
            target, kb_id=kb_id, ds_id=ds_id, job_id=job_id,
            poll_interval_seconds=args.poll_interval,
            timeout_seconds=args.timeout,
        )

    # Render results
    _render_result(result)

    # Save final job ID to state (idempotent with the on-start persist above).
    if cs:
        cs.last_ingestion_job_id = result.job_id
        state_file.set(connector_name, cs)
        save_state(state_file)

    return 0 if result.stats.status in ("COMPLETE", "COMPLETED") else 1


def _render_result(result: MonitorResult) -> None:
    """Pretty-print monitor results."""
    stats = result.stats
    if result.timed_out:
        print("\n  (timed out waiting for terminal state)")

    print(f"\nIngestion summary (job {result.job_id}):")
    print(f"  status:            {stats.status}")
    print(f"  scanned:           {stats.scanned}")
    print(
        f"  indexed:           {stats.indexed_total} "
        f"(new={stats.new_indexed}, modified={stats.modified_indexed})"
    )
    print(f"  failed:            {stats.failed}")
    print(f"  skipped:           {stats.skipped}")
    print(f"  deleted:           {stats.deleted}")
    print(f"  metadata scanned:  {stats.metadata_scanned}")
    print(f"  metadata modified: {stats.metadata_modified}")

    if stats.failure_reasons:
        for reason in stats.failure_reasons[:10]:
            print(f"  failure: {reason}")

    if stats.has_acl_warning:
        print(
            f"\n  WARNING: {stats.skipped} documents skipped "
            f"(only {stats.indexed_total}/{stats.scanned} indexed). "
            "Common cause: crawlAcl=true with missing ACL permissions."
        )
