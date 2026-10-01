"""monitor subcommand — start + poll ingestion, show stats."""

from __future__ import annotations

import argparse
import time
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    # Annotation-only: core.monitor pulls in botocore, and this module is on the
    # --help path.
    from kb_connector.core.monitor import IngestionStats, MonitorResult


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
    return _run_monitor(args)


def _run_monitor(args: argparse.Namespace) -> int:
    from kb_connector import service

    # An explicit --job means "resume this job" and implies --no-start.
    do_start = not args.no_start and not args.job
    # Progress lines are flushed so they reach a file or pipe as they happen,
    # not only when the job ends.
    print(
        "Starting ingestion job..." if do_start else "Polling ingestion job...",
        flush=True,
    )
    started = time.monotonic()

    def _on_started(job_id: str) -> None:
        print(f"  job {job_id}", flush=True)

    def _on_poll(stats: IngestionStats) -> None:
        elapsed = int(time.monotonic() - started)
        print(
            f"  {elapsed // 60:>3}m{elapsed % 60:02d}s  {stats.status:<12} "
            f"scanned={stats.scanned} indexed={stats.indexed_total} "
            f"failed={stats.failed}",
            flush=True,
        )

    result = service.monitor(
        connector_name=args.connector,
        region=args.region,
        profile=args.profile,
        kb_id=args.kb,
        ds_id=args.ds,
        job_id=args.job,
        start=do_start,
        poll_interval_seconds=args.poll_interval,
        timeout_seconds=args.timeout,
        config_path=getattr(args, "config", None),
        on_job_started=_on_started,
        on_poll=_on_poll,
    )
    _render_result(result)
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
