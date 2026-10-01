"""teardown subcommand — clean up resources created by setup.

Conservative by default: only deletes what the tool created (tracked in state),
prompts for confirmation on every destructive action.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from kb_connector.service import TeardownEvent, TeardownPlan


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
    return _run_teardown(args)


def _run_teardown(args: argparse.Namespace) -> int:
    from kb_connector import service

    plan = service.plan_teardown(
        connector_name=args.connector,
        only=args.only,
        include_adopted=args.include_adopted,
        region=args.region,
        profile=args.profile,
        config_path=getattr(args, "config", None),
    )
    if not plan.tracked:
        print(f"No resources tracked in state for {plan.connector!r}. Nothing to tear down.")
        return 0

    _render_plan(plan, dry_run=args.dry_run)

    if not plan.delete:
        # Every tracked resource is adopted. The state entry is the only record
        # that this connector is attached to them, so it is kept.
        print(
            f"\n  Nothing to delete: all {len(plan.keep)} tracked resource(s) were "
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

    if not args.yes:
        print()
        response = input("  Proceed with teardown? (y/N): ").strip().lower()
        if response not in ("y", "yes"):
            print("  Canceled.")
            return 0

    result = service.execute_teardown(
        plan,
        force=args.force,
        auth_method=args.auth_method,
        device_client_id=args.device_client_id,
        on_event=_render_event,
    )

    if result.blocked_by_job:
        cs = plan.ctx.cs
        print(
            f"\n  Refusing to tear down: ingestion job {result.blocked_by_job} is "
            f"in progress on data source {cs.data_source_id}."
        )
        print(
            f"  Re-run with --force to stop the job first, or run "
            f"`aws bedrock-agent stop-ingestion-job --knowledge-base-id "
            f"{cs.knowledge_base_id} --data-source-id {cs.data_source_id} "
            f"--ingestion-job-id {result.blocked_by_job} --region {plan.region}` "
            f"and wait for it to finish."
        )
        return 1

    if plan.keep:
        print(
            f"\n  Keeping tracked state for {plan.connector!r}: "
            f"{len(plan.keep)} adopted resource(s) still exist."
        )
    if result.state_cleared:
        print("\n  Teardown complete. Connector state cleared.")
    elif result.ok:
        print("\n  Teardown complete. State updated.")
    else:
        print(
            f"\n  Teardown incomplete: {len(result.failed)} failed, "
            f"{len(result.skipped)} skipped. State updated; re-run teardown to retry."
        )
    return 0 if result.ok else 1


def _render_plan(plan: TeardownPlan, *, dry_run: bool) -> None:
    print(f"Teardown for connector: {plan.connector}")
    print(f"  type: {plan.connector_type or 'unknown'}")
    if plan.region:
        print(f"  region: {plan.region}")
    if plan.delete:
        print(f"\n  Resources to {'delete (DRY RUN)' if dry_run else 'delete'}:")
        for item in plan.delete:
            note = " [ADOPTED — deleting because --include-adopted]" if item.adopted else ""
            print(f"    • {item.description}{note}")
    if plan.keep:
        print("\n  Kept (adopted by this tool, not created by it):")
        for item in plan.keep:
            print(f"    • {item.description}")
        print(
            "    These were pre-existing when the connector was set up. Use "
            "--include-adopted to delete them too, or remove them yourself."
        )


def _render_event(event: TeardownEvent) -> None:
    item = event.item
    if event.kind == "deleted" and item:
        print(f"    ✓ Deleted {item.description}")
    elif event.kind == "failed" and item:
        print(f"    ✗ Failed to delete {item.description}: {event.detail}")
    elif event.kind == "skipped" and item:
        print(
            f"    ⊘ Skipping {item.description} — AWS-side delete failed earlier; "
            f"upstream credentials left intact for retry."
        )
    elif event.kind == "job_stopping":
        print(f"\n  --force: stopping ingestion job {event.detail}...")
    elif event.kind == "job_stopped":
        print(f"    ingestion job reached {event.detail}")
    elif event.kind == "job_still_stopping":
        print("    (ingestion job still stopping at the deadline — proceeding anyway)")
    elif event.kind == "job_stop_failed":
        print(f"    (stop request failed: {event.detail} — proceeding anyway)")
    elif event.kind == "job_check_failed":
        print(
            f"  WARNING: could not check for a running ingestion job: {event.detail}\n"
            f"  Proceeding without that check. If a job is in flight, deleting "
            f"its credentials now will fail the job.",
            file=sys.stderr,
        )
