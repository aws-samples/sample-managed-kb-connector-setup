"""diagnose subcommand — explain why a connector is failing.

Runs diagnostics: ingestion log analysis, CloudTrail permission check,
secret validation, cert expiry check. Attributes failures to source-side
or AWS-side.
"""

from __future__ import annotations

import argparse
import json
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    # Annotation-only: diagnostics pulls in botocore, and this module is on the
    # --help path.
    from kb_connector.core.diagnostics import CheckResult, DiagnoseResult


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the diagnose subcommand."""
    parser = subparsers.add_parser(
        "diagnose",
        help="Diagnose why a failing connector is failing",
        description=(
            "Run diagnostics: ingestion log analysis, CloudTrail permission check, "
            "secret validation, cert expiry and directory checks. "
            "Attributes failures to source-side or AWS-side."
        ),
    )
    parser.add_argument("connector", nargs="?", help="Connector name from config")
    parser.add_argument("--kb", metavar="KB_ID", help="Knowledge base ID (override)")
    parser.add_argument("--ds", metavar="DS_ID", help="Data source ID (override)")
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    parser.add_argument(
        "--lookback", type=int, default=60,
        help="CloudTrail and log lookback in minutes (default: 60)",
    )
    parser.add_argument(
        "--auth-method", choices=["az", "device_code"], default="az",
        help=(
            "Graph token acquisition for the certificate check (default: az). "
            "Without Graph access that one check reports as unverified and the "
            "rest of the diagnosis still runs."
        ),
    )
    parser.add_argument(
        "--device-client-id",
        help="Public client app id for --auth-method device_code",
    )
    parser.add_argument(
        "--logs", action="store_true",
        help=(
            "Analyze per-document ingestion events from CloudWatch Logs to "
            "explain the scanned-vs-indexed gap. Requires vended log delivery "
            "on the knowledge base and logs:FilterLogEvents on the log group."
        ),
    )
    parser.add_argument(
        "--log-group", metavar="NAME",
        help=(
            "CloudWatch log group holding the KB's APPLICATION_LOGS "
            "(default: /aws/bedrock/knowledgebases/<kb-id>). Implies --logs."
        ),
    )
    parser.add_argument(
        "--no-redact", action="store_true",
        help=(
            "Show full document paths in log analysis instead of redacted ones. "
            "Sample paths name real files; redaction is on by default because "
            "this output gets shared in tickets."
        ),
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the diagnose subcommand."""
    return _run_diagnose(args)


def _run_diagnose(args: argparse.Namespace) -> int:
    from kb_connector import service

    as_json = getattr(args, "json", False)
    if not as_json:
        print(f"Diagnosing connector{': ' + args.connector if args.connector else ''}")

    def _on_check(check: CheckResult) -> None:
        if not as_json:
            _print_check(check)
            _print_log_groups(check)

    result = service.diagnose(
        connector_name=args.connector,
        region=args.region,
        profile=args.profile,
        kb_id=args.kb,
        ds_id=args.ds,
        lookback_minutes=args.lookback,
        include_logs=args.logs,
        log_group_name=args.log_group,
        redact_logs=not args.no_redact,
        check_directory=True,
        graph_auth_method=args.auth_method,
        device_client_id=args.device_client_id,
        config_path=getattr(args, "config", None),
        on_check=_on_check,
    )

    if as_json:
        print(json.dumps(_result_json(result), indent=2))
    else:
        _print_summary(result)
    return 0 if result.status == "healthy" else 1


def _result_json(result: DiagnoseResult) -> dict:
    return {
        "connector": result.connector,
        "status": result.status,
        "attribution": result.attribution,
        "root_cause": result.root_cause,
        "suggested_fix": result.suggested_fix,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "details": c.details,
                "side": c.side,
                "data": c.data,
            }
            for c in result.checks
        ],
    }


def _print_summary(result: DiagnoseResult) -> None:
    print(f"\n{'─' * 50}")
    print(f"Diagnosis ({result.connector}): {result.status.upper()}")
    if result.status != "healthy":
        print(f"Attribution: {result.attribution}-side")
    if result.root_cause:
        print(f"Root cause: {result.root_cause}")
    if result.suggested_fix:
        print(f"Suggested fix: {result.suggested_fix}")


def _print_check(check: CheckResult) -> None:
    """Print a single check result."""
    icon = "✓" if check.passed else "✗"
    print(f"    {icon} {check.name}: {check.details}")


def _print_log_groups(check: CheckResult) -> None:
    """Print the per-reason breakdown from log analysis, largest group first.

    The grouping is the useful part of this check: one line per (status,
    reason) turns "360 documents didn't make it" into a short list of causes.
    """
    groups = (check.data or {}).get("groups") or []
    if not groups:
        return
    print("      Document outcomes by reason:")
    for g in groups[:8]:
        status = g.get("status") or "UNKNOWN"
        reason = g.get("reason") or "(no reason given)"
        print(f"        {g.get('count', 0):>6}  {status:<9} {reason}")
        for sample in (g.get("sample_documents") or [])[:3]:
            if sample:
                print(f"                         e.g. {sample}")
    if (check.data or {}).get("redacted"):
        print("      (document paths redacted; --no-redact shows them in full)")
