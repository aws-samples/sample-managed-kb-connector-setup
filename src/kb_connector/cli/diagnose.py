"""diagnose subcommand — explain why a connector is failing.

Runs diagnostics: ingestion log analysis, CloudTrail permission check,
secret validation, cert expiry check. Attributes failures to source-side
or AWS-side.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

from kb_connector.core.config import load_config
from kb_connector.core.errors import ConfigError, ConnectorError
from kb_connector.core.state import load_state

if TYPE_CHECKING:
    # Annotation-only: diagnostics pulls in botocore, and this module is on the
    # --help path.
    from kb_connector.core.diagnostics import CheckResult
    from kb_connector.core.state import ConnectorState


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the diagnose subcommand."""
    parser = subparsers.add_parser(
        "diagnose",
        help="Diagnose why a failing connector is failing",
        description=(
            "Run diagnostics: ingestion log analysis, CloudTrail permission check, "
            "secret validation, credential mint check, cert expiry check. "
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
    try:
        return _run_diagnose(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_diagnose(args: argparse.Namespace) -> int:
    from kb_connector.core.diagnostics import (
        CheckResult, build_diagnose_result,
        check_cert_expiry, check_certificate_installed,
        check_cloudtrail_permissions, check_ingestion_logs,
        check_secret_validity, default_log_group_name,
    )
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
                    "No connectors configured. Pass --kb/--ds or run init first."
                )
            connector_name = "_direct"
        else:
            raise ConfigError(
                f"Multiple connectors: {', '.join(names)}. Specify one."
            )

    # Resolve state + config
    cs = state_file.get(connector_name) if connector_name != "_direct" else None

    cli_overrides = {}
    if args.region:
        cli_overrides["region"] = args.region
    if args.profile:
        cli_overrides["profile"] = args.profile

    region = args.region
    profile = args.profile
    credential = "cert"
    connector_type = "sharepoint"

    if connector_name != "_direct" and config.connector_names():
        cfg = config.resolve_connector(connector_name, cli_overrides=cli_overrides)
        region = region or cfg.region
        profile = profile or cfg.profile
        credential = cfg.credential or "cert"
        connector_type = cfg.type

    if not region:
        raise ConfigError("No region available. Pass --region or set it in config.")

    session = boto3.Session(region_name=region, profile_name=profile)
    print(f"Diagnosing connector: {connector_name}")

    checks: list[CheckResult] = []

    # 1. Secret validation
    secret_arn = cs.secret_arn if cs else None
    if secret_arn:
        print("  Checking secret...")
        check = check_secret_validity(
            session=session,
            secret_arn=secret_arn,
            connector_type=connector_type,
            credential=credential,
        )
        checks.append(check)
        _print_check(check)
    else:
        print("  Secret ARN not in state; skipping secret check.")

    # 2. Certificate expiry
    cert_not_after = cs.cert_not_after if cs else None
    if cert_not_after or credential == "cert":
        print("  Checking certificate expiry...")
        check = check_cert_expiry(cert_not_after=cert_not_after)
        checks.append(check)
        _print_check(check)

    # 2b. Is that certificate still the one the app trusts? Expiry is read from
    # state, so it says nothing about whether the directory still carries the
    # certificate — the two halves of the credential can drift apart.
    if credential == "cert" and cs and cs.client_app_object_id:
        print("  Checking the certificate is installed on the app...")
        check = check_certificate_installed(
            recorded_thumbprint=cs.cert_thumbprint_b64url,
            installed_thumbprints=_installed_thumbprints(args, cs),
        )
        checks.append(check)
        _print_check(check)

    # 3. CloudTrail permission check
    role_arn = cs.kb_role_arn if cs else None
    print("  Scanning CloudTrail for permission issues...")
    check = check_cloudtrail_permissions(
        session=session,
        region=region,
        role_arn=role_arn,
        secret_arn=secret_arn,
        lookback_minutes=args.lookback,
    )
    checks.append(check)
    _print_check(check)

    # 4. Ingestion log analysis (opt-in: needs vended log delivery configured
    #    on the KB plus logs:FilterLogEvents, so it isn't part of the default
    #    check set).
    kb_id = args.kb or (cs.knowledge_base_id if cs else None)
    if args.logs or args.log_group:
        log_group = args.log_group
        if not log_group:
            if not kb_id:
                raise ConfigError(
                    "Log analysis needs a knowledge base id to derive the log "
                    "group. Pass --kb, or name the group with --log-group."
                )
            log_group = default_log_group_name(kb_id)
        print(f"  Analyzing ingestion logs ({log_group})...")
        check = check_ingestion_logs(
            session=session,
            log_group_name=log_group,
            lookback_minutes=args.lookback,
            redact=not args.no_redact,
        )
        checks.append(check)
        _print_check(check)
        _print_log_groups(check)

    # Build aggregate result
    result = build_diagnose_result(connector_name, checks)

    # Render
    print(f"\n{'─' * 50}")
    print(f"Diagnosis: {result.status.upper()}")
    if result.status != "healthy":
        print(f"Attribution: {result.attribution}-side")
    if result.root_cause:
        print(f"Root cause: {result.root_cause}")
    if result.suggested_fix:
        print(f"Suggested fix: {result.suggested_fix}")

    # JSON output mode
    if getattr(args, "json", False):
        output = {
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
        print(json.dumps(output, indent=2))

    return 0 if result.status == "healthy" else 1


def _installed_thumbprints(
    args: argparse.Namespace, cs: ConnectorState
) -> list[str] | None:
    """Read the app's certificate thumbprints, or None if the directory is
    unreachable.

    Returning None rather than raising is deliberate: an operator diagnosing the
    AWS side of a connector often has no Graph access at all, and one
    unverifiable check should not take the whole diagnosis down. The caller turns
    None into an "unverified" result.
    """
    if not cs.tenant_id or not cs.client_app_object_id:
        return None
    try:
        from kb_connector.providers.microsoft.apps import (
            list_certificate_thumbprints,
        )
        from kb_connector.providers.microsoft.client import GraphClient

        graph = GraphClient.from_auth(
            method=getattr(args, "auth_method", "az"),
            tenant_id=cs.tenant_id,
            device_client_id=getattr(args, "device_client_id", None),
        )
        return list_certificate_thumbprints(graph, cs.client_app_object_id)
    except Exception:  # noqa: BLE001 - no Graph access is an expected outcome
        return None


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
