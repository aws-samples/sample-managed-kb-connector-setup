"""probe subcommand — low-level connector-parameter inspection.

Drives a raw connectorParameters JSON body end-to-end against the bedrock-agent
API and captures every request/response. The round-trip GetDataSource response
shows which fields the service kept, defaulted, or dropped.

This is a maintainer/advanced-debugging tool, not a day-to-day command — the
high-level commands (setup, diagnose) cover the common cases.
"""

from __future__ import annotations

import argparse
import sys

from kb_connector.core.errors import ConnectorError


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the probe subcommand (advanced/maintainer use)."""
    parser = subparsers.add_parser(
        "probe",
        help="[advanced] Submit a raw connectorParameters body and inspect the result",
        description=(
            "Take a raw connectorParameters JSON body and drive it end-to-end, "
            "capturing request/response bodies. The round-trip GetDataSource "
            "response shows which fields the service kept, defaulted, or dropped. "
            "A maintainer/debugging tool, not a day-to-day command."
        ),
    )
    parser.add_argument("connector_params_file", help="JSON file with connectorParameters body")
    parser.add_argument("--secret-body", dest="secret_body_file", metavar="FILE",
                        help="JSON file with the secret body to create")
    parser.add_argument("--secret-name", help="Secrets Manager secret name")
    parser.add_argument("--kb", dest="knowledge_base_id", metavar="KB_ID",
                        help="Reuse an existing KB")
    parser.add_argument("--create-kb", action="store_true", help="Create a new KB")
    parser.add_argument("--create-kb-role", action="store_true",
                        help="Provision a KB service role")
    parser.add_argument("--kb-role-arn", help="Use an existing role ARN")
    parser.add_argument("--kb-role-name", default="kb-connector-probe-role",
                        help="Role name for --create-kb-role")
    parser.add_argument("--kb-name", default="kb-connector-probe", help="Name for new KB")
    parser.add_argument("--ds-name", default="probe-ds", help="Data source name")
    parser.add_argument("--ingest", action="store_true", help="Start + poll ingestion")
    parser.add_argument("--retrieve-query", help="Run a retrieve with this query")
    parser.add_argument("--out-dir", help="Capture output directory")
    parser.add_argument("--poll-interval", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--cert-s3-bucket", help="Cert bucket (for role extension)")
    parser.add_argument("--cert-s3-key", help="Cert key (for role extension)")
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the probe subcommand."""
    try:
        return _run_probe(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_probe(args: argparse.Namespace) -> int:
    import boto3
    from kb_connector.core.config import load_config
    from kb_connector.probe.driver import ProbeArgs, run_probe

    config = load_config(getattr(args, "config", None))
    region = args.region or config.defaults.get("region")
    if not region:
        raise ConnectorError("No region. Pass --region or set defaults.region in config.")
    profile = args.profile or config.defaults.get("profile")

    session = boto3.Session(region_name=region, profile_name=profile)

    probe_args = ProbeArgs(
        connector_params_file=args.connector_params_file,
        secret_body_file=args.secret_body_file,
        secret_name=args.secret_name,
        knowledge_base_id=args.knowledge_base_id,
        create_kb=args.create_kb,
        create_kb_role=args.create_kb_role,
        kb_role_arn=args.kb_role_arn,
        kb_role_name=args.kb_role_name,
        kb_name=args.kb_name,
        data_source_name=args.ds_name,
        ingest=args.ingest,
        poll_interval_seconds=args.poll_interval,
        timeout_seconds=args.timeout,
        retrieve_query=args.retrieve_query,
        out_dir=args.out_dir,
        cert_s3_bucket=args.cert_s3_bucket,
        cert_s3_key=args.cert_s3_key,
    )

    result = run_probe(probe_args, session=session, region=region)

    print(f"\nProbe run: {result.connector_type}")
    print(f"  output: {result.out_dir}")
    print(f"  kb={result.knowledge_base_id}, ds={result.data_source_id}")
    print(f"  result: {'OK' if result.ok else 'had failures (see capture)'}")
    for e in result.events:
        icon = "✓" if e["ok"] else "✗"
        print(f"    {icon} {e['step']}: {e['detail']}")

    return 0 if result.ok else 1
