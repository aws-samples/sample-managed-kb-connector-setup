"""handoff subcommand — export state for split-admin workflows.

Generate a portable handoff file for split-admin workflows:
  * Source admin exports for AWS admin (source -> aws)
  * AWS admin exports for source admin (aws -> source)
"""

from __future__ import annotations

import argparse
import sys

from kb_connector.core.config import load_config
from kb_connector.core.errors import ConnectorError
from kb_connector.core.fileio import atomic_write_json
from kb_connector.core.handoff import build_aws_to_source, build_source_to_aws
from kb_connector.core.state import load_state


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the handoff subcommand."""
    parser = subparsers.add_parser(
        "handoff",
        help="Export state for a different admin to continue setup",
        description=(
            "Generate a portable handoff file for split-admin workflows. "
            "Source admin exports for AWS admin, or vice versa."
        ),
    )
    parser.add_argument("connector", help="Connector name from config")
    parser.add_argument(
        "--to", choices=["aws", "source"], default="aws",
        help="Direction: export for 'aws' admin or 'source' admin (default: aws)",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Output file path (default: auto-named)"
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the handoff subcommand."""
    try:
        return _run_handoff(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_handoff(args: argparse.Namespace) -> int:
    config = load_config(getattr(args, "config", None))
    state_file = load_state()

    connector_name = args.connector
    cs = state_file.get(connector_name)

    # Resolve config (may be absent if user is operating outside their config)
    cfg = None
    if connector_name in config.connector_names():
        cfg = config.resolve_connector(connector_name)

    direction = args.to
    if direction == "aws":
        handoff = build_source_to_aws(connector_name, cs, cfg)
    else:
        handoff = build_aws_to_source(connector_name, cs, cfg)

    # Write output with owner-only permissions. The document holds no secret
    # values, but it does hold the tenant id, application id, and
    # account-bearing ARNs — enough to map the target environment — and it is
    # explicitly meant to be moved between machines.
    output_path = args.output or f"{connector_name}.handoff.json"
    atomic_write_json(output_path, handoff, indent=2)

    print(f"Handoff file written to: {output_path} (mode 0600)")
    print(f"  direction: {handoff['direction']}")
    print(f"  connector: {connector_name} ({handoff.get('type', 'unknown')})")
    print(
        "\n  This file identifies your tenant, app registration, and AWS "
        "account. Transfer it over a channel you'd use for a credential, and "
        "delete it when setup is done."
    )
    print(f"\nShare this file with your {'AWS' if direction == 'aws' else 'source'} admin.")
    if direction == "aws":
        print("They can import it with: kb-connector setup <name> --from-handoff <file>")
    return 0
