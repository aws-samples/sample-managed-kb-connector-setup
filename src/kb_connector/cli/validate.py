"""validate subcommand — verify a connector works end-to-end.

Wraps service.validate, which runs structured checks:
  * Token mint (informational, for Entra connectors).
  * Retrieve — for non-ACL connectors, a single retrieve.
  * For ACL-enabled connectors, three retrieves: with the authorized user
    (expect non-zero), with the unauthorized user (expect zero), and with
    no userContext (expect zero, proving the ACL filter is active).

Test query and users come from the connector's [validation] config block
by default. CLI flags override.
"""

from __future__ import annotations

import argparse
import sys

from kb_connector import service
from kb_connector.core.errors import ConnectorError


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the validate subcommand."""
    parser = subparsers.add_parser(
        "validate",
        help="Validate that a connector configuration actually works",
        description=(
            "Run checks to verify the connector is healthy. For ACL-enabled "
            "connectors, runs an authorized/denied/no-user retrieve trio "
            "using the [validation] block in your config."
        ),
    )
    parser.add_argument("connector", nargs="?", help="Connector name from config")
    parser.add_argument("--kb", metavar="KB_ID", help="Knowledge base ID (override)")
    parser.add_argument(
        "--all", action="store_true", help="Validate all connectors in config"
    )
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--profile", help="AWS profile override")
    parser.add_argument(
        "--query", help="Query text for the test retrieve",
    )
    parser.add_argument(
        "--user-id", dest="authorized_user", metavar="EMAIL",
        help="Authorized user (expect results); overrides config",
    )
    parser.add_argument(
        "--unauthorized-user-id", dest="unauthorized_user", metavar="EMAIL",
        help="Unauthorized user (expect zero); overrides config",
    )
    parser.add_argument(
        "--skip-retrieve", action="store_true",
        help="Skip the retrieve checks (only run informational checks)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the validate subcommand."""
    try:
        return _run_validate(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1


def _run_validate(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    if args.all:
        from kb_connector.core.config import load_config
        config = load_config(config_path)
        names: list[str | None] = list(config.connector_names())
        if not names:
            print("Error: No connectors in config to validate.", file=sys.stderr)
            return 1
    else:
        names = [args.connector] if args.connector else [None]

    all_healthy = True
    for n in names:
        result = service.validate(
            connector_name=n,
            region=args.region,
            profile=args.profile,
            kb_id=args.kb,
            query=args.query,
            authorized_user=args.authorized_user,
            unauthorized_user=args.unauthorized_user,
            skip_retrieve=args.skip_retrieve,
            config_path=config_path,
        )
        _render(result)
        if not result.healthy:
            all_healthy = False

    return 0 if all_healthy else 1


def _render(result) -> None:
    """Pretty-print a ValidateResult."""
    print(f"\n{'═' * 50}")
    print(f"Validating: {result.connector}")
    print(f"{'═' * 50}")
    for check in result.checks:
        icon = "✓" if check.passed else "✗"
        print(f"  {icon} {check.name}: {check.details}")
    for note in result.notes:
        print(f"  ⊘ {note}")
    if not result.checks:
        print("  No checks ran. Provide more state/config.")
        return
    failed = [c for c in result.checks if not c.passed]
    if failed:
        print(f"\n  Result: FAILING ({len(failed)}/{len(result.checks)} checks failed)")
    else:
        print(f"\n  Result: HEALTHY ({len(result.checks)}/{len(result.checks)} checks passed)")
