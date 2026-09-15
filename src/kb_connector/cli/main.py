"""Top-level CLI parser and subcommand dispatch."""

from __future__ import annotations

import argparse
import sys

from kb_connector import __version__
from kb_connector.cli import (
    diagnose,
    handoff,
    init_cmd,
    monitor,
    probe,
    setup,
    teardown,
    validate,
)
from kb_connector.core.errors import ConnectorError


def _render_known_error(exc: BaseException, *, profile: str | None) -> str | None:
    """Map a known-but-uncaught exception to a clean, actionable message.

    Returns a message string for recognized credential, connection, and AWS
    client errors, or None if the exception is unexpected and should surface as
    a traceback. Covers the error class the CLI can hit outside a ConnectorError
    — for example an expired SSO token or a transient socket error raised by
    botocore before library code wraps it.
    """
    # ConnectorError already carries an operator-actionable message.
    if isinstance(exc, ConnectorError):
        return str(exc)

    # botocore is imported lazily so --help and pure-logic paths don't pay the
    # import cost.
    try:
        from botocore import exceptions as bexc
    except ImportError:
        return None

    login_hint = (
        f"aws sso login --profile {profile}" if profile else "aws sso login"
    )

    # Expired or unavailable credentials.
    if isinstance(
        exc,
        (
            bexc.TokenRetrievalError,
            bexc.UnauthorizedSSOTokenError,
            bexc.SSOTokenLoadError,
        ),
    ):
        return (
            "AWS credentials expired or unavailable. "
            f"Run `{login_hint}` and try again."
        )
    if isinstance(exc, (bexc.NoCredentialsError, bexc.PartialCredentialsError)):
        return (
            "No AWS credentials found. Configure a profile or SSO session "
            f"(e.g. `{login_hint}`), or set AWS_PROFILE / AWS_ACCESS_KEY_ID."
        )
    if isinstance(exc, bexc.ProfileNotFound):
        return (
            f"{exc} Check the --profile value or your ~/.aws/config."
        )

    # Transient network conditions.
    if isinstance(
        exc,
        (
            bexc.EndpointConnectionError,
            bexc.ConnectionClosedError,
            bexc.ConnectTimeoutError,
            bexc.ReadTimeoutError,
            bexc.ConnectionError,
        ),
    ):
        return (
            "Lost connection to AWS while making a request. This is usually "
            "transient — check your network and try again."
        )

    # Structured AWS API errors: render the code + message, and special-case
    # the ones with an obvious next step.
    if isinstance(exc, bexc.ClientError):
        err = exc.response.get("Error", {}) if hasattr(exc, "response") else {}
        code = err.get("Code", "")
        message = err.get("Message", str(exc))
        if code in ("ExpiredToken", "ExpiredTokenException"):
            return (
                "AWS security token expired. "
                f"Run `{login_hint}` and try again."
            )
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return f"Access denied by AWS: {message}"
        if code:
            return f"AWS error ({code}): {message}"
        return f"AWS error: {message}"

    return None


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="kb-connector",
        description=(
            "Set up, monitor, validate, and diagnose "
            "AWS Bedrock Knowledge Base connectors."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output raw JSON (for CI/piping)"
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; fail on missing inputs",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to config file (default: ./kb-connector.toml)",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        description="Use 'kb-connector <command> --help' for details.",
    )

    # Register all subcommands
    init_cmd.register(subparsers)
    setup.register(subparsers)
    monitor.register(subparsers)
    validate.register(subparsers)
    diagnose.register(subparsers)
    handoff.register(subparsers)
    teardown.register(subparsers)
    # Advanced: low-level connector-parameter inspection
    probe.register(subparsers)

    return parser


def main() -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level boundary handler
        message = _render_known_error(exc, profile=getattr(args, "profile", None))
        if message is None:
            # Unexpected: let it surface as a traceback so bugs stay visible.
            raise
        print(f"\nError: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
