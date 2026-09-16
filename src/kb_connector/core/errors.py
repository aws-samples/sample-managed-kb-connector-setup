"""Shared error types for the KB Connector Helper.

These are intentionally small. The goal is to let library code raise an error
with an operator-actionable message, and have the CLI top-level turn it into
a clean non-zero exit instead of a traceback.
"""

from __future__ import annotations


class ConnectorError(Exception):
    """Base for all expected, operator-actionable failures.

    Anything that inherits from this is treated as a "clean" error by the CLI:
    the message is printed without a traceback and the process exits non-zero.
    Unexpected exceptions (bugs) still surface as tracebacks.
    """


class ConfigError(ConnectorError):
    """Configuration is missing, invalid, or conflicting."""


class StateError(ConnectorError):
    """The state file is missing a value that an operation needs.

    Typically means an earlier step wasn't run or was run against a different
    connector, and the operator needs to either run it or pass the value
    explicitly via CLI flags.
    """


class AwsError(ConnectorError):
    """An AWS-side operation (Secrets Manager, S3, IAM, bedrock-agent) failed.

    Carries the service's error code when the failure came from an AWS API, so
    the CLI can still recognize the codes that have an obvious next step — an
    expired token, an access denial — after library code has wrapped the
    original exception.
    """

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def aws_error_from(exc: Exception) -> AwsError:
    """Wrap a botocore exception as an AwsError, keeping its error code.

    The botocore shape is read by duck typing rather than by importing
    botocore, which keeps this module free of the dependency and importable on
    the `--help` path. A structured API failure carries
    `response["Error"]["Code"]`; anything else (a connection or timeout error)
    has no code and falls back to its string form.

    The message mirrors the format the CLI uses for an unwrapped botocore
    error, so the code and the service's own wording both survive wrapping.
    """
    response = getattr(exc, "response", None)
    err = response.get("Error", {}) if isinstance(response, dict) else {}
    code = err.get("Code") or None
    message = err.get("Message") or str(exc)
    return AwsError(
        f"AWS error ({code}): {message}" if code else f"AWS error: {message}",
        code=code,
    )


class GraphError(ConnectorError):
    """A Microsoft Graph / Entra token-endpoint call failed.

    Carries the HTTP status and parsed body when available so callers can make
    decisions (e.g. distinguish 401 auth failures from 403 consent failures).
    """

    def __init__(self, message: str, *, status: int | None = None, body: object = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class ProviderError(ConnectorError):
    """A source-side identity provider operation failed (Entra, Google, etc.)."""


class PreflightError(ConnectorError):
    """A required credential or tool is missing/unusable.

    Raised by preflight checks before any real work begins, so the operator
    finds out immediately rather than halfway through setup.
    """
