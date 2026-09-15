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
    """An AWS-side operation (Secrets Manager, S3, IAM, bedrock-agent) failed."""


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
