"""SigV4-signed HTTP client for the bedrock-agent JSON API.

Why not the typed boto3 client? The public boto3 model did not expose the
MANAGED_KNOWLEDGE_BASE_CONNECTOR data-source envelope
(managedKnowledgeBaseConnectorConfiguration) or the top-level userContext
field on Retrieve until 1.43.32, so a typed call against an older boto3
rejects the managed-connector payload during serialization and ACL retrieves
do not work. This client is what has been validated end-to-end, so it is what
ships; a future release will retire it in favour of typed boto3 calls.
KNOWN-LIMITATIONS.md has the full picture.

This client signs raw JSON requests with SigV4 (the same thing
`awscurl --service bedrock` does) so we control the exact body.

Resilience: long-running poll loops (ingestion monitor, KB/DS waiters) make
many GETs over minutes, so a single transient network blip must not abort the
whole operation. The client retries transient failures with exponential backoff
+ jitter, with an idempotency-aware policy (see _classify_*): GETs retry on any
transient error; non-idempotent writes retry only when the request provably did
not reach or was rejected by the service (connection errors, throttling), never
on an ambiguous read timeout or 5xx that may have already been processed.
"""

from __future__ import annotations

import json
import random
import sys
import time
from typing import Any

from kb_connector.core.errors import AwsError

_SIGNING_SERVICE = "bedrock"
_TIMEOUT = 60

# Hosts this client will sign requests to. Every request carries a SigV4
# signature computed with the caller's live credentials, so the destination is
# a security boundary: a request sent to a host an attacker controls hands them
# a valid Authorization header for service "bedrock" plus the request body
# (which includes secret ARNs), and that header is replayable against the real
# endpoint inside its signing window.
#
# endpoint_url / runtime_endpoint_url exist as a pre-production testing hook and
# are reachable from config *and* from the environment
# (KB_CONNECTOR_ENDPOINT_URL), which means a poisoned config file or an
# inherited env var in CI is enough to redirect traffic. So overrides are
# constrained to AWS-owned domains by default, and stepping outside that set
# requires an explicit opt-in the operator has to type.
_ALLOWED_ENDPOINT_SUFFIXES = (
    ".amazonaws.com",
    ".amazonaws.com.cn",
    ".api.aws",
    ".on.aws",
)

_ENDPOINT_OVERRIDE_ENV = "KB_CONNECTOR_ALLOW_INSECURE_ENDPOINT"

# Retry defaults. Full-jitter exponential backoff capped at _RETRY_MAX_DELAY.
_MAX_RETRIES = 4
_RETRY_BASE_DELAY = 1.0
_RETRY_MAX_DELAY = 20.0

_IDEMPOTENT_METHODS = {"GET", "HEAD"}


def validate_endpoint(endpoint: str, *, label: str = "endpoint") -> str:
    """Validate and normalize an endpoint URL before anything is signed to it.

    Enforces two properties:

    1. **https only.** A plaintext endpoint would put the SigV4 Authorization
       header and the request body on the wire in the clear.
    2. **AWS-owned host.** See _ALLOWED_ENDPOINT_SUFFIXES for why the
       destination is a security boundary rather than a cosmetic setting.

    Returns the endpoint with any trailing slash removed.

    Raises:
        AwsError: when the endpoint is malformed, not https, or points outside
            the allowlist without the opt-out set.
    """
    import os
    from urllib.parse import urlparse

    if not endpoint or not endpoint.strip():
        raise AwsError(f"{label} is empty; expected an https:// URL.")

    raw = endpoint.strip()
    parsed = urlparse(raw)

    if not parsed.scheme or not parsed.netloc:
        raise AwsError(
            f"{label} {raw!r} is not a valid absolute URL. Expected something "
            f"like https://bedrock-agent.us-east-1.amazonaws.com"
        )

    if parsed.scheme != "https":
        raise AwsError(
            f"{label} {raw!r} uses scheme {parsed.scheme!r}, but only https is "
            f"allowed. Requests to this endpoint carry a SigV4 signature "
            f"computed from your AWS credentials; sending them over plaintext "
            f"would expose that signature and the request body."
        )

    host = (parsed.hostname or "").lower()
    allowed = host.endswith(_ALLOWED_ENDPOINT_SUFFIXES)
    opted_out = os.environ.get(_ENDPOINT_OVERRIDE_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    if not allowed and not opted_out:
        raise AwsError(
            f"{label} {raw!r} points at {host!r}, which is not an AWS-owned "
            f"endpoint.\n\n"
            f"Every request this client sends is signed with your live AWS "
            f"credentials. A non-AWS host receives a valid, replayable "
            f"Authorization header for the bedrock service along with the "
            f"request body — which includes secret ARNs. So the tool will not "
            f"sign requests to arbitrary hosts.\n\n"
            f"Allowed suffixes: {', '.join(_ALLOWED_ENDPOINT_SUFFIXES)}\n\n"
            f"If you are deliberately testing against a private pre-production "
            f"endpoint, set {_ENDPOINT_OVERRIDE_ENV}=1 to acknowledge the risk. "
            f"Do not set it in a shared shell profile or CI configuration."
        )

    if not allowed and opted_out:
        print(
            f"  WARNING: signing requests to non-AWS endpoint {host!r} because "
            f"{_ENDPOINT_OVERRIDE_ENV} is set. Your AWS credentials are being "
            f"used to sign requests to a host outside AWS.",
            file=sys.stderr,
        )

    return raw.rstrip("/")


class _TransientError(Exception):
    """Internal: a failure that may be worth retrying.

    Attributes:
        safe_for_writes: True when the failure provably did not mutate server
            state (connection never established, or request explicitly rejected
            via throttling) — so it is safe to retry even non-idempotent writes.
            False for ambiguous failures (read timeout, 5xx) that may have been
            processed server-side; those retry only for idempotent methods.
    """

    def __init__(self, message: str, *, safe_for_writes: bool) -> None:
        super().__init__(message)
        self.safe_for_writes = safe_for_writes


class SignedClient:
    """SigV4-signed JSON client for the bedrock-agent control plane and runtime.

    Args:
        session: a boto3 Session (provides credentials + region).
        buildtime_endpoint: base URL for KB / data source / ingestion calls.
        runtime_endpoint: base URL for retrieve calls (validate).
        region: region for SigV4; falls back to the session's region.
        max_retries: max retry attempts for transient failures (0 disables).
    """

    def __init__(
        self,
        *,
        session: Any,
        buildtime_endpoint: str,
        runtime_endpoint: str | None = None,
        region: str | None = None,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        # Imported lazily so --help and source-only runs don't pay for botocore.
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.httpsession import URLLib3Session

        self._SigV4Auth = SigV4Auth
        self._AWSRequest = AWSRequest
        self._http = URLLib3Session(timeout=_TIMEOUT)

        self._credentials = session.get_credentials()
        if self._credentials is None:
            raise AwsError("No AWS credentials available for signing requests.")
        self._region = region or session.region_name
        if not self._region:
            raise AwsError("No AWS region set for signing requests.")
        self._buildtime = validate_endpoint(buildtime_endpoint, label="endpoint_url")
        self._runtime = (
            validate_endpoint(runtime_endpoint, label="runtime_endpoint_url")
            if runtime_endpoint
            else ""
        )
        # Clamped so `range(self._max_retries + 1)` in _send always yields at
        # least one attempt. A negative value would skip the request entirely
        # and fall through to the failure path with nothing to report.
        self._max_retries = max(0, max_retries)

    # -- public verbs --------------------------------------------------------

    def buildtime(self, method: str, path: str, body: Any = None) -> Any:
        """Signed call against the buildtime endpoint (KB/DS/ingestion)."""
        return self._send(method, self._buildtime + path, body)

    def runtime(self, method: str, path: str, body: Any = None) -> Any:
        """Signed call against the runtime endpoint (retrieve)."""
        if not self._runtime:
            raise AwsError(
                "No runtime endpoint configured. Set runtime_endpoint_url "
                "in config or pass --runtime-endpoint-url for retrieve operations."
            )
        return self._send(method, self._runtime + path, body)

    # -- internals -----------------------------------------------------------

    def _send(self, method: str, url: str, body: Any) -> Any:
        """Send with idempotency-aware retry on transient failures."""
        idempotent = method.upper() in _IDEMPOTENT_METHODS
        last_error: _TransientError | None = None

        attempts = 0

        for attempt in range(self._max_retries + 1):
            attempts = attempt + 1
            try:
                return self._send_once(method, url, body)
            except _TransientError as exc:
                last_error = exc
                retryable = idempotent or exc.safe_for_writes
                if not retryable or attempt >= self._max_retries:
                    break
                time.sleep(self._backoff_delay(attempt))

        # Out of retries (or a non-retryable transient on a write): surface it.
        #
        # `attempts` is tracked explicitly rather than reading the loop variable
        # after the loop, which would depend on the loop having run at least
        # once. Guarding that with `assert last_error is not None` would not
        # help: asserts are stripped under `python -O`, turning a logic error
        # here into an AttributeError on None instead of this message.
        # _max_retries is clamped non-negative in __init__ so the loop always
        # runs at least once.
        raise AwsError(
            f"{method} {url} failed after {attempts} attempt(s): {last_error}"
        ) from last_error

    def _send_once(self, method: str, url: str, body: Any) -> Any:
        """Perform a single signed request. Raises _TransientError or AwsError."""
        from botocore.exceptions import (
            ConnectionError as BotoConnectionError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        )

        data = json.dumps(body) if body is not None else None
        request = self._AWSRequest(
            method=method,
            url=url,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        # Sign in place. Credentials are resolved fresh each call so refreshable
        # providers (SSO, assumed roles) keep working on long monitor loops.
        self._SigV4Auth(
            self._credentials.get_frozen_credentials(), _SIGNING_SERVICE, self._region
        ).add_auth(request)

        try:
            response = self._http.send(request.prepare())
        except (ConnectTimeoutError, EndpointConnectionError, BotoConnectionError) as exc:
            # The connection never completed, so the request did not reach the
            # service — safe to retry even for writes.
            raise _TransientError(f"connection error: {exc}", safe_for_writes=True) from exc
        except ReadTimeoutError as exc:
            # The request was sent but no response arrived in time. For a write
            # this is ambiguous (may have been processed), so it's only retried
            # for idempotent methods.
            raise _TransientError(f"read timeout: {exc}", safe_for_writes=False) from exc

        text = response.text or ""
        status = response.status_code

        if 200 <= status < 300:
            if not text:
                return None
            try:
                return json.loads(text)
            except ValueError:
                return {"raw": text}

        # Throttling: the service rejected the request without processing it —
        # safe to retry for any method.
        if status == 429 or _is_throttling(text):
            raise _TransientError(f"throttled ({status})", safe_for_writes=True)

        # Server errors: may or may not have been processed. Retry only for
        # idempotent methods (safe_for_writes=False).
        if status >= 500:
            raise _TransientError(f"server error ({status}): {text[:500]}", safe_for_writes=False)

        # 4xx (validation, auth, not-found, conflict): deterministic — surface
        # immediately with the parsed body so callers get actionable errors.
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = text[:2000]
        raise AwsError(f"{method} {url} -> {status}: {parsed}")

    def _backoff_delay(self, attempt: int) -> float:
        """Full-jitter exponential backoff: random(0, min(cap, base*2^attempt))."""
        ceiling = min(_RETRY_MAX_DELAY, _RETRY_BASE_DELAY * (2 ** attempt))
        return random.uniform(0, ceiling)


def _is_throttling(text: str) -> bool:
    """Detect throttling signaled in the response body (not just HTTP 429)."""
    if not text:
        return False
    lowered = text.lower()
    return "throttl" in lowered or "toomanyrequests" in lowered or "slow down" in lowered
