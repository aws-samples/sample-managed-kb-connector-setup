"""Unit tests for SignedClient retry behavior (no network)."""

import pytest

from kb_connector.core.errors import AwsError
from kb_connector.core.signed_client import SignedClient


class _FakeFrozenCreds:
    access_key = "AKIA_TEST"
    secret_key = "secret"
    token = None


class _FakeCreds:
    def get_frozen_credentials(self):
        return _FakeFrozenCreds()


class _FakeSession:
    region_name = "us-west-2"

    def get_credentials(self):
        return _FakeCreds()


class _FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class _FakeHttp:
    """Fake URLLib3Session: replays a scripted sequence of outcomes.

    Each item is either an Exception instance (raised) or a _FakeResponse.
    """

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    def send(self, _prepared):
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _make_client(outcomes, *, max_retries=4):
    client = SignedClient(
        session=_FakeSession(),
        buildtime_endpoint="https://bedrock-agent.us-west-2.amazonaws.com",
        runtime_endpoint="https://bedrock-agent-runtime.us-west-2.amazonaws.com",
        region="us-west-2",
        max_retries=max_retries,
    )
    # Replace the real HTTP session and neuter signing + sleep.
    client._http = _FakeHttp(outcomes)
    client._SigV4Auth = lambda *a, **k: _NoAuth()
    client._backoff_delay = lambda attempt: 0.0  # no real sleeping in tests
    return client


class _NoAuth:
    def add_auth(self, _request):
        pass


# --- Success / no retry ------------------------------------------------------


def test_get_success_no_retry():
    client = _make_client([_FakeResponse(200, '{"ok": true}')])
    result = client.buildtime("GET", "/knowledgebases/KB1")
    assert result == {"ok": True}
    assert client._http.calls == 1


def test_empty_2xx_returns_none():
    client = _make_client([_FakeResponse(200, "")])
    assert client.buildtime("GET", "/x") is None


# --- Retry on transient (idempotent GET) -------------------------------------


def test_get_retries_read_timeout_then_succeeds():
    from botocore.exceptions import ReadTimeoutError
    client = _make_client([
        ReadTimeoutError(endpoint_url="https://x"),
        ReadTimeoutError(endpoint_url="https://x"),
        _FakeResponse(200, '{"status": "ACTIVE"}'),
    ])
    result = client.buildtime("GET", "/knowledgebases/KB1")
    assert result == {"status": "ACTIVE"}
    assert client._http.calls == 3


def test_get_retries_5xx_then_succeeds():
    client = _make_client([
        _FakeResponse(503, "service unavailable"),
        _FakeResponse(200, '{"ok": 1}'),
    ])
    result = client.buildtime("GET", "/x")
    assert result == {"ok": 1}
    assert client._http.calls == 2


def test_get_exhausts_retries_then_raises():
    from botocore.exceptions import ReadTimeoutError
    client = _make_client(
        [ReadTimeoutError(endpoint_url="https://x")] * 10, max_retries=3
    )
    with pytest.raises(AwsError, match="after 4 attempt"):
        client.buildtime("GET", "/x")
    assert client._http.calls == 4  # 1 + 3 retries


# --- Idempotency policy for writes -------------------------------------------


def test_put_does_not_retry_read_timeout():
    """A read timeout on a write is ambiguous — must NOT be retried."""
    from botocore.exceptions import ReadTimeoutError
    client = _make_client([
        ReadTimeoutError(endpoint_url="https://x"),
        _FakeResponse(200, '{"created": true}'),  # would succeed if retried
    ])
    with pytest.raises(AwsError, match="read timeout"):
        client.buildtime("PUT", "/knowledgebases/", {"name": "kb"})
    assert client._http.calls == 1  # no retry


def test_put_does_not_retry_5xx():
    """A 5xx on a write may have been processed — must NOT be retried."""
    client = _make_client([
        _FakeResponse(500, "internal error"),
        _FakeResponse(200, '{"created": true}'),
    ])
    with pytest.raises(AwsError, match="server error"):
        client.buildtime("PUT", "/knowledgebases/", {"name": "kb"})
    assert client._http.calls == 1


def test_put_retries_connection_error():
    """A connection error means the request never reached the server — safe."""
    from botocore.exceptions import EndpointConnectionError
    client = _make_client([
        EndpointConnectionError(endpoint_url="https://x"),
        _FakeResponse(200, '{"created": true}'),
    ])
    result = client.buildtime("PUT", "/knowledgebases/", {"name": "kb"})
    assert result == {"created": True}
    assert client._http.calls == 2


def test_put_retries_throttling():
    """Throttling means the request was rejected, not processed — safe."""
    client = _make_client([
        _FakeResponse(429, "ThrottlingException"),
        _FakeResponse(200, '{"created": true}'),
    ])
    result = client.buildtime("PUT", "/knowledgebases/", {"name": "kb"})
    assert result == {"created": True}
    assert client._http.calls == 2


def test_throttling_detected_in_body_with_non_429_status():
    client = _make_client([
        _FakeResponse(400, '{"message": "Rate exceeded, please slow down"}'),
        _FakeResponse(200, '{"ok": 1}'),
    ])
    # GET retries any transient including body-signaled throttling
    result = client.buildtime("GET", "/x")
    assert result == {"ok": 1}
    assert client._http.calls == 2


# --- Non-retryable 4xx -------------------------------------------------------


def test_4xx_validation_not_retried():
    client = _make_client([
        _FakeResponse(400, '{"message": "validation error"}'),
        _FakeResponse(200, '{"ok": 1}'),
    ])
    with pytest.raises(AwsError, match="validation error"):
        client.buildtime("GET", "/x")
    assert client._http.calls == 1


def test_409_conflict_not_retried():
    client = _make_client([_FakeResponse(409, '{"message": "already exists"}')])
    with pytest.raises(AwsError, match="already exists"):
        client.buildtime("PUT", "/knowledgebases/", {"name": "kb"})
    assert client._http.calls == 1
