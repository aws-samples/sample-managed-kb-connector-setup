"""Unit tests for the target abstraction (no network calls)."""

import pytest

from kb_connector.core.errors import AwsError
from kb_connector.targets import get_target
from kb_connector.targets.base import Target
from kb_connector.targets.bmkb import BmkbTarget
from kb_connector.targets.quick import QuickTarget


class _FakeSession:
    """Minimal fake boto3 session for constructing targets without network."""

    region_name = "us-west-2"

    def get_credentials(self):
        class _Creds:
            def get_frozen_credentials(self):
                return self
            access_key = "AKIA_TEST"
            secret_key = "secret"
            token = None
        return _Creds()


def test_get_target_bmkb():
    target = get_target("bmkb", session=_FakeSession(), region="us-west-2")
    assert isinstance(target, BmkbTarget)
    assert target.name == "bmkb"


def test_get_target_quick():
    target = get_target("quick", session=_FakeSession(), region="us-west-2")
    assert isinstance(target, QuickTarget)
    assert target.name == "quick"


def test_get_target_default():
    target = get_target("", session=_FakeSession(), region="us-west-2")
    assert isinstance(target, BmkbTarget)


def test_get_target_unknown():
    with pytest.raises(ValueError, match="Unknown target"):
        get_target("dropbox", session=_FakeSession(), region="us-west-2")


def test_bmkb_is_target():
    target = get_target("bmkb", session=_FakeSession(), region="us-west-2")
    assert isinstance(target, Target)


def test_quick_raises_not_implemented():
    target = get_target("quick", session=_FakeSession(), region="us-west-2")
    with pytest.raises(NotImplementedError, match="not yet available"):
        target.create_knowledge_base(name="test", role_arn="arn:test")
    with pytest.raises(NotImplementedError):
        target.get_knowledge_base("kb-1")
    with pytest.raises(NotImplementedError):
        target.retrieve("kb-1", query="test")


def test_bmkb_exposes_client():
    target = get_target("bmkb", session=_FakeSession(), region="us-west-2")
    # BmkbTarget exposes the signed client for advanced/raw calls
    assert target.client is not None


def test_bmkb_custom_endpoints():
    # Endpoint overrides still work for pre-production testing, as long as the
    # host is AWS-owned (see signed_client._ALLOWED_ENDPOINT_SUFFIXES).
    target = BmkbTarget(
        session=_FakeSession(),
        region="us-west-2",
        buildtime_endpoint="https://bedrock-agent-beta.us-west-2.amazonaws.com",
        runtime_endpoint="https://bedrock-agent-runtime-beta.us-west-2.amazonaws.com",
    )
    assert target.name == "bmkb"


def test_bmkb_rejects_non_aws_endpoint():
    """A non-AWS endpoint must not receive SigV4-signed requests.

    The override is reachable from config and from KB_CONNECTOR_ENDPOINT_URL,
    so this is the guard against a poisoned config or an inherited CI env var
    redirecting credential-bearing requests off-platform.
    """
    with pytest.raises(AwsError, match="not an AWS-owned endpoint"):
        BmkbTarget(
            session=_FakeSession(),
            region="us-west-2",
            buildtime_endpoint="https://beta.example.com",
        )


def test_bmkb_rejects_plaintext_endpoint():
    with pytest.raises(AwsError, match="only https is allowed"):
        BmkbTarget(
            session=_FakeSession(),
            region="us-west-2",
            buildtime_endpoint="http://bedrock-agent.us-west-2.amazonaws.com",
        )


def test_bmkb_rejects_suffix_lookalike_host():
    """A host that merely *contains* an AWS domain must not pass as one.

    `amazonaws.com.blocked.example` would satisfy a naive substring check, so
    the allowlist matches against the parsed hostname's suffix instead.
    """
    with pytest.raises(AwsError, match="not an AWS-owned endpoint"):
        BmkbTarget(
            session=_FakeSession(),
            region="us-west-2",
            buildtime_endpoint="https://amazonaws.com.blocked.example",
        )


def test_non_aws_endpoint_allowed_with_explicit_opt_out(monkeypatch):
    """The escape hatch works, but only when deliberately set."""
    monkeypatch.setenv("KB_CONNECTOR_ALLOW_INSECURE_ENDPOINT", "1")
    target = BmkbTarget(
        session=_FakeSession(),
        region="us-west-2",
        buildtime_endpoint="https://localhost:8443",
    )
    assert target.name == "bmkb"
