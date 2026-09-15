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


class _FakeClient:
    """Stands in for the transport underneath BmkbTarget.

    Returns scripted responses in order and records every call. This class is
    the only thing in this file that knows how the target reaches AWS; the
    operation tests below assert behavior, so they hold whatever the transport
    is.
    """

    def __init__(self, buildtime=None, runtime=None):
        self._buildtime = list(buildtime or [])
        self._runtime = list(runtime or [])
        self.calls: list[tuple] = []

    def buildtime(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self._buildtime.pop(0) if self._buildtime else None

    def runtime(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self._runtime.pop(0) if self._runtime else None


def _bmkb(*, buildtime=None, runtime=None):
    """A BmkbTarget wired to scripted responses instead of AWS."""
    target = BmkbTarget(session=_FakeSession(), region="us-west-2")
    target._client = _FakeClient(buildtime=buildtime, runtime=runtime)
    return target


def _no_sleep(monkeypatch):
    """Waiters poll on a real clock; drop the sleep so tests stay sub-second."""
    monkeypatch.setattr("time.sleep", lambda _: None)


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


# --- Knowledge base operations -----------------------------------------------


def test_create_knowledge_base_returns_created_kb():
    target = _bmkb(buildtime=[{"knowledgeBase": {"knowledgeBaseId": "KB123456789"}}])
    result = target.create_knowledge_base(
        name="kb-connector-eng", role_arn="arn:aws:iam::111122223333:role/r"
    )
    assert result["knowledgeBase"]["knowledgeBaseId"] == "KB123456789"


def test_create_knowledge_base_omits_embedding_model_unless_given():
    """No embedding model means the service picks its managed default."""
    target = _bmkb(buildtime=[{}])
    target.create_knowledge_base(name="kb", role_arn="arn:role")
    _, _, body = target._client.calls[0]
    managed = body["knowledgeBaseConfiguration"]["managedKnowledgeBaseConfiguration"]
    assert managed == {}
    assert body["knowledgeBaseConfiguration"]["type"] == "MANAGED"
    assert "kmsKeyArn" not in body


def test_create_knowledge_base_passes_embedding_model_when_given():
    target = _bmkb(buildtime=[{}])
    target.create_knowledge_base(
        name="kb",
        role_arn="arn:role",
        embedding_model_arn="arn:aws:bedrock:::foundation-model/titan",
    )
    _, _, body = target._client.calls[0]
    managed = body["knowledgeBaseConfiguration"]["managedKnowledgeBaseConfiguration"]
    assert managed["embeddingModelArn"] == "arn:aws:bedrock:::foundation-model/titan"


def test_create_knowledge_base_encrypts_with_customer_managed_key():
    """A KMS key reaches the managed config block, not the request top level."""
    target = _bmkb(buildtime=[{}])
    target.create_knowledge_base(
        name="kb", role_arn="arn:role", kms_key_arn="arn:aws:kms:::key/k1"
    )
    _, _, body = target._client.calls[0]
    managed = body["knowledgeBaseConfiguration"]["managedKnowledgeBaseConfiguration"]
    assert managed["serverSideEncryptionConfiguration"] == {
        "kmsKeyArn": "arn:aws:kms:::key/k1"
    }
    assert "kmsKeyArn" not in body


def test_get_knowledge_base_returns_response():
    target = _bmkb(buildtime=[{"knowledgeBase": {"status": "ACTIVE"}}])
    assert target.get_knowledge_base("KB123456789")["knowledgeBase"]["status"] == "ACTIVE"


def test_delete_knowledge_base_returns_none():
    target = _bmkb(buildtime=[None])
    assert target.delete_knowledge_base("KB123456789") is None


# --- Knowledge base waiter ---------------------------------------------------


def test_wait_until_kb_active_returns_when_active(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"knowledgeBase": {"status": "ACTIVE"}}])
    assert target.wait_until_kb_active("KB123456789") == "ACTIVE"


def test_wait_until_kb_active_polls_until_active(monkeypatch):
    """CREATING is the normal first response; the waiter keeps going."""
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[
        {"knowledgeBase": {"status": "CREATING"}},
        {"knowledgeBase": {"status": "CREATING"}},
        {"knowledgeBase": {"status": "ACTIVE"}},
    ])
    assert target.wait_until_kb_active("KB123456789") == "ACTIVE"
    assert len(target._client.calls) == 3


def test_wait_until_kb_active_accepts_unwrapped_response(monkeypatch):
    """Status is read whether or not the response nests under knowledgeBase."""
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"status": "ACTIVE"}])
    assert target.wait_until_kb_active("KB123456789") == "ACTIVE"


def test_wait_until_kb_active_is_case_insensitive(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"knowledgeBase": {"status": "active"}}])
    assert target.wait_until_kb_active("KB123456789") == "ACTIVE"


def test_wait_until_kb_active_raises_on_terminal_bad(monkeypatch):
    """FAILED must stop the waiter rather than poll to the timeout."""
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[
        {"knowledgeBase": {"status": "FAILED", "failureReasons": ["role denied"]}},
    ])
    with pytest.raises(AwsError, match="terminal-bad status FAILED"):
        target.wait_until_kb_active("KB123456789")


def test_wait_until_kb_active_surfaces_failure_reasons(monkeypatch):
    """The service's reason is the only actionable part of the failure."""
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[
        {"knowledgeBase": {"status": "FAILED", "failureReasons": ["role denied"]}},
    ])
    with pytest.raises(AwsError, match="role denied"):
        target.wait_until_kb_active("KB123456789")


def test_wait_until_kb_active_times_out(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"knowledgeBase": {"status": "CREATING"}}])
    with pytest.raises(TimeoutError, match="did not reach ACTIVE"):
        target.wait_until_kb_active("KB123456789", timeout_seconds=0)


# --- Data source operations --------------------------------------------------


def test_create_data_source_wraps_connector_parameters():
    """connectorParameters go inside the MANAGED_KNOWLEDGE_BASE_CONNECTOR envelope."""
    target = _bmkb(buildtime=[{"dataSource": {"dataSourceId": "DS123456789"}}])
    params = {"sharePointConfiguration": {"aclEnabled": True}}
    result = target.create_data_source(
        "KB123456789", name="eng-ds", connector_parameters=params
    )
    assert result["dataSource"]["dataSourceId"] == "DS123456789"
    _, _, body = target._client.calls[0]
    dsc = body["dataSourceConfiguration"]
    assert dsc["type"] == "MANAGED_KNOWLEDGE_BASE_CONNECTOR"
    assert dsc["managedKnowledgeBaseConnectorConfiguration"][
        "connectorParameters"
    ] == params


def test_create_data_source_omits_chunking_configuration():
    """A managed-embedding KB rejects an explicit chunkingConfiguration."""
    target = _bmkb(buildtime=[{}])
    target.create_data_source("KB123456789", name="ds", connector_parameters={})
    _, _, body = target._client.calls[0]
    assert "vectorIngestionConfiguration" not in body
    assert "chunkingConfiguration" not in body


def test_create_data_source_raw_passes_payload_through():
    """The raw form is how non-managed shapes (e.g. S3) are created."""
    target = _bmkb(buildtime=[{"dataSource": {}}])
    payload = {"name": "s3-ds", "dataSourceConfiguration": {"type": "S3"}}
    target.create_data_source_raw("KB123456789", payload)
    _, _, body = target._client.calls[0]
    assert body == payload


def test_get_data_source_returns_response():
    target = _bmkb(buildtime=[{"dataSource": {"status": "AVAILABLE"}}])
    got = target.get_data_source("KB123456789", "DS123456789")
    assert got["dataSource"]["status"] == "AVAILABLE"


def test_delete_data_source_returns_none():
    target = _bmkb(buildtime=[None])
    assert target.delete_data_source("KB123456789", "DS123456789") is None


# --- Data source waiter ------------------------------------------------------


def test_wait_until_ds_available_returns_when_available(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"dataSource": {"status": "AVAILABLE"}}])
    assert target.wait_until_ds_available("KB123456789", "DS123456789") == "AVAILABLE"


def test_wait_until_ds_available_polls_through_creating(monkeypatch):
    """StartIngestionJob fails while the DS is CREATING, so the waiter matters."""
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[
        {"dataSource": {"status": "CREATING"}},
        {"dataSource": {"status": "AVAILABLE"}},
    ])
    assert target.wait_until_ds_available("KB123456789", "DS123456789") == "AVAILABLE"
    assert len(target._client.calls) == 2


def test_wait_until_ds_available_raises_on_terminal_bad(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[
        {"dataSource": {"status": "FAILED", "failureReasons": ["bad secret"]}},
    ])
    with pytest.raises(AwsError, match="terminal-bad status FAILED"):
        target.wait_until_ds_available("KB123456789", "DS123456789")


def test_wait_until_ds_available_times_out(monkeypatch):
    _no_sleep(monkeypatch)
    target = _bmkb(buildtime=[{"dataSource": {"status": "CREATING"}}])
    with pytest.raises(TimeoutError, match="did not reach AVAILABLE"):
        target.wait_until_ds_available(
            "KB123456789", "DS123456789", timeout_seconds=0
        )


# --- Ingestion ---------------------------------------------------------------


def test_start_ingestion_job_returns_job():
    target = _bmkb(buildtime=[{"ingestionJob": {"ingestionJobId": "JOB1"}}])
    got = target.start_ingestion_job("KB123456789", "DS123456789")
    assert got["ingestionJob"]["ingestionJobId"] == "JOB1"


def test_get_ingestion_job_returns_job():
    target = _bmkb(buildtime=[{"ingestionJob": {"status": "COMPLETE"}}])
    got = target.get_ingestion_job("KB123456789", "DS123456789", "JOB1")
    assert got["ingestionJob"]["status"] == "COMPLETE"


# --- Retrieve and the ACL contract -------------------------------------------


def test_retrieve_sends_query():
    target = _bmkb(runtime=[{"retrievalResults": [{"id": 1}]}])
    got = target.retrieve("KB123456789", query="who won")
    assert got["retrievalResults"] == [{"id": 1}]
    _, _, body = target._client.calls[0]
    assert body["retrievalQuery"] == {"text": "who won"}


def test_retrieve_without_user_id_omits_user_context():
    """The no-user leg of the ACL trio must send no userContext at all."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q")
    _, _, body = target._client.calls[0]
    assert "userContext" not in body


def test_retrieve_with_user_id_sets_top_level_user_context():
    """ACL-aware retrieval keys off a top-level userContext.userId."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q", user_id="alice@example.com")
    _, _, body = target._client.calls[0]
    assert body["userContext"] == {"userId": "alice@example.com"}


def test_retrieve_filter_uses_managed_search_configuration():
    """Managed KBs reject vectorSearchConfiguration, so this is not an alias."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve(
        "KB123456789", query="q", filter={"equals": {"key": "k", "value": "v"}}
    )
    _, _, body = target._client.calls[0]
    assert body["retrievalConfiguration"] == {
        "managedSearchConfiguration": {"filter": {"equals": {"key": "k", "value": "v"}}}
    }


def test_retrieve_omits_retrieval_configuration_without_filter():
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q")
    _, _, body = target._client.calls[0]
    assert "retrievalConfiguration" not in body
