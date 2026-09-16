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

    def client(self, service_name, **kwargs):
        return _FakeClient()

    def get_credentials(self):
        class _Creds:
            def get_frozen_credentials(self):
                return self
            access_key = "AKIA_TEST"
            secret_key = "secret"
            token = None
        return _Creds()


class _FakeClient:
    """Stands in for a boto3 client underneath BmkbTarget.

    Returns scripted responses in order and records every call as
    (operation, kwargs). This class is the only thing in this file that knows
    how the target reaches AWS; the operation tests below assert behavior, so
    they hold whatever the transport is.
    """

    def __init__(self, responses=None):
        self._responses = list(responses or [])
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((operation, kwargs))
            return self._responses.pop(0) if self._responses else None

        return call


def _bmkb(*, buildtime=None, runtime=None):
    """A BmkbTarget wired to scripted responses instead of AWS.

    `buildtime` scripts the control-plane client, `runtime` the retrieve path.
    """
    target = BmkbTarget(session=_FakeSession(), region="us-west-2")
    target._client = _FakeClient(buildtime)
    target._runtime = _FakeClient(runtime)
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
    _, body = target._client.calls[0]
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
    _, body = target._client.calls[0]
    managed = body["knowledgeBaseConfiguration"]["managedKnowledgeBaseConfiguration"]
    assert managed["embeddingModelArn"] == "arn:aws:bedrock:::foundation-model/titan"


def test_create_knowledge_base_encrypts_with_customer_managed_key():
    """A KMS key reaches the managed config block, not the request top level."""
    target = _bmkb(buildtime=[{}])
    target.create_knowledge_base(
        name="kb", role_arn="arn:role", kms_key_arn="arn:aws:kms:::key/k1"
    )
    _, body = target._client.calls[0]
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
    _, body = target._client.calls[0]
    dsc = body["dataSourceConfiguration"]
    assert dsc["type"] == "MANAGED_KNOWLEDGE_BASE_CONNECTOR"
    assert dsc["managedKnowledgeBaseConnectorConfiguration"][
        "connectorParameters"
    ] == params


def test_create_data_source_omits_chunking_configuration():
    """A managed-embedding KB rejects an explicit chunkingConfiguration."""
    target = _bmkb(buildtime=[{}])
    target.create_data_source("KB123456789", name="ds", connector_parameters={})
    _, body = target._client.calls[0]
    assert "vectorIngestionConfiguration" not in body
    assert "chunkingConfiguration" not in body


def test_create_data_source_raw_passes_payload_through():
    """The raw form is how non-managed shapes (e.g. S3) are created."""
    target = _bmkb(buildtime=[{"dataSource": {}}])
    payload = {"name": "s3-ds", "dataSourceConfiguration": {"type": "S3"}}
    target.create_data_source_raw("KB123456789", payload)
    _, body = target._client.calls[0]
    # The payload reaches the API untouched; the KB id rides alongside it.
    assert body == {"knowledgeBaseId": "KB123456789", **payload}


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


def test_identifiers_map_to_the_right_parameters():
    """Each operation must put each id in the right parameter.

    Return values alone would not catch this: swapping knowledgeBaseId and
    dataSourceId still returns the scripted response, so the ids are asserted
    directly.
    """
    kb_id, ds_id, job_id = "KB123456789", "DS123456789", "JOB1"
    cases = [
        (lambda t: t.get_knowledge_base(kb_id),
         "get_knowledge_base", {"knowledgeBaseId": kb_id}),
        (lambda t: t.delete_knowledge_base(kb_id),
         "delete_knowledge_base", {"knowledgeBaseId": kb_id}),
        (lambda t: t.get_data_source(kb_id, ds_id),
         "get_data_source", {"knowledgeBaseId": kb_id, "dataSourceId": ds_id}),
        (lambda t: t.delete_data_source(kb_id, ds_id),
         "delete_data_source", {"knowledgeBaseId": kb_id, "dataSourceId": ds_id}),
        (lambda t: t.start_ingestion_job(kb_id, ds_id),
         "start_ingestion_job", {"knowledgeBaseId": kb_id, "dataSourceId": ds_id}),
        (lambda t: t.get_ingestion_job(kb_id, ds_id, job_id),
         "get_ingestion_job",
         {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "ingestionJobId": job_id}),
        (lambda t: t.stop_ingestion_job(kb_id, ds_id, job_id),
         "stop_ingestion_job",
         {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "ingestionJobId": job_id}),
    ]
    for invoke, want_operation, want_kwargs in cases:
        target = _bmkb(buildtime=[{}])
        invoke(target)
        assert target._client.calls == [(want_operation, want_kwargs)]


def test_retrieve_identifies_the_knowledge_base():
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q")
    operation, body = target._runtime.calls[0]
    assert operation == "retrieve"
    assert body["knowledgeBaseId"] == "KB123456789"


def test_list_ingestion_jobs_passes_max_results():
    """Teardown's precheck reads only the newest few jobs."""
    target = _bmkb(buildtime=[{"ingestionJobSummaries": [{"status": "COMPLETE"}]}])
    got = target.list_ingestion_jobs("KB123456789", "DS123456789", max_results=5)
    assert got["ingestionJobSummaries"] == [{"status": "COMPLETE"}]
    _, body = target._client.calls[0]
    assert body["maxResults"] == 5


def test_stop_ingestion_job_targets_the_job():
    target = _bmkb(buildtime=[{"ingestionJob": {"status": "STOPPING"}}])
    target.stop_ingestion_job("KB123456789", "DS123456789", "JOB1")
    operation, body = target._client.calls[0]
    assert operation == "stop_ingestion_job"
    assert body["ingestionJobId"] == "JOB1"


# --- Retrieve and the ACL contract -------------------------------------------


def test_retrieve_sends_query():
    target = _bmkb(runtime=[{"retrievalResults": [{"id": 1}]}])
    got = target.retrieve("KB123456789", query="who won")
    assert got["retrievalResults"] == [{"id": 1}]
    _, body = target._runtime.calls[0]
    assert body["retrievalQuery"] == {"text": "who won"}


def test_retrieve_without_user_id_omits_user_context():
    """The no-user leg of the ACL trio must send no userContext at all."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q")
    _, body = target._runtime.calls[0]
    assert "userContext" not in body


def test_retrieve_with_user_id_sets_top_level_user_context():
    """ACL-aware retrieval keys off a top-level userContext.userId."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q", user_id="alice@example.com")
    _, body = target._runtime.calls[0]
    assert body["userContext"] == {"userId": "alice@example.com"}


def test_retrieve_filter_uses_managed_search_configuration():
    """Managed KBs reject vectorSearchConfiguration, so this is not an alias."""
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve(
        "KB123456789", query="q", filter={"equals": {"key": "k", "value": "v"}}
    )
    _, body = target._runtime.calls[0]
    assert body["retrievalConfiguration"] == {
        "managedSearchConfiguration": {"filter": {"equals": {"key": "k", "value": "v"}}}
    }


def test_retrieve_omits_retrieval_configuration_without_filter():
    target = _bmkb(runtime=[{"retrievalResults": []}])
    target.retrieve("KB123456789", query="q")
    _, body = target._runtime.calls[0]
    assert "retrievalConfiguration" not in body


# --- AWS SDK error translation ------------------------------------------------
#
# Callers up the stack catch AwsError to enrich or record a failure: probe
# captures the response for the run, setup turns a data-source name collision
# into guidance. The SDK raises botocore exceptions, so the target has to
# translate them or none of those handlers ever run.


class _RaisingClient:
    """Stands in for a boto3 client whose every operation fails."""

    def __init__(self, exc):
        self._exc = exc

    def __getattr__(self, operation):
        def call(**kwargs):
            raise self._exc

        return call


def _client_error(code, message="something the service said"):
    from botocore.exceptions import ClientError

    return ClientError(
        {"Error": {"Code": code, "Message": message}}, "SomeOperation"
    )


def _bmkb_raising(exc):
    target = BmkbTarget(session=_FakeSession(), region="us-west-2")
    target._client = _RaisingClient(exc)
    target._runtime = _RaisingClient(exc)
    return target


# Every operation that issues an SDK call. Parametrized rather than spot-checked
# so that a new operation added without the translation is caught here instead
# of silently disabling a caller's error handling.
_SDK_OPERATIONS = {
    "create_knowledge_base": lambda t: t.create_knowledge_base(
        name="kb", role_arn="arn:aws:iam::123456789012:role/r"
    ),
    "get_knowledge_base": lambda t: t.get_knowledge_base("KB123456789"),
    "delete_knowledge_base": lambda t: t.delete_knowledge_base("KB123456789"),
    "create_data_source": lambda t: t.create_data_source(
        "KB123456789", name="ds", connector_parameters={"type": "SHAREPOINT"}
    ),
    "create_data_source_raw": lambda t: t.create_data_source_raw(
        "KB123456789", {"name": "ds"}
    ),
    "get_data_source": lambda t: t.get_data_source("KB123456789", "DS123456789"),
    "delete_data_source": lambda t: t.delete_data_source(
        "KB123456789", "DS123456789"
    ),
    "start_ingestion_job": lambda t: t.start_ingestion_job(
        "KB123456789", "DS123456789"
    ),
    "get_ingestion_job": lambda t: t.get_ingestion_job(
        "KB123456789", "DS123456789", "JOB1234567"
    ),
    "list_ingestion_jobs": lambda t: t.list_ingestion_jobs(
        "KB123456789", "DS123456789", max_results=5
    ),
    "stop_ingestion_job": lambda t: t.stop_ingestion_job(
        "KB123456789", "DS123456789", "JOB1234567"
    ),
    "retrieve": lambda t: t.retrieve("KB123456789", query="q"),
}


@pytest.mark.parametrize("operation", sorted(_SDK_OPERATIONS))
def test_every_sdk_operation_reports_a_service_failure_as_aws_error(operation):
    target = _bmkb_raising(_client_error("ValidationException"))
    with pytest.raises(AwsError):
        _SDK_OPERATIONS[operation](target)


def test_service_failure_keeps_its_code_and_the_services_own_wording():
    target = _bmkb_raising(_client_error("ConflictException", "already exists"))
    with pytest.raises(AwsError) as excinfo:
        target.create_data_source_raw("KB123456789", {"name": "ds"})
    assert excinfo.value.code == "ConflictException"
    assert "ConflictException" in str(excinfo.value)
    assert "already exists" in str(excinfo.value)


def test_a_connection_failure_translates_but_carries_no_service_code():
    from botocore.exceptions import EndpointConnectionError

    target = _bmkb_raising(EndpointConnectionError(endpoint_url="https://example"))
    with pytest.raises(AwsError) as excinfo:
        target.get_knowledge_base("KB123456789")
    assert excinfo.value.code is None


def test_a_bug_is_not_disguised_as_an_aws_failure():
    """Only SDK exceptions translate. A TypeError is a defect and must surface
    as a traceback rather than a clean, expected-looking AwsError."""
    target = _bmkb_raising(TypeError("not an AWS problem"))
    with pytest.raises(TypeError):
        target.get_knowledge_base("KB123456789")
