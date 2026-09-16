"""Bedrock Agent API target (managed Knowledge Bases).

Implements the Target interface against the bedrock-agent control plane and the
bedrock-agent-runtime data plane, using the payload builders from
core.knowledge_base.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any, Callable, ParamSpec, TypeVar

from kb_connector.core import knowledge_base as kb
from kb_connector.core.errors import aws_error_from
from kb_connector.targets.base import Target

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _as_aws_error(fn: Callable[_P, _R]) -> Callable[_P, _R]:
    """Translate botocore exceptions from this boundary into `AwsError`.

    Callers up the stack catch `AwsError` to enrich or record a failure —
    probe captures the response to disk, setup turns a data-source name
    collision into guidance. boto3 raises `ClientError`, so without this
    translation those handlers never run and the failure escapes to the CLI's
    top-level instead: the enrichment is silently lost, and probe writes no
    summary for the run that failed.

    `ParamSpec` keeps each method's signature intact, so the precise response
    TypeDefs survive the decorator.

    botocore is imported inside the handler rather than at module scope so this
    module stays off the botocore import path for `--help`. By the time any
    exception can arrive here `__init__` has already built two clients, so the
    import is a dictionary lookup.
    """

    @functools.wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(exc, (ClientError, BotoCoreError)):
                raise aws_error_from(exc) from exc
            raise

    return wrapper

if TYPE_CHECKING:
    # Type-only imports: boto3 stays off the import path for --help and
    # pure-logic runs, and the stub packages are dev-only dependencies. Naming
    # the client types is what makes the SDK's response TypedDicts visible here
    # rather than collapsing to Any.
    from boto3 import Session
    from mypy_boto3_bedrock_agent import AgentsforBedrockClient
    from mypy_boto3_bedrock_agent.type_defs import (
        CreateDataSourceResponseTypeDef,
        CreateKnowledgeBaseResponseTypeDef,
        GetDataSourceResponseTypeDef,
        GetIngestionJobResponseTypeDef,
        GetKnowledgeBaseResponseTypeDef,
        ListIngestionJobsResponseTypeDef,
        StartIngestionJobResponseTypeDef,
        StopIngestionJobResponseTypeDef,
    )
    from mypy_boto3_bedrock_agent_runtime import AgentsforBedrockRuntimeClient
    from mypy_boto3_bedrock_agent_runtime.type_defs import RetrieveResponseTypeDef


class BmkbTarget(Target):
    """bedrock-agent control plane for managed KBs."""

    name = "bmkb"

    def __init__(self, *, session: Session, region: str | None) -> None:
        self._region = region
        # Two clients because the control plane and the retrieve path are two
        # services. Endpoints resolve from the session and the SDK's own
        # configuration; this target has no endpoint settings of its own.
        self._client: AgentsforBedrockClient = session.client(
            "bedrock-agent", region_name=region
        )
        self._runtime: AgentsforBedrockRuntimeClient = session.client(
            "bedrock-agent-runtime", region_name=region
        )

    # --- Knowledge base ------------------------------------------------------

    @_as_aws_error
    def create_knowledge_base(
        self,
        *,
        name: str,
        role_arn: str,
        embedding_model_arn: str | None = None,
        kms_key_arn: str | None = None,
    ) -> CreateKnowledgeBaseResponseTypeDef:
        payload = kb.build_knowledge_base_payload(
            name=name,
            role_arn=role_arn,
            embedding_model_arn=embedding_model_arn,
            kms_key_arn=kms_key_arn,
        )
        return self._client.create_knowledge_base(**payload)

    @_as_aws_error
    def get_knowledge_base(self, kb_id: str) -> GetKnowledgeBaseResponseTypeDef:
        return self._client.get_knowledge_base(knowledgeBaseId=kb_id)

    def wait_until_kb_active(
        self, kb_id: str, *, poll_interval_seconds: int = 5, timeout_seconds: int = 600
    ) -> str:
        return kb.wait_until_kb_active(
            self, kb_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    @_as_aws_error
    def delete_knowledge_base(self, kb_id: str) -> None:
        self._client.delete_knowledge_base(knowledgeBaseId=kb_id)

    # --- Data source ---------------------------------------------------------

    def create_data_source(
        self, kb_id: str, *, name: str, connector_parameters: dict[str, Any]
    ) -> CreateDataSourceResponseTypeDef:
        payload = kb.build_data_source_payload(
            name=name, connector_parameters=connector_parameters
        )
        return self.create_data_source_raw(kb_id, payload)

    @_as_aws_error
    def create_data_source_raw(
        self, kb_id: str, payload: dict[str, Any]
    ) -> CreateDataSourceResponseTypeDef:
        """Create a DS with a fully-formed payload (for non-managed shapes like S3)."""
        return self._client.create_data_source(knowledgeBaseId=kb_id, **payload)

    @_as_aws_error
    def get_data_source(self, kb_id: str, ds_id: str) -> GetDataSourceResponseTypeDef:
        return self._client.get_data_source(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )

    def wait_until_ds_available(
        self, kb_id: str, ds_id: str, *, poll_interval_seconds: int = 3, timeout_seconds: int = 120
    ) -> str:
        return kb.wait_until_ds_available(
            self, kb_id, ds_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    @_as_aws_error
    def delete_data_source(self, kb_id: str, ds_id: str) -> None:
        self._client.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)

    # --- Ingestion -----------------------------------------------------------

    @_as_aws_error
    def start_ingestion_job(
        self, kb_id: str, ds_id: str
    ) -> StartIngestionJobResponseTypeDef:
        return self._client.start_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )

    @_as_aws_error
    def get_ingestion_job(
        self, kb_id: str, ds_id: str, job_id: str
    ) -> GetIngestionJobResponseTypeDef:
        return self._client.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )

    @_as_aws_error
    def list_ingestion_jobs(
        self, kb_id: str, ds_id: str, *, max_results: int
    ) -> ListIngestionJobsResponseTypeDef:
        return self._client.list_ingestion_jobs(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, maxResults=max_results
        )

    @_as_aws_error
    def stop_ingestion_job(
        self, kb_id: str, ds_id: str, job_id: str
    ) -> StopIngestionJobResponseTypeDef:
        return self._client.stop_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )

    # --- Retrieve ------------------------------------------------------------

    @_as_aws_error
    def retrieve(
        self,
        kb_id: str,
        *,
        query: str,
        user_id: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> RetrieveResponseTypeDef:
        request: dict[str, Any] = {
            "knowledgeBaseId": kb_id,
            "retrievalQuery": {"text": query},
        }
        if user_id:
            # Top-level userContext for ACL-aware retrieval. Per the Bedrock
            # managed-KB docs the userId is the user's universal email
            # address associated with the underlying data source.
            request["userContext"] = {"userId": user_id}
        if filter:
            # Managed knowledge bases take managedSearchConfiguration. The
            # vectorSearchConfiguration shape used by vector KBs is rejected
            # outright here ("not supported for managed knowledge bases"), so
            # this is not an alias — sending the wrong one fails the call.
            request["retrievalConfiguration"] = {
                "managedSearchConfiguration": {"filter": filter}
            }
        return self._runtime.retrieve(**request)
