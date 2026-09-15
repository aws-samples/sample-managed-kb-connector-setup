"""Bedrock Agent API target (managed Knowledge Bases).

Implements the Target interface against the bedrock-agent control plane and the
bedrock-agent-runtime data plane, using the payload builders from
core.knowledge_base.
"""

from __future__ import annotations

from typing import Any

from kb_connector.core import knowledge_base as kb
from kb_connector.targets.base import Target


class BmkbTarget(Target):
    """bedrock-agent control plane for managed KBs."""

    name = "bmkb"

    def __init__(self, *, session: Any, region: str) -> None:
        self._region = region
        # Two clients because the control plane and the retrieve path are two
        # services. Endpoints resolve from the session and the SDK's own
        # configuration; this target has no endpoint settings of its own.
        self._client = session.client("bedrock-agent", region_name=region)
        self._runtime = session.client("bedrock-agent-runtime", region_name=region)

    # --- Knowledge base ------------------------------------------------------

    def create_knowledge_base(
        self,
        *,
        name: str,
        role_arn: str,
        embedding_model_arn: str | None = None,
        kms_key_arn: str | None = None,
    ) -> dict:
        payload = kb.build_knowledge_base_payload(
            name=name,
            role_arn=role_arn,
            embedding_model_arn=embedding_model_arn,
            kms_key_arn=kms_key_arn,
        )
        return self._client.create_knowledge_base(**payload)

    def get_knowledge_base(self, kb_id: str) -> dict:
        return self._client.get_knowledge_base(knowledgeBaseId=kb_id)

    def wait_until_kb_active(
        self, kb_id: str, *, poll_interval_seconds: int = 5, timeout_seconds: int = 300
    ) -> str:
        return kb.wait_until_kb_active(
            self, kb_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    def delete_knowledge_base(self, kb_id: str) -> None:
        self._client.delete_knowledge_base(knowledgeBaseId=kb_id)

    # --- Data source ---------------------------------------------------------

    def create_data_source(
        self, kb_id: str, *, name: str, connector_parameters: dict
    ) -> dict:
        payload = kb.build_data_source_payload(
            name=name, connector_parameters=connector_parameters
        )
        return self.create_data_source_raw(kb_id, payload)

    def create_data_source_raw(self, kb_id: str, payload: dict) -> dict:
        """Create a DS with a fully-formed payload (for non-managed shapes like S3)."""
        return self._client.create_data_source(knowledgeBaseId=kb_id, **payload)

    def get_data_source(self, kb_id: str, ds_id: str) -> dict:
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

    def delete_data_source(self, kb_id: str, ds_id: str) -> None:
        self._client.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)

    # --- Ingestion -----------------------------------------------------------

    def start_ingestion_job(self, kb_id: str, ds_id: str) -> dict:
        return self._client.start_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )

    def get_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> dict:
        return self._client.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )

    def list_ingestion_jobs(self, kb_id: str, ds_id: str, *, max_results: int) -> dict:
        return self._client.list_ingestion_jobs(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, maxResults=max_results
        )

    def stop_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> dict:
        return self._client.stop_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )

    # --- Retrieve ------------------------------------------------------------

    def retrieve(
        self,
        kb_id: str,
        *,
        query: str,
        user_id: str | None = None,
        filter: dict | None = None,
    ) -> dict:
        request: dict = {
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
