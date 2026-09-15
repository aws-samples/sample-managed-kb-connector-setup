"""Bedrock Agent API target (managed Knowledge Bases).

Implements the Target interface against the bedrock-agent control plane,
using the SigV4-signed client and the payload builders from core.knowledge_base.
"""

from __future__ import annotations

from typing import Any

from kb_connector.core import knowledge_base as kb
from kb_connector.core.signed_client import SignedClient
from kb_connector.targets.base import Target

_PUBLIC_BUILDTIME = "https://bedrock-agent.{region}.amazonaws.com"
_PUBLIC_RUNTIME = "https://bedrock-agent-runtime.{region}.amazonaws.com"


class BmkbTarget(Target):
    """bedrock-agent control plane for managed KBs."""

    name = "bmkb"

    def __init__(
        self,
        *,
        session: Any,
        region: str,
        buildtime_endpoint: str | None = None,
        runtime_endpoint: str | None = None,
    ) -> None:
        self._region = region
        buildtime = buildtime_endpoint or _PUBLIC_BUILDTIME.format(region=region)
        runtime = runtime_endpoint or _PUBLIC_RUNTIME.format(region=region)
        self._client = SignedClient(
            session=session,
            buildtime_endpoint=buildtime,
            runtime_endpoint=runtime,
            region=region,
        )

    @property
    def client(self) -> SignedClient:
        """Expose the signed client for advanced/raw calls (e.g. probe)."""
        return self._client

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
        return kb.create_knowledge_base(self._client, payload)

    def get_knowledge_base(self, kb_id: str) -> dict:
        return kb.get_knowledge_base(self._client, kb_id)

    def wait_until_kb_active(
        self, kb_id: str, *, poll_interval_seconds: int = 5, timeout_seconds: int = 300
    ) -> str:
        return kb.wait_until_kb_active(
            self._client, kb_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    def delete_knowledge_base(self, kb_id: str) -> None:
        self._client.buildtime("DELETE", f"/knowledgebases/{kb_id}")

    # --- Data source ---------------------------------------------------------

    def create_data_source(
        self, kb_id: str, *, name: str, connector_parameters: dict
    ) -> dict:
        payload = kb.build_data_source_payload(
            name=name, connector_parameters=connector_parameters
        )
        return kb.create_data_source(self._client, kb_id, payload)

    def create_data_source_raw(self, kb_id: str, payload: dict) -> dict:
        """Create a DS with a fully-formed payload (for non-managed shapes like S3)."""
        return kb.create_data_source(self._client, kb_id, payload)

    def get_data_source(self, kb_id: str, ds_id: str) -> dict:
        return kb.get_data_source(self._client, kb_id, ds_id)

    def wait_until_ds_available(
        self, kb_id: str, ds_id: str, *, poll_interval_seconds: int = 3, timeout_seconds: int = 120
    ) -> str:
        return kb.wait_until_ds_available(
            self._client, kb_id, ds_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    def delete_data_source(self, kb_id: str, ds_id: str) -> None:
        self._client.buildtime("DELETE", f"/knowledgebases/{kb_id}/datasources/{ds_id}")

    # --- Ingestion -----------------------------------------------------------

    def start_ingestion_job(self, kb_id: str, ds_id: str) -> dict:
        return kb.start_ingestion_job(self._client, kb_id, ds_id)

    def get_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> dict:
        return kb.get_ingestion_job(self._client, kb_id, ds_id, job_id)

    # --- Retrieve ------------------------------------------------------------

    def retrieve(
        self,
        kb_id: str,
        *,
        query: str,
        user_id: str | None = None,
        filter: dict | None = None,
    ) -> dict:
        body: dict = {"retrievalQuery": {"text": query}}
        if user_id:
            # Top-level userContext for ACL-aware retrieval. Per the Bedrock
            # managed-KB docs the userId is the user's universal email
            # address associated with the underlying data source.
            body["userContext"] = {"userId": user_id}
        if filter:
            # Managed knowledge bases take managedSearchConfiguration. The
            # vectorSearchConfiguration shape used by vector KBs is rejected
            # outright here ("not supported for managed knowledge bases"), so
            # this is not an alias — sending the wrong one fails the call.
            body["retrievalConfiguration"] = {
                "managedSearchConfiguration": {"filter": filter}
            }
        return self._client.runtime("POST", f"/knowledgebases/{kb_id}/retrieve", body)
