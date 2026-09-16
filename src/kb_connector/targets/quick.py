"""Quick KB API target (future — stub).

Quick KB shares the same connector config + source-side setup as the Bedrock
managed KB target; only the control-plane API differs. This stub declares the
interface so the rest of the tool can target Quick once the APIs land.

All methods raise NotImplementedError until the Quick control-plane API is
available. The structure mirrors BmkbTarget so the implementation is a
matter of swapping the API calls, not redesigning.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


from kb_connector.targets.base import Target

_NOT_AVAILABLE = (
    "The Quick KB target is not yet available. Quick control-plane APIs have "
    "not launched. Use the bmkb target (the default) for now."
)


class QuickTarget(Target):
    """Quick KB control plane — placeholder until APIs land."""

    name = "quick"

    def __init__(self, *, session: Any, region: str | None, **kwargs: Any) -> None:
        self._region = region
        self._session = session

    def create_knowledge_base(
        self,
        *,
        name: str,
        role_arn: str,
        embedding_model_arn: str | None = None,
        kms_key_arn: str | None = None,
    ) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def get_knowledge_base(self, kb_id: str) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def wait_until_kb_active(
        self, kb_id: str, *, poll_interval_seconds: int = 5, timeout_seconds: int = 600
    ) -> str:
        raise NotImplementedError(_NOT_AVAILABLE)

    def create_data_source(
        self, kb_id: str, *, name: str, connector_parameters: dict[str, Any]
    ) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def create_data_source_raw(
        self, kb_id: str, payload: dict[str, Any]
    ) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def get_data_source(self, kb_id: str, ds_id: str) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def wait_until_ds_available(
        self, kb_id: str, ds_id: str, *, poll_interval_seconds: int = 3, timeout_seconds: int = 120
    ) -> str:
        raise NotImplementedError(_NOT_AVAILABLE)

    def delete_data_source(self, kb_id: str, ds_id: str) -> None:
        raise NotImplementedError(_NOT_AVAILABLE)

    def delete_knowledge_base(self, kb_id: str) -> None:
        raise NotImplementedError(_NOT_AVAILABLE)

    def start_ingestion_job(self, kb_id: str, ds_id: str) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def get_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def list_ingestion_jobs(self, kb_id: str, ds_id: str, *, max_results: int) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def stop_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)

    def retrieve(
        self,
        kb_id: str,
        *,
        query: str,
        user_id: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        raise NotImplementedError(_NOT_AVAILABLE)
