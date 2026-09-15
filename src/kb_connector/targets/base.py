"""Target interface — control-plane abstraction for KB backends.

A Target encapsulates the control-plane API for a knowledge base backend.
The same connector config + source-side setup works across targets; only
the control-plane calls differ.

  * BmkbTarget  — the bedrock-agent managed knowledge base API (current).
                  "BMKB" is shortened to that throughout the code.
  * QuickTarget — Quick KB API (future, when APIs land)

The rest of the tool (setup, monitor, validate, diagnose) talks to a Target
through this interface, never directly to a specific backend's API.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any


class Target(ABC):
    """Control-plane adapter for a knowledge base backend."""

    name: str  # "bmkb" | "quick"

    @abstractmethod
    def create_knowledge_base(
        self,
        *,
        name: str,
        role_arn: str,
        embedding_model_arn: str | None = None,
        kms_key_arn: str | None = None,
    ) -> Mapping[str, Any]:
        """Create a knowledge base; return the created KB object."""
        ...

    @abstractmethod
    def get_knowledge_base(self, kb_id: str) -> Mapping[str, Any]:
        """Get a knowledge base by ID."""
        ...

    @abstractmethod
    def wait_until_kb_active(
        self, kb_id: str, *, poll_interval_seconds: int = 5, timeout_seconds: int = 300
    ) -> str:
        """Poll until the KB is ACTIVE; return the final status."""
        ...

    @abstractmethod
    def create_data_source(
        self, kb_id: str, *, name: str, connector_parameters: dict[str, Any]
    ) -> Mapping[str, Any]:
        """Create a managed-connector data source; return the created DS."""
        ...

    @abstractmethod
    def get_data_source(self, kb_id: str, ds_id: str) -> Mapping[str, Any]:
        """Get a data source by KB + DS ID."""
        ...

    @abstractmethod
    def wait_until_ds_available(
        self, kb_id: str, ds_id: str, *, poll_interval_seconds: int = 3, timeout_seconds: int = 120
    ) -> str:
        """Poll until the DS is AVAILABLE; return the final status."""
        ...

    @abstractmethod
    def delete_data_source(self, kb_id: str, ds_id: str) -> None:
        """Delete a data source."""
        ...

    @abstractmethod
    def delete_knowledge_base(self, kb_id: str) -> None:
        """Delete a knowledge base."""
        ...

    @abstractmethod
    def start_ingestion_job(self, kb_id: str, ds_id: str) -> Mapping[str, Any]:
        """Start an ingestion job; return the job object."""
        ...

    @abstractmethod
    def get_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> Mapping[str, Any]:
        """Get an ingestion job by ID."""
        ...

    @abstractmethod
    def list_ingestion_jobs(self, kb_id: str, ds_id: str, *, max_results: int) -> Mapping[str, Any]:
        """List recent ingestion jobs, newest first."""
        ...

    @abstractmethod
    def stop_ingestion_job(self, kb_id: str, ds_id: str, job_id: str) -> Mapping[str, Any]:
        """Request that a running ingestion job stop.

        The stop is asynchronous: the job moves to STOPPING and reaches
        STOPPED on its own.
        """
        ...

    @abstractmethod
    def retrieve(
        self,
        kb_id: str,
        *,
        query: str,
        user_id: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        """Send a retrieve request; return the results.

        Pass user_id to enable ACL-aware retrieval (the value goes into
        the top-level userContext field). Pass filter to apply a metadata
        filter; the target places it under whichever search configuration
        its knowledge-base kind accepts.
        """
        ...
