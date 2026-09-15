"""KB + data source create/get/update/delete operations.

Uses the SigV4 signed client to drive KB lifecycle calls. Payload construction
is separated from the API calls so shapes can be unit-tested without AWS access.

ACL field handling: `aclEnabled` at the connectorParameters top level is the
toggle for document-level access control. `crawlIdentities` is set to the same
value so identity crawling stays consistent with the ACL setting.
"""

from __future__ import annotations

import time

from kb_connector.core.errors import AwsError
from kb_connector.core.signed_client import SignedClient


# --- Payload builders --------------------------------------------------------


def build_knowledge_base_payload(
    *,
    name: str,
    role_arn: str,
    embedding_model_arn: str | None = None,
    kms_key_arn: str | None = None,
) -> dict:
    """CreateKnowledgeBase body for a MANAGED knowledge base.

    When embedding_model_arn is omitted, the service picks its own default
    (managed embedding). A customer-managed kms_key_arn encrypts the knowledge
    base through managedKnowledgeBaseConfiguration.
    serverSideEncryptionConfiguration; CreateKnowledgeBase has no top-level
    key field, so this is the only place it belongs.
    """
    config: dict = {}
    if embedding_model_arn:
        config["embeddingModelArn"] = embedding_model_arn
    if kms_key_arn:
        config["serverSideEncryptionConfiguration"] = {"kmsKeyArn": kms_key_arn}
    return {
        "name": name,
        "roleArn": role_arn,
        "knowledgeBaseConfiguration": {
            "type": "MANAGED",
            "managedKnowledgeBaseConfiguration": config,
        },
    }


def build_data_source_payload(
    *,
    name: str,
    connector_parameters: dict,
) -> dict:
    """Wrap connectorParameters into a full CreateDataSource request body.

    Chunking is omitted — managed-embedding KBs reject an explicit
    chunkingConfiguration with "A chunking strategy cannot be specified
    with a managed embedding model."
    """
    return {
        "name": name,
        "dataSourceConfiguration": {
            "type": "MANAGED_KNOWLEDGE_BASE_CONNECTOR",
            "managedKnowledgeBaseConnectorConfiguration": {
                "connectorParameters": connector_parameters
            },
        },
    }


# --- API calls ---------------------------------------------------------------


def create_knowledge_base(client: SignedClient, payload: dict) -> dict:
    """PUT a new knowledge base; returns the created KB object."""
    return client.buildtime("PUT", "/knowledgebases/", payload)


def get_knowledge_base(client: SignedClient, kb_id: str) -> dict:
    """GET a knowledge base by ID."""
    return client.buildtime("GET", f"/knowledgebases/{kb_id}")


def create_data_source(client: SignedClient, kb_id: str, payload: dict) -> dict:
    """PUT a new data source under a knowledge base."""
    return client.buildtime("PUT", f"/knowledgebases/{kb_id}/datasources", payload)


def get_data_source(client: SignedClient, kb_id: str, ds_id: str) -> dict:
    """GET a data source by KB + DS ID."""
    return client.buildtime("GET", f"/knowledgebases/{kb_id}/datasources/{ds_id}")


def start_ingestion_job(client: SignedClient, kb_id: str, ds_id: str) -> dict:
    """PUT to start an ingestion job."""
    return client.buildtime(
        "PUT", f"/knowledgebases/{kb_id}/datasources/{ds_id}/ingestionjobs"
    )


def get_ingestion_job(client: SignedClient, kb_id: str, ds_id: str, job_id: str) -> dict:
    """GET an ingestion job by ID."""
    return client.buildtime(
        "GET",
        f"/knowledgebases/{kb_id}/datasources/{ds_id}/ingestionjobs/{job_id}",
    )


# --- Waiters -----------------------------------------------------------------


_KB_TERMINAL_BAD = {"FAILED", "DELETING", "DELETE_UNSUCCESSFUL"}
_DS_TERMINAL_BAD = {"DELETE_UNSUCCESSFUL", "FAILED"}


def wait_until_kb_active(
    client: SignedClient,
    kb_id: str,
    *,
    poll_interval_seconds: int = 5,
    timeout_seconds: int = 300,
) -> str:
    """Poll GetKnowledgeBase until status is ACTIVE.

    A freshly-created managed KB returns CREATING and CreateDataSource rejects
    with 409 until the KB transitions to ACTIVE. Returns the final status.
    Raises if the KB enters a terminal-bad status or the timeout elapses.
    """
    deadline = time.time() + timeout_seconds
    last_status: str = ""
    while time.time() < deadline:
        resp = get_knowledge_base(client, kb_id)
        kb = resp.get("knowledgeBase", resp)
        status = (kb.get("status") or "").upper()
        last_status = status
        if status == "ACTIVE":
            return status
        if status in _KB_TERMINAL_BAD:
            reasons = kb.get("failureReasons") or []
            raise AwsError(
                f"Knowledge base {kb_id} entered terminal-bad status {status}"
                + (f": {reasons}" if reasons else "")
            )
        time.sleep(poll_interval_seconds)  # nosemgrep: arbitrary-sleep -- polling backoff
    raise TimeoutError(
        f"Knowledge base {kb_id} did not reach ACTIVE within "
        f"{timeout_seconds}s (last status {last_status or 'UNKNOWN'})."
    )


def wait_until_ds_available(
    client: SignedClient,
    kb_id: str,
    ds_id: str,
    *,
    poll_interval_seconds: int = 3,
    timeout_seconds: int = 120,
) -> str:
    """Poll GetDataSource until status is AVAILABLE.

    Managed-connector data sources transition CREATING -> AVAILABLE async.
    StartIngestionJob while the DS is CREATING fails with HTTP 409. Returns
    the final status. Raises on terminal-bad or timeout.
    """
    deadline = time.time() + timeout_seconds
    last_status: str = ""
    while time.time() < deadline:
        resp = get_data_source(client, kb_id, ds_id)
        ds = resp.get("dataSource", resp)
        status = (ds.get("status") or "").upper()
        last_status = status
        if status == "AVAILABLE":
            return status
        if status in _DS_TERMINAL_BAD:
            reasons = ds.get("failureReasons") or []
            raise AwsError(
                f"Data source {ds_id} entered terminal-bad status {status}"
                + (f": {reasons}" if reasons else "")
            )
        time.sleep(poll_interval_seconds)  # nosemgrep: arbitrary-sleep -- polling backoff
    raise TimeoutError(
        f"Data source {ds_id} did not reach AVAILABLE within "
        f"{timeout_seconds}s (last status {last_status or 'UNKNOWN'})."
    )
