"""KB + data source create/get/update/delete operations.

Payload construction is separated from the calls that send it, so request
shapes can be unit-tested without AWS access. The waiters below poll through
the Target interface rather than a client, which keeps them independent of
how a target reaches AWS.

ACL field handling: `aclEnabled` at the connectorParameters top level is the
toggle for document-level access control. `crawlIdentities` is set to the same
value so identity crawling stays consistent with the ACL setting.
"""

from __future__ import annotations

import time
from typing import Any

from kb_connector.core.errors import AwsError


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


# --- Waiters -----------------------------------------------------------------


_KB_TERMINAL_BAD = {"FAILED", "DELETING", "DELETE_UNSUCCESSFUL"}
_DS_TERMINAL_BAD = {"DELETE_UNSUCCESSFUL", "FAILED"}


def wait_until_kb_active(
    target: Any,
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
        resp = target.get_knowledge_base(kb_id)
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
    target: Any,
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
        resp = target.get_data_source(kb_id, ds_id)
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
