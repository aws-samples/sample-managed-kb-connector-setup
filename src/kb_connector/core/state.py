"""State file management (kb-connector.state.json).

The config file is *intent* ("what I want to set up"). The state file tracks
*what was actually created* (app IDs, KB IDs, DS IDs, role ARNs, secret ARNs)
— like Terraform state.

Design:
- State is per-project: ./kb-connector.state.json (gitignored, mode 0600).
- State is keyed by connector name (one entry per configured connector).
- Only non-secret identifiers are stored (no private keys, passwords, tokens).
  This is enforced structurally: `save_state` serializes declared dataclass
  fields via asdict(), so credential material stashed on dynamic attributes
  (cs._p12_bytes and friends) cannot reach the file.
- `created_resources` maps each resource to "tool", "tool-untagged", or
  "external". Resources the tool provisioned are "tool"; ones it provisioned
  but could not tag are "tool-untagged"; resources the operator pointed it at —
  an existing knowledge base via --kb, that KB's own role, or anything adopted
  with --adopt-existing-resources — are "external". Teardown deletes both tool
  markers unless told otherwise but never "external", so attaching a connector
  to a pre-existing knowledge base can't lead to that KB being destroyed.
  "tool-untagged" additionally lets setup recognize its own untagged resource
  on a later run instead of mistaking it for a stranger's.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields as dc_fields
from typing import Any

from kb_connector.core.fileio import atomic_write_json

DEFAULT_STATE_FILENAME = "kb-connector.state.json"

# Resource kinds tracked in ConnectorState.created_resources. These are the
# keys teardown consults, and they match its --only choices.
RESOURCE_KB = "kb"
RESOURCE_DS = "ds"
# A resource-kind label, not a credential. Keep the suppression comment bare:
# bandit reads anything after the test id as further test ids, so a trailing
# justification silently stops it applying.
RESOURCE_SECRET = "secret"  # nosec B105
RESOURCE_ROLE = "role"
RESOURCE_CERT = "cert"
RESOURCE_APP = "app"
RESOURCE_CERT_BUCKET = "cert_bucket"

OWNER_TOOL = "tool"
OWNER_EXTERNAL = "external"
# A resource this tool created but could not tag, because the caller lacked
# iam:TagRole / secretsmanager:TagResource or tagging was turned off. Ours for
# teardown purposes, but with no tag on the resource to prove it next time —
# which is exactly why the fact is recorded here instead.
OWNER_TOOL_UNTAGGED = "tool-untagged"

# Both tool markers mean "this tool created it", so both are in teardown's scope.
_TOOL_OWNED = frozenset({OWNER_TOOL, OWNER_TOOL_UNTAGGED})


@dataclass
class ConnectorState:
    """Non-secret identifiers for a single connector, shared across commands.

    Every field is optional: a fresh run starts empty and each command fills in
    what it produces. Commands check for required values and raise StateError
    with a clear message if something is missing.
    """

    # Context
    connector_type: str | None = None  # "sharepoint", "onedrive", etc.
    tenant_id: str | None = None
    region: str | None = None

    # Source-side (provider) outputs
    client_app_id: str | None = None
    client_app_object_id: str | None = None
    cert_thumbprint_b64url: str | None = None
    cert_not_after: str | None = None  # ISO8601 cert expiry

    # AWS-side outputs
    secret_arn: str | None = None
    kb_role_arn: str | None = None
    cert_s3_bucket: str | None = None
    cert_s3_key: str | None = None
    knowledge_base_id: str | None = None
    data_source_id: str | None = None

    # Monitor outputs
    last_ingestion_job_id: str | None = None

    # Tracking
    created_resources: dict = field(default_factory=dict)  # resource -> "tool" | "external"
    last_updated: str | None = None

    def merge(self, **updates: Any) -> "ConnectorState":
        """Return a copy with any non-None updates applied."""
        data = asdict(self)
        for key, value in updates.items():
            if value is not None and key in data:
                data[key] = value
        return ConnectorState(**data)

    # --- Ownership tracking -------------------------------------------------

    def record_owned(self, resource: str) -> None:
        """Mark a resource as provisioned by this tool (safe for teardown)."""
        self.created_resources[resource] = OWNER_TOOL

    def record_external(self, resource: str) -> None:
        """Mark a resource as pre-existing/adopted (teardown must not delete)."""
        self.created_resources[resource] = OWNER_EXTERNAL

    def record_ownership(self, resource: str, marker: str) -> None:
        """Record a resource's ownership from a ProvisionedResource marker.

        Anything that isn't a recognized tool marker is stored as external, so
        an unexpected value fails safe: teardown leaves the resource alone.
        """
        self.created_resources[resource] = (
            marker if marker in _TOOL_OWNED else OWNER_EXTERNAL
        )

    def is_tool_owned(self, resource: str) -> bool:
        """Whether teardown may delete this resource.

        Unknown resources return True: adoption is always recorded explicitly,
        so an absent entry means "not adopted", and treating unknown as "don't
        delete" would strip teardown of its purpose. Both tool markers count as
        owned, since a resource created without a tag is still one we created.
        """
        return self.created_resources.get(resource, OWNER_TOOL) in _TOOL_OWNED

    def created_untagged(self, resource: str) -> bool:
        """Whether this tool created the resource but could not tag it.

        Setup consults this before refusing to reuse a resource whose ownership
        tag is missing: absent because tagging was denied is not the same as
        absent because the resource belongs to someone else.
        """
        return self.created_resources.get(resource) == OWNER_TOOL_UNTAGGED

    def adopted_resources(self) -> list[str]:
        """Resource kinds explicitly recorded as external."""
        return sorted(
            key for key, val in self.created_resources.items() if val == OWNER_EXTERNAL
        )


@dataclass
class StateFile:
    """Top-level state file containing all connector states."""

    connectors: dict[str, ConnectorState] = field(default_factory=dict)

    def get(self, connector_name: str) -> ConnectorState:
        """Get state for a connector, creating an empty entry if absent."""
        if connector_name not in self.connectors:
            self.connectors[connector_name] = ConnectorState()
        return self.connectors[connector_name]

    def set(self, connector_name: str, state: ConnectorState) -> None:
        """Set state for a connector."""
        self.connectors[connector_name] = state


def _state_path(path: str | None) -> str:
    return path or os.path.join(os.getcwd(), DEFAULT_STATE_FILENAME)


def load_state(path: str | None = None) -> StateFile:
    """Load state from disk, returning empty state if the file is absent.

    Unknown keys in the file are silently ignored so a state file written by
    a newer version of the tool doesn't crash an older one.
    """
    resolved = _state_path(path)
    if not os.path.exists(resolved):
        return StateFile()
    try:
        with open(resolved, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        # Corrupt/unreadable state file shouldn't be fatal: treat as empty.
        return StateFile()

    known_fields = {f.name for f in dc_fields(ConnectorState)}
    connectors: dict[str, ConnectorState] = {}
    for name, data in raw.get("connectors", {}).items():
        if isinstance(data, dict):
            filtered = {k: v for k, v in data.items() if k in known_fields}
            connectors[name] = ConnectorState(**filtered)

    return StateFile(connectors=connectors)


def save_state(state_file: StateFile, path: str | None = None) -> str:
    """Persist state to disk (pretty-printed, mode 0600); return the path.

    Written atomically: a partial write would be unparseable, and load_state
    treats an unparseable file as empty state, which would un-track every
    resource the tool has created.
    """
    resolved = _state_path(path)
    data = {
        "connectors": {
            name: asdict(cs) for name, cs in state_file.connectors.items()
        }
    }
    return atomic_write_json(resolved, data, indent=2, sort_keys=True)
