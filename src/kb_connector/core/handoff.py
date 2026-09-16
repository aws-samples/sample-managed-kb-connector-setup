"""Handoff document builders for split-admin workflows.

A handoff is a portable JSON document that lets one admin pick up where
another left off. Two directions:

    source -> aws     Source admin finished Stage 1 (identity provider).
                      AWS admin imports this and runs Stage 2.
    aws -> source     AWS admin finished Stage 2 (KB resources).
                      Source admin sees what was created.

These builders are pure functions over (state, config, timestamp) so they
can be reused by the CLI (writes to file + prints) and the service layer
(returns a dict for MCP/programmatic callers).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Any

from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import ConfigError
from kb_connector.core.identifiers import (
    validate_bedrock_id,
    validate_guid,
    validate_region,
    validate_secret_arn,
)
from kb_connector.core.state import ConnectorState

# Handoff format versions this tool can read. The builders stamp "1"; an
# unrecognized version is refused rather than best-effort parsed, since the
# whole point of the field is to make a format change detectable.
SUPPORTED_HANDOFF_VERSIONS = frozenset({"1"})

DIRECTION_SOURCE_TO_AWS = "source-to-aws"
DIRECTION_AWS_TO_SOURCE = "aws-to-source"
_DIRECTIONS = frozenset({DIRECTION_SOURCE_TO_AWS, DIRECTION_AWS_TO_SOURCE})


def now_utc_iso() -> str:
    """Current UTC time as an ISO8601 string with second precision."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_handoff(raw: Any) -> dict:
    """Validate a loaded handoff document and return it normalized.

    A handoff arrives as a file, usually over email or chat, from a person in
    a different team than the one importing it. Every value in it becomes
    connector state, and `secret_arn` in particular goes on to be the target of
    a force-delete during teardown — so the document is treated as input to be
    checked rather than a record to be trusted.

    Three checks carry that weight:

    * `version` is read, not just written. Skipping it would let a future
      format change be misparsed as the current one.
    * `direction` is compared with `==`, never `in`. A substring match would
      let any string merely *containing* "source-to-aws" select that branch.
    * Identifier fields are shape-checked before they reach state.

    Returns the document with recognized fields validated. Unknown top-level
    keys are preserved but ignored, so a newer writer can add fields without
    breaking an older reader.

    Raises:
        ConfigError: with a message naming the offending field.
    """
    if not isinstance(raw, dict):
        raise ConfigError(
            "Handoff file must contain a JSON object, got "
            f"{type(raw).__name__}."
        )

    version = str(raw.get("version", "")).strip()
    if version not in SUPPORTED_HANDOFF_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_HANDOFF_VERSIONS))
        raise ConfigError(
            f"Handoff file declares version {version or '(missing)'!r}, but "
            f"this version of the tool reads: {supported}. Regenerate the "
            f"handoff with `kb-connector handoff`."
        )

    direction = str(raw.get("direction", "")).strip()
    if direction not in _DIRECTIONS:
        expected = ", ".join(sorted(_DIRECTIONS))
        raise ConfigError(
            f"Handoff file declares direction {direction or '(missing)'!r}. "
            f"Expected exactly one of: {expected}."
        )

    section_key = "source" if direction == DIRECTION_SOURCE_TO_AWS else "aws"
    section = raw.get(section_key, {})
    if not isinstance(section, dict):
        raise ConfigError(
            f"Handoff file's {section_key!r} must be a JSON object, got "
            f"{type(section).__name__}."
        )

    # Only fields that reach state are validated, and only when present:
    # a handoff legitimately omits whatever its stage did not produce.
    checks: dict[str, Callable[[Any], str]] = {
        "tenant_id": lambda v: validate_guid(v, field="handoff source.tenant_id"),
        "client_id": lambda v: validate_guid(v, field="handoff source.client_id"),
        "region": lambda v: validate_region(v, field="handoff aws.region"),
        "secret_arn": lambda v: validate_secret_arn(
            v, field="handoff aws.secret_arn"
        ),
        "knowledge_base_id": lambda v: validate_bedrock_id(
            v, field="handoff aws.knowledge_base_id"
        ),
        "data_source_id": lambda v: validate_bedrock_id(
            v, field="handoff aws.data_source_id"
        ),
    }
    normalized_section = dict(section)
    for key, check in checks.items():
        if section.get(key) is not None:
            try:
                normalized_section[key] = check(section[key])
            except ConfigError:
                raise
            except Exception as exc:
                # identifiers.* raise ConnectorError; surface as ConfigError so
                # the CLI reports it as a bad input file rather than an AWS fault.
                raise ConfigError(str(exc)) from exc

    out = dict(raw)
    out["version"] = version
    out["direction"] = direction
    out[section_key] = normalized_section
    return out


def build_source_to_aws(
    connector_name: str,
    cs: ConnectorState | None,
    cfg: ConnectorConfig | None,
    *,
    created_at: str | None = None,
) -> dict:
    """Build a source-to-aws handoff document."""
    connector_type = (
        (cs.connector_type if cs else None)
        or (cfg.type if cfg else "unknown")
    )
    tenant_id = (
        (cs.tenant_id if cs else None)
        or (cfg.tenant_id if cfg else None)
    )

    source: dict = {}
    if tenant_id:
        source["tenant_id"] = tenant_id
    if cs and cs.client_app_id:
        source["client_id"] = cs.client_app_id
    if cfg:
        if cfg.credential:
            source["credential"] = cfg.credential
        source["acl"] = cfg.acl
        if cfg.type == "sharepoint":
            site_urls = cfg.get("site_urls", [])
            if site_urls:
                source["site_urls"] = site_urls
            host = cfg.get("sharepoint_host")
            if host:
                source["sharepoint_host"] = host

    return {
        "version": "1",
        "connector": connector_name,
        "type": connector_type,
        "direction": "source-to-aws",
        "source": source,
        "created_at": created_at or now_utc_iso(),
    }


def build_aws_to_source(
    connector_name: str,
    cs: ConnectorState | None,
    cfg: ConnectorConfig | None,
    *,
    created_at: str | None = None,
) -> dict:
    """Build an aws-to-source handoff document."""
    connector_type = (
        (cs.connector_type if cs else None)
        or (cfg.type if cfg else "unknown")
    )

    aws: dict = {}
    if cs:
        if cs.region:
            aws["region"] = cs.region
        if cs.knowledge_base_id:
            aws["knowledge_base_id"] = cs.knowledge_base_id
        if cs.data_source_id:
            aws["data_source_id"] = cs.data_source_id
        if cs.secret_arn:
            aws["secret_arn"] = cs.secret_arn

    return {
        "version": "1",
        "connector": connector_name,
        "type": connector_type,
        "direction": "aws-to-source",
        "aws": aws,
        "created_at": created_at or now_utc_iso(),
    }
