"""Service layer — programmatic entrypoints behind the CLI and MCP server.

Each function takes plain kwargs (not argparse Namespaces), resolves config
+ state, runs the core logic, and returns a structured dataclass. No
printing, no exit codes — callers decide how to render or exit.

The CLI continues to do its own printing and argparse handling. The MCP
server (kb_connector.mcp_server) marshals these dataclasses to JSON and
returns them to the agent.

All functions accept optional `config_path` and `state_path` so callers
can target a specific project. AWS sessions and Targets are built lazily
through small factory hooks the test suite can monkeypatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from kb_connector.core.config import ConnectorConfig, ToolConfig, load_config
from kb_connector.core.diagnostics import (
    CheckResult,
    DiagnoseResult,
    build_diagnose_result,
    check_cert_expiry,
    check_cloudtrail_permissions,
    check_ingestion_logs,
    check_secret_validity,
    default_log_group_name,
)
from kb_connector.core.errors import ConfigError, StateError
from kb_connector.core.handoff import build_aws_to_source, build_source_to_aws
from kb_connector.core.monitor import MonitorResult, poll_job, start_and_poll
from kb_connector.core.state import ConnectorState, StateFile, load_state


# --- Result types added by the service layer ---------------------------------


@dataclass
class ConnectorSummary:
    """Compact view of a configured connector + its state."""

    name: str
    type: str
    region: str | None = None
    has_state: bool = False
    knowledge_base_id: str | None = None
    data_source_id: str | None = None
    secret_arn: str | None = None
    cert_not_after: str | None = None
    last_ingestion_job_id: str | None = None


@dataclass
class ListResult:
    """Structured result from list_connectors."""

    connectors: list[ConnectorSummary]
    config_path: str | None = None


@dataclass
class ValidateResult:
    """Structured result from validate."""

    connector: str
    healthy: bool
    checks: list[CheckResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class HandoffResult:
    """Structured result from handoff (the document, not a file path)."""

    connector: str
    direction: Literal["source-to-aws", "aws-to-source"]
    document: dict


# --- Factory hooks (overridable for tests) -----------------------------------


def _default_session_factory(region: str | None, profile: str | None) -> Any:
    """Build a boto3 Session. Imported lazily so tests don't pay for it."""
    import boto3
    return boto3.Session(region_name=region, profile_name=profile)


def _default_target_factory(*, session: Any, region: str) -> Any:
    """Build a BmkbTarget. Imported lazily so tests don't pay for it."""
    from kb_connector.targets import get_target
    return get_target("bmkb", session=session, region=region)


SessionFactory = Callable[[str | None, str | None], Any]
TargetFactory = Callable[..., Any]


# --- Shared resolution helpers -----------------------------------------------


def _resolve_connector_name(
    config: ToolConfig,
    connector_name: str | None,
    *,
    allow_direct: bool = False,
    direct_ok: bool = False,
) -> str:
    """Resolve a connector name from the config (or auto-pick if there's only one).

    `allow_direct=True` lets the caller use a synthetic '_direct' name when no
    connectors are configured but they have provided overrides (kb/ds/region).
    """
    if connector_name:
        return connector_name
    names = config.connector_names()
    if len(names) == 1:
        return names[0]
    if not names:
        if allow_direct and direct_ok:
            return "_direct"
        raise ConfigError(
            "No connectors configured. Run 'kb-connector init' or pass a connector name."
        )
    raise ConfigError(
        f"Multiple connectors configured ({', '.join(names)}). Specify one."
    )


def _resolve_region_profile(
    config: ToolConfig,
    connector_name: str,
    *,
    region: str | None,
    profile: str | None,
) -> tuple[str, str | None, ConnectorConfig | None]:
    """Pick region+profile (CLI override > connector cfg > defaults)."""
    cfg: ConnectorConfig | None = None
    if connector_name != "_direct" and connector_name in config.connector_names():
        overrides: dict = {}
        if region:
            overrides["region"] = region
        if profile:
            overrides["profile"] = profile
        cfg = config.resolve_connector(connector_name, cli_overrides=overrides)
        region = region or cfg.region
        profile = profile or cfg.profile
    if not region:
        raise ConfigError("No region available. Pass region or set it in config.")
    return region, profile, cfg


# --- list --------------------------------------------------------------------


def list_connectors(
    *,
    config_path: str | None = None,
    state_path: str | None = None,
) -> ListResult:
    """Return a summary of every configured connector and its tracked state."""
    config = load_config(config_path)
    state_file = load_state(state_path)

    summaries: list[ConnectorSummary] = []
    for name in config.connector_names():
        try:
            cfg = config.resolve_connector(name)
        except ConfigError:
            # Bad entry — skip rather than fail the whole listing.
            continue
        cs = state_file.connectors.get(name)
        summaries.append(
            ConnectorSummary(
                name=name,
                type=cfg.type,
                region=cfg.region,
                has_state=cs is not None and any(
                    [cs.knowledge_base_id, cs.data_source_id, cs.client_app_id,
                     cs.secret_arn, cs.kb_role_arn]
                ),
                knowledge_base_id=cs.knowledge_base_id if cs else None,
                data_source_id=cs.data_source_id if cs else None,
                secret_arn=cs.secret_arn if cs else None,
                cert_not_after=cs.cert_not_after if cs else None,
                last_ingestion_job_id=cs.last_ingestion_job_id if cs else None,
            )
        )

    # Surface state-only entries (state without matching config) at the end.
    config_names = set(config.connector_names())
    for name, cs in state_file.connectors.items():
        if name in config_names:
            continue
        summaries.append(
            ConnectorSummary(
                name=name,
                type=cs.connector_type or "unknown",
                region=cs.region,
                has_state=True,
                knowledge_base_id=cs.knowledge_base_id,
                data_source_id=cs.data_source_id,
                secret_arn=cs.secret_arn,
                cert_not_after=cs.cert_not_after,
                last_ingestion_job_id=cs.last_ingestion_job_id,
            )
        )

    return ListResult(connectors=summaries, config_path=config.config_path)


# --- diagnose ----------------------------------------------------------------


def diagnose(
    *,
    connector_name: str | None = None,
    region: str | None = None,
    profile: str | None = None,
    kb_id: str | None = None,
    ds_id: str | None = None,
    lookback_minutes: int = 60,
    include_logs: bool = False,
    log_group_name: str | None = None,
    redact_logs: bool = True,
    config_path: str | None = None,
    state_path: str | None = None,
    session_factory: SessionFactory | None = None,
) -> DiagnoseResult:
    """Run the diagnostic checks and return a structured result.

    Reuses the existing core check functions (secret/cert/CloudTrail) — this
    function just wires them up with the right session and connector context.

    `include_logs` adds per-document ingestion log analysis. It is off by
    default because it needs vended log delivery configured on the knowledge
    base plus logs:FilterLogEvents, so for most callers it would just add a
    failed check. Document paths in the result are redacted unless
    `redact_logs=False`.
    """
    config = load_config(config_path)
    state_file = load_state(state_path)

    name = _resolve_connector_name(
        config, connector_name,
        allow_direct=True, direct_ok=bool(kb_id and ds_id),
    )
    region, profile, cfg = _resolve_region_profile(
        config, name, region=region, profile=profile,
    )
    cs = state_file.connectors.get(name) if name != "_direct" else None
    credential = (cfg.credential if cfg else None) or "cert"
    connector_type = cfg.type if cfg else ((cs.connector_type if cs else None) or "sharepoint")

    factory = session_factory or _default_session_factory
    session = factory(region, profile)

    checks: list[CheckResult] = []

    secret_arn = cs.secret_arn if cs else None
    if secret_arn:
        checks.append(check_secret_validity(
            session=session,
            secret_arn=secret_arn,
            connector_type=connector_type,
            credential=credential,
        ))

    cert_not_after = cs.cert_not_after if cs else None
    if cert_not_after or credential == "cert":
        checks.append(check_cert_expiry(cert_not_after=cert_not_after))

    role_arn = cs.kb_role_arn if cs else None
    checks.append(check_cloudtrail_permissions(
        session=session,
        region=region,
        role_arn=role_arn,
        secret_arn=secret_arn,
        lookback_minutes=lookback_minutes,
    ))

    if include_logs or log_group_name:
        resolved_kb = kb_id or (cs.knowledge_base_id if cs else None)
        group = log_group_name or (
            default_log_group_name(resolved_kb) if resolved_kb else None
        )
        if not group:
            raise StateError(
                "Log analysis needs a knowledge base id to derive the log group "
                "name, or an explicit log_group_name."
            )
        checks.append(check_ingestion_logs(
            session=session,
            log_group_name=group,
            lookback_minutes=lookback_minutes,
            redact=redact_logs,
        ))

    return build_diagnose_result(name, checks)


# --- monitor -----------------------------------------------------------------


def monitor(
    *,
    connector_name: str | None = None,
    region: str | None = None,
    profile: str | None = None,
    kb_id: str | None = None,
    ds_id: str | None = None,
    job_id: str | None = None,
    start: bool = False,
    poll_interval_seconds: int = 10,
    timeout_seconds: int = 1800,
    config_path: str | None = None,
    state_path: str | None = None,
    session_factory: SessionFactory | None = None,
    target_factory: TargetFactory | None = None,
) -> MonitorResult:
    """Poll an ingestion job (or start a new one).

    Defaults to *poll-only* (start=False) so an agent can't accidentally
    kick off ingestion. Pass start=True to begin a fresh job.
    """
    config = load_config(config_path)
    state_file = load_state(state_path)

    name = _resolve_connector_name(
        config, connector_name,
        allow_direct=True, direct_ok=bool(kb_id and ds_id),
    )
    region, profile, cfg = _resolve_region_profile(
        config, name, region=region, profile=profile,
    )
    cs = state_file.connectors.get(name) if name != "_direct" else None

    kb_id = kb_id or (cs.knowledge_base_id if cs else None)
    ds_id = ds_id or (cs.data_source_id if cs else None)
    if not kb_id or not ds_id:
        raise StateError(
            "Need kb_id and ds_id, or run setup first to populate state."
        )

    sess_factory = session_factory or _default_session_factory
    tgt_factory = target_factory or _default_target_factory
    session = sess_factory(region, profile)
    target = tgt_factory(session=session, region=region)

    if start:
        return start_and_poll(
            target, kb_id=kb_id, ds_id=ds_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
        )

    last_job_id = job_id or (cs.last_ingestion_job_id if cs else None)
    if not last_job_id:
        raise StateError(
            "Poll-only mode requires a known job_id (in state or passed in). "
            "Use start=True to begin a new job."
        )
    return poll_job(
        target, kb_id=kb_id, ds_id=ds_id, job_id=last_job_id,
        poll_interval_seconds=poll_interval_seconds,
        timeout_seconds=timeout_seconds,
    )


# --- validate ----------------------------------------------------------------


def validate(
    *,
    connector_name: str | None = None,
    region: str | None = None,
    profile: str | None = None,
    kb_id: str | None = None,
    query: str | None = None,
    authorized_user: str | None = None,
    unauthorized_user: str | None = None,
    skip_retrieve: bool = False,
    config_path: str | None = None,
    state_path: str | None = None,
    session_factory: SessionFactory | None = None,
    target_factory: TargetFactory | None = None,
) -> ValidateResult:
    """Verify a connector's credentials and retrieve path are healthy.

    For non-ACL connectors, runs a single retrieve check.

    For ACL-enabled connectors, runs up to three checks:
      * retrieve_no_user: with no userContext; expects zero results (proves
        the ACL filter is on).
      * retrieve_authorized: with the authorized_user's userContext; expects
        non-zero results (proves indexing + ACL allow path).
      * retrieve_denied: with the unauthorized_user's userContext; expects
        zero results (proves ACL deny path).

    Test query and users come from the connector's [validation] config
    block by default; CLI/programmatic args override.
    """
    config = load_config(config_path)
    state_file = load_state(state_path)

    name = _resolve_connector_name(config, connector_name)
    region, profile, cfg = _resolve_region_profile(
        config, name, region=region, profile=profile,
    )
    cs = state_file.connectors.get(name)

    # Pull validation config from the connector. The block is optional — set it
    # once and `validate` becomes self-contained.
    val_cfg = (cfg.get("validation") if cfg else None) or {}
    query = query or val_cfg.get("query", "test")
    authorized_user = authorized_user or val_cfg.get("authorized_user")
    unauthorized_user = unauthorized_user or val_cfg.get("unauthorized_user")
    acl_enabled = bool(cfg.acl) if cfg else False

    checks: list[CheckResult] = []
    notes: list[str] = []

    # Validate reaches AWS and the connector's own state; it does not sign in to
    # the identity provider. So the source side is reported as a note rather than
    # a check: a check that cannot fail counts toward the healthy total and makes
    # the result look better evidenced than it is. `diagnose` holds the check that
    # does reach Microsoft Graph and can fail — it confirms the directory still
    # carries the certificate this connector authenticates with.
    if cfg and cfg.type in ("sharepoint", "onedrive"):
        tenant_id = cfg.tenant_id or (cs.tenant_id if cs else None)
        client_id = cs.client_app_id if cs else None
        if tenant_id and client_id:
            notes.append(
                f"Source side not checked here: app {client_id} in tenant "
                f"{tenant_id}. Run `kb-connector diagnose` to verify the "
                f"certificate against the directory."
            )
        else:
            notes.append(
                "Source side not checked: tenant_id or client_app_id unavailable."
            )

    target_kb = kb_id or (cs.knowledge_base_id if cs else None)
    if skip_retrieve:
        notes.append("Retrieve check skipped (skip_retrieve=True).")
    elif not target_kb:
        notes.append("Skipped retrieve: no kb_id available.")
    else:
        sess_factory = session_factory or _default_session_factory
        tgt_factory = target_factory or _default_target_factory
        session = sess_factory(region, profile)
        target = tgt_factory(session=session, region=region)

        if acl_enabled:
            if authorized_user:
                checks.append(_check_retrieve_acl(
                    target, target_kb, query, authorized_user,
                    name="retrieve_authorized",
                    expectation="nonzero",
                ))
            else:
                notes.append(
                    "Skipped retrieve_authorized: no authorized_user set "
                    "(add one to [connectors.<name>.validation])."
                )
            if unauthorized_user:
                checks.append(_check_retrieve_acl(
                    target, target_kb, query, unauthorized_user,
                    name="retrieve_denied",
                    expectation="zero",
                ))
            else:
                notes.append(
                    "Skipped retrieve_denied: no unauthorized_user set."
                )
            checks.append(_check_retrieve_acl(
                target, target_kb, query, None,
                name="retrieve_no_user",
                expectation="zero",
            ))
        else:
            checks.append(_check_retrieve(target, target_kb, query))

    healthy = bool(checks) and all(c.passed for c in checks)
    return ValidateResult(
        connector=name,
        healthy=healthy,
        checks=checks,
        notes=notes,
    )


def _check_retrieve(target: Any, kb_id: str, query: str) -> CheckResult:
    """Run a basic retrieve and wrap the outcome in a CheckResult."""
    try:
        resp = target.retrieve(kb_id, query=query)
        results = resp.get("retrievalResults", [])
        return CheckResult(
            name="retrieve",
            passed=True,
            details=f"Retrieve returned {len(results)} result(s) for query {query!r}.",
            data={"result_count": len(results)},
            side="aws",
        )
    except Exception as exc:
        return CheckResult(
            name="retrieve",
            passed=False,
            details=f"Retrieve failed: {exc}",
            data={"error": str(exc)},
            side="aws",
        )


def _check_retrieve_acl(
    target: Any,
    kb_id: str,
    query: str,
    user_id: str | None,
    *,
    name: str,
    expectation: Literal["zero", "nonzero"],
) -> CheckResult:
    """Run an ACL-aware retrieve and assert results match expectation."""
    user_label = user_id or "(none)"
    try:
        resp = target.retrieve(kb_id, query=query, user_id=user_id)
        results = resp.get("retrievalResults", [])
        count = len(results)
    except Exception as exc:
        return CheckResult(
            name=name,
            passed=False,
            details=f"Retrieve failed (user={user_label}): {exc}",
            data={"error": str(exc), "user_id": user_id},
            side="aws",
        )

    passed = (count == 0) if expectation == "zero" else (count > 0)
    expectation_label = "zero results" if expectation == "zero" else "results"
    return CheckResult(
        name=name,
        passed=passed,
        details=(
            f"Retrieve user={user_label} returned {count} result(s); "
            f"expected {expectation_label}."
        ),
        data={"result_count": count, "user_id": user_id, "expectation": expectation},
        side="aws",
    )


# --- handoff -----------------------------------------------------------------


def handoff(
    *,
    connector_name: str,
    direction: Literal["aws", "source"] = "aws",
    config_path: str | None = None,
    state_path: str | None = None,
) -> HandoffResult:
    """Build a handoff document for the given connector.

    `direction="aws"` produces source-to-aws (source admin -> AWS admin).
    `direction="source"` produces aws-to-source.
    """
    config = load_config(config_path)
    state_file = load_state(state_path)

    cs: ConnectorState | None = state_file.connectors.get(connector_name)
    cfg: ConnectorConfig | None = None
    if connector_name in config.connector_names():
        cfg = config.resolve_connector(connector_name)

    if direction == "aws":
        document = build_source_to_aws(connector_name, cs, cfg)
        outgoing: Literal["source-to-aws", "aws-to-source"] = "source-to-aws"
    elif direction == "source":
        document = build_aws_to_source(connector_name, cs, cfg)
        outgoing = "aws-to-source"
    else:
        raise ConfigError(
            f"Unknown direction {direction!r}; expected 'aws' or 'source'."
        )

    return HandoffResult(
        connector=connector_name,
        direction=outgoing,
        document=document,
    )


# Re-export StateFile so consumers don't need to import from core.state
__all__ = [
    "ConnectorSummary",
    "ListResult",
    "ValidateResult",
    "HandoffResult",
    "DiagnoseResult",
    "MonitorResult",
    "CheckResult",
    "StateFile",
    "list_connectors",
    "diagnose",
    "monitor",
    "validate",
    "handoff",
]
