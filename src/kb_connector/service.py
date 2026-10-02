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

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from kb_connector.context import (
    SessionFactory as _SessionFactory,
    TargetFactory as _TargetFactory,
    resolve_context,
)
from kb_connector.core.config import load_config
from kb_connector.core.diagnostics import (
    CheckResult,
    DiagnoseResult,
    build_diagnose_result,
    check_cert_expiry,
    check_certificate_installed,
    check_cloudtrail_permissions,
    check_ingestion_logs,
    check_secret_validity,
    default_log_group_name,
)
from kb_connector.core.errors import ConfigError, StateError
from kb_connector.core.handoff import build_aws_to_source, build_source_to_aws
from kb_connector.core.monitor import (
    IngestionStats,
    MonitorResult,
    poll_job,
    start_and_poll,
)
from kb_connector.core.state import StateFile, load_state


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


# --- Factory types -----------------------------------------------------------

# Resolution lives in kb_connector.context. The factory types are re-exported
# here because callers of this module annotate against them.
SessionFactory = _SessionFactory
TargetFactory = _TargetFactory


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
    check_directory: bool = False,
    graph_auth_method: str = "az",
    device_client_id: str | None = None,
    config_path: str | None = None,
    state_path: str | None = None,
    session_factory: SessionFactory | None = None,
    thumbprint_reader: Callable[[Any], list[str] | None] | None = None,
    on_check: Callable[[CheckResult], None] | None = None,
) -> DiagnoseResult:
    """Run the diagnostic checks and return a structured result.

    Reuses the existing core check functions (secret/cert/CloudTrail) — this
    function just wires them up with the right session and connector context.

    `include_logs` adds per-document ingestion log analysis. It is off by
    default because it needs vended log delivery configured on the knowledge
    base plus logs:FilterLogEvents, so for most callers it would just add a
    failed check. Document paths in the result are redacted unless
    `redact_logs=False`.

    `check_directory` adds a Microsoft Graph lookup confirming the app still
    carries the certificate this connector authenticates with. Without Graph
    access that check reports as unverified. `on_check` receives each result as
    it completes.
    """
    ctx = resolve_context(
        connector_name, region=region, profile=profile,
        config_path=config_path, state_path=state_path,
        direct_ok=bool(kb_id and ds_id), session_factory=session_factory,
    )
    region = ctx.require_region()
    cfg, cs, name = ctx.cfg, ctx.cs, ctx.name
    credential = (cfg.credential if cfg else None) or "cert"
    connector_type = cfg.type if cfg else ((cs.connector_type if cs else None) or "sharepoint")

    session = ctx.session()

    checks: list[CheckResult] = []

    def _add(check: CheckResult) -> None:
        checks.append(check)
        if on_check is not None:
            on_check(check)

    secret_arn = cs.secret_arn if cs else None
    if secret_arn:
        _add(check_secret_validity(
            session=session,
            secret_arn=secret_arn,
            connector_type=connector_type,
            credential=credential,
        ))

    cert_not_after = cs.cert_not_after if cs else None
    if cert_not_after or credential == "cert":
        _add(check_cert_expiry(cert_not_after=cert_not_after))

    # Expiry comes from state, so it cannot tell whether the directory still
    # carries the certificate. This asks the directory.
    if check_directory and credential == "cert" and cs and cs.client_app_object_id:
        reader = thumbprint_reader or (
            lambda state: _read_installed_thumbprints(
                state, method=graph_auth_method, device_client_id=device_client_id,
            )
        )
        _add(check_certificate_installed(
            recorded_thumbprint=cs.cert_thumbprint_b64url,
            installed_thumbprints=reader(cs),
        ))

    role_arn = cs.kb_role_arn if cs else None
    _add(check_cloudtrail_permissions(
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
        _add(check_ingestion_logs(
            session=session,
            log_group_name=group,
            lookback_minutes=lookback_minutes,
            redact=redact_logs,
        ))

    return build_diagnose_result(name, checks)


def _read_installed_thumbprints(
    cs: Any, *, method: str, device_client_id: str | None
) -> list[str] | None:
    """Read the app's certificate thumbprints, or None if Graph is unreachable.

    None rather than an exception: an operator diagnosing the AWS side often has
    no Graph access, and `check_certificate_installed` reports None as
    unverified instead of failing the diagnosis.
    """
    if not cs.tenant_id or not cs.client_app_object_id:
        return None
    try:
        from kb_connector.providers.microsoft.apps import list_certificate_thumbprints
        from kb_connector.providers.microsoft.client import GraphClient

        graph = GraphClient.from_auth(
            method=method, tenant_id=cs.tenant_id, device_client_id=device_client_id,
        )
        return list_certificate_thumbprints(graph, cs.client_app_object_id)
    except Exception:  # noqa: BLE001 - no Graph access is an expected outcome
        return None


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
    on_job_started: Callable[[str], None] | None = None,
    on_poll: Callable[[IngestionStats], None] | None = None,
) -> MonitorResult:
    """Poll an ingestion job (or start a new one).

    Defaults to *poll-only* (start=False) so an agent can't accidentally
    kick off ingestion. Pass start=True to begin a fresh job.

    The job id is written to state as soon as a started job exists, and again
    when polling ends, so `monitor --no-start` can resume it. A DIRECT run (ids
    given, no connector) writes no state. `on_job_started` and `on_poll` are
    progress hooks for the caller.
    """
    ctx = resolve_context(
        connector_name, region=region, profile=profile,
        config_path=config_path, state_path=state_path,
        direct_ok=bool(kb_id and ds_id),
        session_factory=session_factory, target_factory=target_factory,
    )
    ctx.require_region()
    cs = ctx.cs

    kb_id = kb_id or (cs.knowledge_base_id if cs else None)
    ds_id = ds_id or (cs.data_source_id if cs else None)
    if not kb_id or not ds_id:
        raise StateError(
            "Need kb_id and ds_id, or run setup first to populate state."
        )

    def _record_job(started_id: str) -> None:
        if not ctx.is_direct:
            ctx.ensure_state().last_ingestion_job_id = started_id
            ctx.save()

    if start:
        def _started(started_id: str) -> None:
            _record_job(started_id)
            if on_job_started is not None:
                on_job_started(started_id)

        result = start_and_poll(
            ctx.target(), kb_id=kb_id, ds_id=ds_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
            on_job_started=_started,
            on_poll=on_poll,
        )
    else:
        last_job_id = job_id or (cs.last_ingestion_job_id if cs else None)
        if not last_job_id:
            raise StateError(
                "No ingestion job to poll: none is recorded in state and none was "
                "given. Pass a job id, or start a new job."
            )
        result = poll_job(
            ctx.target(), kb_id=kb_id, ds_id=ds_id, job_id=last_job_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds,
            on_poll=on_poll,
        )
    _record_job(result.job_id)
    return result


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
    ctx = resolve_context(
        connector_name, region=region, profile=profile,
        config_path=config_path, state_path=state_path,
        session_factory=session_factory, target_factory=target_factory,
    )
    cfg, cs, name = ctx.cfg, ctx.cs, ctx.name

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
        ctx.require_region()
        target = ctx.target()

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
    ctx = resolve_context(
        connector_name, config_path=config_path, state_path=state_path,
    )
    cs, cfg = ctx.cs, ctx.cfg

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


# --- teardown ----------------------------------------------------------------

# Resource kinds deleted through an AWS client. "app" goes through Graph.
_AWS_KINDS = frozenset({"ds", "kb", "secret", "role", "cert"})
# Deleted first. If either fails, the credentials they depend on are kept.
_CONTROL_PLANE_KINDS = ("ds", "kb")
TEARDOWN_KINDS = ("ds", "kb", "secret", "role", "cert", "app")


@dataclass
class TeardownItem:
    """One tracked resource teardown would act on."""

    kind: str          # one of TEARDOWN_KINDS
    identifier: str
    description: str
    adopted: bool      # recorded as external rather than created by this tool


@dataclass
class TeardownPlan:
    """What teardown would delete and keep. Computing it makes no AWS call."""

    connector: str
    connector_type: str | None
    region: str | None
    delete: list[TeardownItem] = field(default_factory=list)
    keep: list[TeardownItem] = field(default_factory=list)
    scoped: bool = False   # limited to one kind with `only`
    ctx: Any = field(default=None, repr=False)

    @property
    def tracked(self) -> bool:
        return bool(self.delete or self.keep)


@dataclass
class TeardownEvent:
    """Progress from execute_teardown, in the order things happen."""

    kind: Literal[
        "job_check_failed", "job_stopping", "job_stopped", "job_still_stopping",
        "job_stop_failed", "deleted", "failed", "skipped",
    ]
    item: TeardownItem | None = None
    detail: str | None = None


@dataclass
class TeardownResult:
    """Outcome of execute_teardown."""

    connector: str
    deleted: list[TeardownItem] = field(default_factory=list)
    failed: list[TeardownItem] = field(default_factory=list)
    skipped: list[TeardownItem] = field(default_factory=list)
    # Set when an ingestion job was running and `force` was not passed. Nothing
    # was deleted.
    blocked_by_job: str | None = None
    state_cleared: bool = False
    state_path: str | None = None

    @property
    def ok(self) -> bool:
        return not (self.failed or self.skipped or self.blocked_by_job)


def plan_teardown(
    *,
    connector_name: str | None = None,
    only: str | None = None,
    include_adopted: bool = False,
    region: str | None = None,
    profile: str | None = None,
    config_path: str | None = None,
    state_path: str | None = None,
    session_factory: SessionFactory | None = None,
    target_factory: TargetFactory | None = None,
) -> TeardownPlan:
    """List what teardown would delete and keep, from state.

    Resources recorded as adopted are kept unless `include_adopted`. A config
    entry that fails to resolve does not block the plan, since state is what
    teardown acts on. Raises ConfigError if anything AWS-side would be deleted
    and no region is known: a guessed region sends every delete to a region
    where the resources do not exist.
    """
    if only is not None and only not in TEARDOWN_KINDS:
        raise ConfigError(
            f"Unknown resource type {only!r}. Expected one of: "
            f"{', '.join(TEARDOWN_KINDS)}."
        )
    ctx = resolve_context(
        connector_name, region=region, profile=profile,
        config_path=config_path, state_path=state_path, strict_config=False,
        session_factory=session_factory, target_factory=target_factory,
    )
    cs = ctx.cs
    plan = TeardownPlan(
        connector=ctx.name,
        connector_type=cs.connector_type if cs else None,
        region=ctx.region,
        scoped=only is not None,
        ctx=ctx,
    )
    if cs is None:
        return plan

    candidates: list[tuple[str, str | None, str]] = [
        ("ds", cs.data_source_id, f"Data source {cs.data_source_id}"),
        ("kb", cs.knowledge_base_id, f"Knowledge base {cs.knowledge_base_id}"),
        ("secret", cs.secret_arn, f"Secret {cs.secret_arn}"),
        ("role", cs.kb_role_arn, f"IAM role {cs.kb_role_arn}"),
        (
            "cert",
            f"s3://{cs.cert_s3_bucket}/{cs.cert_s3_key}"
            if cs.cert_s3_bucket and cs.cert_s3_key else None,
            f"Certificate s3://{cs.cert_s3_bucket}/{cs.cert_s3_key}",
        ),
        ("app", cs.client_app_id, f"Entra app {cs.client_app_id}"),
    ]
    for kind, identifier, description in candidates:
        if not identifier or (only and kind != only):
            continue
        adopted = not cs.is_tool_owned(kind)
        item = TeardownItem(kind, identifier, description, adopted)
        (plan.keep if adopted and not include_adopted else plan.delete).append(item)

    if any(item.kind in _AWS_KINDS for item in plan.delete):
        ctx.require_region(
            f"No region known for {ctx.name!r}: state does not record one and "
            f"config does not set one. Pass the region the resources were "
            f"created in."
        )
    return plan


def execute_teardown(
    plan: TeardownPlan,
    *,
    force: bool = False,
    auth_method: str = "az",
    device_client_id: str | None = None,
    on_event: Callable[[TeardownEvent], None] | None = None,
) -> TeardownResult:
    """Delete what the plan lists, then update or clear the state entry.

    Refuses while an ingestion job is running on the data source unless
    `force`, which stops the job first. The data source and knowledge base are
    deleted before the credentials; if either fails, the credentials are kept
    so a later run can retry. The state entry is removed only after an unscoped
    teardown that deleted everything and kept nothing.
    """
    from kb_connector.core import teardown as td

    ctx = plan.ctx
    cs = ctx.cs
    result = TeardownResult(connector=plan.connector, state_path=ctx.state_path)

    def _emit(event: TeardownEvent) -> None:
        if on_event is not None:
            on_event(event)

    if not plan.delete:
        return result

    if cs.knowledge_base_id and cs.data_source_id:
        target = ctx.target()
        try:
            active = td.find_active_ingestion_job(
                target, cs.knowledge_base_id, cs.data_source_id
            )
        except Exception as exc:  # noqa: BLE001 - a failed check must not block cleanup
            active = None
            _emit(TeardownEvent("job_check_failed", detail=str(exc)))
        if active and not force:
            result.blocked_by_job = active
            return result
        if active:
            _emit(TeardownEvent("job_stopping", detail=active))
            try:
                status = td.stop_and_wait(
                    target, cs.knowledge_base_id, cs.data_source_id, active
                )
            except Exception as exc:  # noqa: BLE001 - deletes proceed regardless
                _emit(TeardownEvent("job_stop_failed", detail=str(exc)))
            else:
                _emit(TeardownEvent(
                    "job_stopped" if status else "job_still_stopping", detail=status,
                ))

    ordered = sorted(
        plan.delete, key=lambda i: 0 if i.kind in _CONTROL_PLANE_KINDS else 1
    )
    control_plane_failed = False
    for item in ordered:
        if control_plane_failed and item.kind not in _CONTROL_PLANE_KINDS:
            result.skipped.append(item)
            _emit(TeardownEvent("skipped", item))
            continue
        try:
            _delete_item(ctx, cs, item, auth_method, device_client_id)
        except Exception as exc:  # noqa: BLE001 - reported per resource
            result.failed.append(item)
            _emit(TeardownEvent("failed", item, str(exc)))
            if item.kind in _CONTROL_PLANE_KINDS:
                control_plane_failed = True
            continue
        result.deleted.append(item)
        _emit(TeardownEvent("deleted", item))

    nothing_left = not any([
        cs.knowledge_base_id, cs.data_source_id, cs.secret_arn,
        cs.kb_role_arn, cs.client_app_id, cs.cert_s3_bucket,
    ])
    if not plan.scoped and nothing_left and result.ok and not plan.keep:
        result.state_path = ctx.forget()
        result.state_cleared = True
    else:
        result.state_path = ctx.save()
    return result


def _delete_item(
    ctx: Any, cs: Any, item: TeardownItem, auth_method: str,
    device_client_id: str | None,
) -> None:
    """Delete one resource and clear its identifiers from state."""
    from kb_connector.core import teardown as td

    if item.kind == "ds":
        if not cs.knowledge_base_id:
            raise StateError(
                "The data source cannot be deleted without its knowledge base "
                "id, and state does not record one."
            )
        ctx.target().delete_data_source(cs.knowledge_base_id, item.identifier)
        cs.data_source_id = None
    elif item.kind == "kb":
        ctx.target().delete_knowledge_base(item.identifier)
        cs.knowledge_base_id = None
    elif item.kind == "secret":
        td.delete_secret(ctx.session(), item.identifier)
        cs.secret_arn = None
    elif item.kind == "role":
        td.delete_role(ctx.session(), item.identifier)
        cs.kb_role_arn = None
    elif item.kind == "cert":
        td.delete_cert(ctx.session(), cs.cert_s3_bucket, cs.cert_s3_key)
        cs.cert_s3_bucket = None
        cs.cert_s3_key = None
    elif item.kind == "app":
        td.delete_entra_app(
            tenant_id=cs.tenant_id, object_id=cs.client_app_object_id,
            auth_method=auth_method, device_client_id=device_client_id,
        )
        cs.client_app_id = None
        cs.client_app_object_id = None


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
    "TeardownItem",
    "TeardownPlan",
    "TeardownEvent",
    "TeardownResult",
    "plan_teardown",
    "execute_teardown",
]
