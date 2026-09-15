"""Probe driver — low-level connector-parameter inspection.

Purpose: take a raw connectorParameters JSON body and drive it end-to-end
against the configured bedrock-agent endpoint (including a custom preview/beta
endpoint). The body is passed through unchanged, so the same driver works for
every managed connector type (WEB, SHAREPOINT, ONEDRIVE, CONFLUENCE, ...)
without per-type code.

This is a maintainer/advanced-debugging tool — the high-level commands (setup,
diagnose) are what most users want. A run produces a directory of request +
response bodies, including the post-create GetDataSource response, so you can
compare what you submitted against what the service kept, defaulted, or dropped.

Steps:
  1. Optionally write a secret and substitute its ARN into params.
  2. Resolve the KB (reuse or create).
  3. CreateDataSource with the raw connectorParameters.
  4. GetDataSource — the round-trip shows which fields the service persisted.
  5. Optionally StartIngestionJob + poll.
  6. Optionally Retrieve.

Service rejections are not fatal — a 400 is captured as a useful observation
about what the API accepts. Everything is captured to disk for inspection.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from kb_connector.core.errors import AwsError, ConnectorError
from kb_connector.core.fileio import atomic_write_json, open_owner_only
from kb_connector.targets.bmkb import BmkbTarget

# A placeholder token substituted at runtime, not a real ARN. Keep the
# suppression comment bare: bandit reads anything after the test id as further
# test ids, so a trailing justification silently stops it applying.
SECRET_ARN_PLACEHOLDER = "__SECRET_ARN__"  # nosec B105
_TERMINAL = {"COMPLETE", "COMPLETED", "FAILED", "STOPPED"}

# Ownership tag value for probe-created resources. Probe runs are maintainer
# scratch work, so they get their own owner name rather than borrowing a real
# connector's — that keeps a probe run from ever adopting or clobbering a
# resource belonging to a live connector.
_PROBE_OWNER = "_probe"


@dataclass
class ProbeArgs:
    """Inputs for a probe run."""

    connector_params_file: str
    secret_body_file: str | None = None
    secret_name: str | None = None
    knowledge_base_id: str | None = None
    create_kb: bool = False
    create_kb_role: bool = False
    kb_role_arn: str | None = None
    kb_role_name: str = "kb-connector-probe-role"
    kb_name: str = "kb-connector-probe"
    data_source_name: str = "probe-ds"
    ingest: bool = False
    poll_interval_seconds: int = 10
    timeout_seconds: int = 1800
    retrieve_query: str | None = None
    out_dir: str | None = None
    cert_s3_bucket: str | None = None
    cert_s3_key: str | None = None
    cert_s3_key_prefix: str | None = None
    adopt_existing: bool = False


@dataclass
class _Event:
    step: str
    ok: bool
    request_file: str | None = None
    response_file: str | None = None
    detail: str = ""
    timestamp: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )


@dataclass
class ProbeResult:
    """Structured result of a probe run."""

    connector_type: str
    out_dir: str
    knowledge_base_id: str | None
    data_source_id: str | None
    ok: bool
    events: list[dict]


def run_probe(
    args: ProbeArgs,
    *,
    session: Any,
    region: str,
    buildtime_endpoint: str | None = None,
    runtime_endpoint: str | None = None,
) -> ProbeResult:
    """Execute one probe run; returns a structured result. Captures to disk."""
    connector_params = _read_json_file(args.connector_params_file)
    if not isinstance(connector_params, dict):
        raise ConnectorError(
            f"Connector params file {args.connector_params_file!r} must contain "
            "a JSON object (the value of connectorParameters)."
        )
    connector_type = str(connector_params.get("type") or "unknown").lower()

    out_dir = args.out_dir or _default_out_dir(connector_type)
    # 0700: the directory listing alone reveals connector type and run times,
    # and the files inside carry configuration and document excerpts.
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    events: list[_Event] = []

    _write_json(out_dir, "00-input-connector-params.json", connector_params)

    target = BmkbTarget(
        session=session,
        region=region,
        buildtime_endpoint=buildtime_endpoint,
        runtime_endpoint=runtime_endpoint,
    )

    # 1. Optional secret.
    secret_arn: str | None = None
    if args.secret_body_file:
        if not args.secret_name:
            raise ConnectorError("--secret-body requires --secret-name.")
        from kb_connector.core import provisioning
        secret_body = _read_json_file(args.secret_body_file)
        secret_res = provisioning.put_secret(
            session=session,
            name=args.secret_name,
            body=secret_body,
            connector_name=_PROBE_OWNER,
            adopt_existing=args.adopt_existing,
        )
        secret_arn = secret_res.arn
        events.append(_Event("put-secret", True, detail=f"arn={secret_arn}"))

    if SECRET_ARN_PLACEHOLDER in json.dumps(connector_params):
        if not secret_arn:
            raise ConnectorError(
                f"Params reference {SECRET_ARN_PLACEHOLDER!r} but no secret supplied."
            )
        connector_params = _substitute(connector_params, SECRET_ARN_PLACEHOLDER, secret_arn)
    _write_json(out_dir, "01-connector-params-resolved.json", connector_params)

    # 2. Resolve KB.
    kb_id = _resolve_kb(args, target, session, region, secret_arn, out_dir, events)

    # 3. CreateDataSource (raw connectorParameters).
    ds_payload = {
        "name": args.data_source_name,
        "dataSourceConfiguration": {
            "type": "MANAGED_KNOWLEDGE_BASE_CONNECTOR",
            "managedKnowledgeBaseConnectorConfiguration": {
                "connectorParameters": connector_params
            },
        },
    }
    _write_json(out_dir, "02-create-data-source.req.json", ds_payload)
    create_ok, create_resp = _attempt(
        lambda: target.create_data_source_raw(kb_id, ds_payload)
    )
    _write_json(out_dir, "02-create-data-source.resp.json", create_resp)
    events.append(_Event(
        "create-data-source", create_ok,
        request_file="02-create-data-source.req.json",
        response_file="02-create-data-source.resp.json",
        detail=_short(create_resp),
    ))
    if not create_ok:
        _finalize(out_dir, events, connector_type, kb_id, None)
        return _build_result(connector_type, out_dir, kb_id, None, events)

    ds_id = _extract_id(create_resp, "dataSource", "dataSourceId")

    # 4. Round-trip GetDataSource — shows what the service persisted.
    get_ok, get_resp = _attempt(lambda: target.get_data_source(kb_id, ds_id))
    _write_json(out_dir, "03-get-data-source.resp.json", get_resp)
    events.append(_Event(
        "get-data-source", get_ok,
        response_file="03-get-data-source.resp.json",
        detail=_short(get_resp),
    ))
    if get_ok:
        _diff_round_trip(connector_params, get_resp, out_dir, events)

    # 5. Optional ingestion.
    if args.ingest:
        try:
            target.wait_until_ds_available(kb_id, ds_id)
            events.append(_Event("wait-ds-available", True))
        except (AwsError, TimeoutError) as exc:
            events.append(_Event("wait-ds-available", False, detail=str(exc)))

        start_ok, start_resp = _attempt(lambda: target.start_ingestion_job(kb_id, ds_id))
        _write_json(out_dir, "04-start-ingestion.resp.json", start_resp)
        events.append(_Event(
            "start-ingestion", start_ok,
            response_file="04-start-ingestion.resp.json",
            detail=_short(start_resp),
        ))
        if start_ok:
            job_id = _extract_id(start_resp, "ingestionJob", "ingestionJobId")
            final_job = _poll_ingestion(
                target, kb_id, ds_id, job_id,
                args.poll_interval_seconds, args.timeout_seconds,
            )
            _write_json(out_dir, "05-final-ingestion.resp.json", final_job)
            events.append(_Event(
                "ingestion-final", True,
                response_file="05-final-ingestion.resp.json",
                detail=f"status={(final_job.get('status') or 'UNKNOWN').upper()}",
            ))

    # 6. Optional retrieve.
    if args.retrieve_query:
        retr_ok, retr_resp = _attempt(
            lambda: target.retrieve(kb_id, query=args.retrieve_query)
        )
        _write_json(out_dir, "06-retrieve.resp.json", retr_resp)
        count = len(((retr_resp or {}).get("retrievalResults")) or []) if retr_ok else 0
        events.append(_Event(
            "retrieve", retr_ok,
            response_file="06-retrieve.resp.json",
            detail=f"results={count}" if retr_ok else _short(retr_resp),
        ))

    _finalize(out_dir, events, connector_type, kb_id, ds_id)
    return _build_result(connector_type, out_dir, kb_id, ds_id, events)


# --- helpers -----------------------------------------------------------------


def _resolve_kb(args, target, session, region, secret_arn, out_dir, events) -> str:
    """Reuse or create the KB the data source hangs off."""
    from kb_connector.core import provisioning

    kb_id = args.knowledge_base_id
    reusing = bool(kb_id) and not args.create_kb

    if reusing:
        try:
            kb_resp = target.get_knowledge_base(kb_id)
        except AwsError as exc:
            raise ConnectorError(f"Could not GetKnowledgeBase {kb_id}: {exc}") from exc
        kb_body = kb_resp.get("knowledgeBase", kb_resp) or {}
        role_arn = kb_body.get("roleArn")
        events.append(_Event("get-knowledge-base", True, detail=f"role={role_arn}"))
        if secret_arn and role_arn:
            role_name = role_arn.split(":role/")[-1].rsplit("/", 1)[-1]
            try:
                provisioning.extend_kb_role_for_secret(
                    session=session, role_name=role_name, secret_arn=secret_arn,
                    cert_bucket=args.cert_s3_bucket, cert_key=args.cert_s3_key,
                    cert_key_prefix=args.cert_s3_key_prefix,
                    region=region,
                )
                time.sleep(10)  # nosemgrep: arbitrary-sleep -- polling backoff
                events.append(_Event("extend-kb-role", True))
            except AwsError as exc:
                events.append(_Event("extend-kb-role", False, detail=str(exc)))
        return kb_id

    # Create path.
    if not args.create_kb:
        raise ConnectorError(
            "Need a KB. Pass knowledge_base_id (reuse) or create_kb (provision)."
        )
    kb_role_arn = args.kb_role_arn
    if args.create_kb_role:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        role_res = provisioning.ensure_kb_role(
            session=session, role_name=args.kb_role_name, account_id=account_id,
            region=region, secret_arn=secret_arn,
            cert_bucket=args.cert_s3_bucket, cert_key=args.cert_s3_key,
            cert_key_prefix=args.cert_s3_key_prefix,
            connector_name=_PROBE_OWNER,
            adopt_existing=args.adopt_existing,
        )
        kb_role_arn = role_res.arn
        events.append(
            _Event("ensure-kb-role", True, detail=f"{kb_role_arn} ({role_res.ownership.value})")
        )
        time.sleep(10)  # nosemgrep: arbitrary-sleep -- polling backoff
    if not kb_role_arn:
        raise ConnectorError("create_kb requires kb_role_arn or create_kb_role.")

    created = target.create_knowledge_base(name=args.kb_name, role_arn=kb_role_arn)
    kb_id = _extract_id(created, "knowledgeBase", "knowledgeBaseId")
    target.wait_until_kb_active(kb_id)
    events.append(_Event("create-knowledge-base", True, detail=f"kb={kb_id}"))
    return kb_id


def _poll_ingestion(target, kb_id, ds_id, job_id, poll_interval, timeout) -> dict:
    """Poll until terminal or timeout. Returns the last job dict."""
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        ok, resp = _attempt(lambda: target.get_ingestion_job(kb_id, ds_id, job_id))
        if not ok:
            return resp if isinstance(resp, dict) else {"error": _short(resp)}
        job = resp.get("ingestionJob", resp) or {}
        status = (job.get("status") or "").upper()
        last = job
        if status in _TERMINAL:
            return job
        time.sleep(poll_interval)  # nosemgrep: arbitrary-sleep -- polling backoff
    return last


def _attempt(fn: Callable) -> tuple[bool, Any]:
    """Call fn, capturing AwsError as a (False, {error}) tuple for the run."""
    try:
        resp = fn()
    except AwsError as exc:
        return False, {"error": str(exc)}
    if resp is None:
        return True, {}
    return True, resp


def _read_json_file(path: str) -> Any:
    if not os.path.exists(path):
        raise ConnectorError(f"File not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"Could not parse JSON from {path}: {exc}") from exc


def _write_json(out_dir: str, name: str, body: Any) -> str:
    """Write one capture artifact, owner-only.

    Probe artifacts are the most sensitive output the tool produces: resolved
    connector parameters, secret ARNs, the full persisted data-source config,
    and — when --retrieve-query is used — excerpts of the indexed documents
    themselves.
    """
    path = os.path.join(out_dir, name)
    return atomic_write_json(path, body, indent=2, sort_keys=True)


def _substitute(value: Any, needle: str, replacement: str) -> Any:
    """Recursively replace exact-equal leaf strings."""
    if isinstance(value, dict):
        return {k: _substitute(v, needle, replacement) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, needle, replacement) for v in value]
    if isinstance(value, str) and value == needle:
        return replacement
    return value


def _diff_round_trip(sent: dict, get_resp: dict, out_dir: str, events: list[_Event]) -> None:
    """Compare what we PUT vs what GetDataSource returns; capture missing keys."""
    ds = (get_resp or {}).get("dataSource") or get_resp or {}
    wrapper = (
        (ds.get("dataSourceConfiguration") or {})
        .get("managedKnowledgeBaseConnectorConfiguration") or {}
    )
    raw_params = wrapper.get("connectorParameters")
    if isinstance(raw_params, str):
        try:
            cfg = json.loads(raw_params)
        except (TypeError, ValueError) as exc:
            cfg = {"_parse_error": str(exc)}
    elif isinstance(raw_params, dict):
        cfg = raw_params
    else:
        cfg = {}

    sent_paths = _flatten_paths(sent)
    seen_paths = _flatten_paths(cfg) if isinstance(cfg, dict) else {}

    dropped = sorted(p for p in sent_paths if p not in seen_paths)
    injected = sorted(p for p in seen_paths if p not in sent_paths)
    rewrites = sorted(
        p for p in sent_paths if p in seen_paths and sent_paths[p] != seen_paths[p]
    )

    diff = {
        "dropped_by_service": dropped,
        "injected_by_service": injected,
        "value_rewrites": [
            {"path": p, "sent": sent_paths[p], "round_trip": seen_paths[p]}
            for p in rewrites
        ],
        "data_source_status": ds.get("status"),
    }
    _write_json(out_dir, "03b-round-trip-diff.json", diff)
    events.append(_Event(
        "round-trip-diff", True,
        response_file="03b-round-trip-diff.json",
        detail=f"dropped={len(dropped)}, injected={len(injected)}, rewritten={len(rewrites)}",
    ))


def _flatten_paths(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dict to dotted.path -> leaf value. Lists are leaves."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            sub = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                nested = _flatten_paths(value, sub)
                if not nested:
                    out[sub] = value
                else:
                    out.update(nested)
            else:
                out[sub] = value
    else:
        out[prefix] = obj
    return out


def _short(body: Any, limit: int = 240) -> str:
    if not body:
        return ""
    try:
        text = json.dumps(body, default=str)
    except (TypeError, ValueError):
        text = str(body)
    text = text.replace("\n", " ")
    return text[:limit] + "..." if len(text) > limit else text


def _extract_id(resp: dict, container: str, id_field: str) -> str:
    if not resp:
        raise ConnectorError(f"Empty response; expected {id_field}.")
    if id_field in resp:
        return resp[id_field]
    inner = resp.get(container) or {}
    if id_field in inner:
        return inner[id_field]
    raise ConnectorError(f"Could not find {id_field} in response: {resp}")


def _default_out_dir(connector_type: str) -> str:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(os.getcwd(), "kb-connector-probe-runs", connector_type, ts)


def _finalize(out_dir, events, connector_type, kb_id, ds_id) -> None:
    """Write summary.json + events.jsonl describing the whole run."""
    summary = {
        "connector_type": connector_type,
        "knowledge_base_id": kb_id,
        "data_source_id": ds_id,
        "ok": all(e.ok for e in events),
        "steps": [_event_dict(e) for e in events],
    }
    _write_json(out_dir, "summary.json", summary)
    with open_owner_only(os.path.join(out_dir, "events.jsonl")) as f:
        for e in events:
            f.write(json.dumps(_event_dict(e), default=str) + "\n")


def _event_dict(e: _Event) -> dict:
    return {
        "step": e.step,
        "ok": e.ok,
        "timestamp": e.timestamp,
        "request_file": e.request_file,
        "response_file": e.response_file,
        "detail": e.detail,
    }


def _build_result(connector_type, out_dir, kb_id, ds_id, events) -> ProbeResult:
    return ProbeResult(
        connector_type=connector_type,
        out_dir=out_dir,
        knowledge_base_id=kb_id,
        data_source_id=ds_id,
        ok=all(e.ok for e in events),
        events=[_event_dict(e) for e in events],
    )
