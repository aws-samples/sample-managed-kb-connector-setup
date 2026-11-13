"""validate and diagnose checks for a connector with target = "quick".

Each check returns a `core.diagnostics.CheckResult`. The decisions are in pure
helpers (`key_policy_allows_sign`, `grants_allow_sign`, `sign_denials`,
`kb_documents`, `check_kb_latest_sync`) so they can be tested without a
client.

Details and `data` never carry key-policy text, grant contents or anything
else read from a credential- or policy-named call. They use fixed sentences
and say which route matched.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any

from kb_connector.core.diagnostics import CheckResult, check_certificate_installed
from kb_connector.core.errors import ConnectorError
from kb_connector.core.kms_signing import key_shape_problems
from kb_connector.core.state import ConnectorState

SYNC_REPORT_DOCS = (
    "https://docs.aws.amazon.com/quick/latest/userguide/sync-reports-observability.html"
)

QUERY_GAP_NOTE = (
    "Not checked: a test query and the ACL checks (authorized, denied, no user). "
    "Amazon Quick has no API to query a knowledge base."
)

_SELECT_KEYS_STEP = (
    "A Quick administrator (Admin Pro) adds the key in the Quick console: "
    "Manage account -> Permissions -> AWS resources -> AWS Key Management "
    "Service -> Select keys, then Save."
)

_SYNC_IN_PROGRESS = ("QUEUED", "RUNNING")
_SYNC_FAILED = ("INCOMPLETE", "FAILED", "TIMEOUT", "CANCELLED")
_SIGN_LOOKUP_PAGES = 10


def _error_code(exc: Exception) -> str:
    code = getattr(exc, "code", None)
    if code:
        return str(code)
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        found = response.get("Error", {}).get("Code")
        if found:
            return str(found)
    return type(exc).__name__


def _region_of(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[3] if len(parts) >= 6 and parts[3] else None


def _role_name(role_arn: str) -> str:
    return role_arn.rsplit("/", 1)[-1]


# --- signing key -------------------------------------------------------------


def check_signing_key_usable(kms: Any, key_arn: str | None, region: str | None) -> CheckResult:
    """The KMS key exists, has the shape Quick needs and is in the connector's Region."""
    name = "signing_key_usable"
    if not key_arn:
        return CheckResult(
            name=name, passed=False, side="aws",
            details="State records no KMS signing key. Run `kb-connector setup` first.",
        )
    try:
        meta = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    except Exception as exc:  # noqa: BLE001 - reported as the check outcome
        return CheckResult(
            name=name, passed=False, side="aws",
            details=f"Could not describe KMS key {key_arn} ({_error_code(exc)}).",
            data={"key_arn": key_arn, "error_code": _error_code(exc)},
        )
    problems = key_shape_problems(meta)
    key_region = _region_of(key_arn)
    if region and key_region and key_region != region:
        problems.append(
            f"it is in {key_region}, and the connector's Quick Region is {region}"
        )
    if problems:
        return CheckResult(
            name=name, passed=False, side="aws",
            details=f"KMS key {key_arn} cannot sign for Quick: " + "; ".join(problems) + ".",
            data={"key_arn": key_arn, "problems": problems},
        )
    return CheckResult(
        name=name, passed=True, side="aws",
        details=f"KMS key {key_arn} is an enabled RSA_2048 SIGN_VERIFY key in {key_region}.",
        data={"key_arn": key_arn},
    )


def _statements(policy: Any) -> list[dict]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return []
    if not isinstance(policy, dict):
        return []
    raw = policy.get("Statement")
    if isinstance(raw, dict):
        raw = [raw]
    return [s for s in raw or [] if isinstance(s, dict)]


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    return [value] if value is not None else []


def key_policy_allows_sign(policy: Any, role_arn: str) -> bool:
    """Whether an Allow statement names `role_arn` as AWS principal for kms:Sign.

    `policy` is the key policy document, as JSON text or parsed. A wildcard
    principal does not count: it says nothing about Quick's role in particular.
    """
    for statement in _statements(policy):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        if role_arn not in _as_list(principal.get("AWS")):
            continue
        actions = {str(a).lower() for a in _as_list(statement.get("Action"))}
        if actions & {"kms:sign", "kms:*"}:
            return True
    return False


def grants_allow_sign(grants: list[dict], role_arn: str) -> bool:
    """Whether a KMS grant gives `role_arn` the Sign operation."""
    return any(
        g.get("GranteePrincipal") == role_arn and "Sign" in (g.get("Operations") or [])
        for g in grants
    )


def _list_all_grants(kms: Any, key_arn: str) -> list[dict]:
    grants: list[dict] = []
    kwargs: dict[str, Any] = {"KeyId": key_arn}
    while True:
        resp = kms.list_grants(**kwargs)
        grants.extend(g for g in resp.get("Grants") or [] if isinstance(g, dict))
        marker = resp.get("NextMarker")
        if not marker or not resp.get("Truncated", True):
            return grants
        kwargs["Marker"] = marker


def check_key_authorized(*, iam: Any, kms: Any, key_arn: str | None, signer: Any) -> CheckResult:
    """Whether the role Quick signs with may call kms:Sign on the key.

    Any one route passes: the role's identity policies (IAM policy simulator),
    a key policy statement naming the role, or a grant to the role.
    """
    name = "quick_key_authorized"
    if not key_arn:
        return CheckResult(
            name=name, passed=False, side="aws",
            details="State records no KMS signing key, so there is nothing to authorize.",
        )
    role_arn = getattr(signer, "role_arn", None)
    role_type = getattr(signer, "role_type", None)
    if not role_arn:
        reason = getattr(signer, "detail", None) or f"role type {role_type!r}"
        return CheckResult(
            name=name, passed=False, side="aws",
            details=(
                f"Could not tell which role Amazon Quick signs with "
                f"(DescribeResourcePermissions: {reason})."
            ),
            data={"role_type": role_type},
        )

    data: dict[str, Any] = {
        "signer_role": role_arn,
        "role_type": role_type,
        "routes": [],
        "unreadable": [],
        "note": (
            "The key policy is not passed to the policy simulator: its default "
            "statement for the account root would make every key look allowed. "
            "Key policy statements and grants are read and checked separately."
        ),
    }
    try:
        iam.get_role(RoleName=_role_name(role_arn))
    except Exception as exc:  # noqa: BLE001 - reported as the check outcome
        if _error_code(exc) == "NoSuchEntity":
            if role_type == "QUICKSIGHT_MANAGED":
                details = (
                    f"Amazon Quick is not authorized to sign with KMS key {key_arn}: "
                    f"the role Quick signs with ({role_arn}) does not exist, so the "
                    f"Quick console 'Select keys' step has not been done in this "
                    f"account. {_SELECT_KEYS_STEP}"
                )
            else:
                details = (
                    f"The Quick service role {role_arn} does not exist, so Quick "
                    f"cannot sign with KMS key {key_arn}."
                )
            return CheckResult(name=name, passed=False, side="aws", details=details, data=data)
        data["unreadable"].append("role (iam:GetRole)")

    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=["kms:Sign"], ResourceArns=[key_arn],
        )
        if any(r.get("EvalDecision") == "allowed" for r in resp.get("EvaluationResults") or []):
            data["routes"].append("identity policy")
    except Exception:  # noqa: BLE001 - an unreadable route is listed, not fatal
        data["unreadable"].append("identity policy (iam:SimulatePrincipalPolicy)")

    try:
        document = kms.get_key_policy(KeyId=key_arn, PolicyName="default").get("Policy")
        if key_policy_allows_sign(document, role_arn):
            data["routes"].append("key policy")
    except Exception:  # noqa: BLE001
        data["unreadable"].append("key policy (kms:GetKeyPolicy)")

    try:
        if grants_allow_sign(_list_all_grants(kms, key_arn), role_arn):
            data["routes"].append("grant")
    except Exception:  # noqa: BLE001
        data["unreadable"].append("grants (kms:ListGrants)")

    unread = (
        f" Could not read: {', '.join(data['unreadable'])}." if data["unreadable"] else ""
    )
    if data["routes"]:
        return CheckResult(
            name=name, passed=True, side="aws",
            details=(
                f"The role Quick signs with ({role_arn}) may call kms:Sign on the "
                f"key: allowed by {' and '.join(data['routes'])}.{unread}"
            ),
            data=data,
        )
    customer = (
        " This account uses a customer-managed Quick service role, which also "
        "needs kms:Sign on the key." if role_type == "CUSTOMER_MANAGED" else ""
    )
    return CheckResult(
        name=name, passed=False, side="aws",
        details=(
            f"Amazon Quick is not yet authorized to sign with KMS key {key_arn}: no "
            f"identity policy, key policy statement or grant gives {role_arn} "
            f"kms:Sign on it.{unread} {_SELECT_KEYS_STEP}{customer}"
        ),
        data=data,
    )


# --- Microsoft Entra -----------------------------------------------------------


@dataclass
class DirectorySnapshot:
    """What Microsoft Graph says about the connector's Entra app."""

    app_found: bool
    object_id: str | None
    app_id: str | None
    thumbprints: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)  # permission values in the plan
    missing: list[str] = field(default_factory=list)   # values without admin consent


def consent_plan(cfg: Any, cs: ConnectorState) -> Any:
    """The application permissions setup grants this Quick connector."""
    from kb_connector.providers.microsoft import permissions
    from kb_connector.quick import templates

    source = (cfg.type if cfg else None) or cs.connector_type or "sharepoint"
    return permissions.build_plan(
        source=source,
        acl=templates.quick_acl(cfg) if cfg else True,
        sites_selected=bool(cfg.get("sites_selected", False)) if cfg else False,
        credential="cert",
        target="quick",
    )


def read_directory(
    cs: ConnectorState, plan: Any, *, method: str, device_client_id: str | None,
) -> DirectorySnapshot | None:
    """Read the app, its certificates and its consent; None when Graph is unreachable."""
    if not cs.tenant_id or not cs.client_app_object_id:
        return None
    try:
        from kb_connector.providers.microsoft import apps
        from kb_connector.providers.microsoft.client import GraphClient

        graph = GraphClient.from_auth(
            method=method, tenant_id=cs.tenant_id, device_client_id=device_client_id,
        )
        required = [req.value for req in plan.requirements]
        app = apps.get_application(graph, cs.client_app_object_id)
        app_id = (app or {}).get("appId")
        if app is None or (cs.client_app_id and app_id != cs.client_app_id):
            return DirectorySnapshot(
                app_found=False, object_id=cs.client_app_object_id,
                app_id=cs.client_app_id, required=required,
            )
        thumbprints = apps.list_certificate_thumbprints(graph, cs.client_app_object_id)
        sp = apps.find_service_principal(graph, str(app_id))
        if sp is None:
            missing = list(required)
        else:
            assigned = {
                (a.get("resourceId"), a.get("appRoleId"))
                for a in apps.list_app_role_assignments(graph, sp["id"])
            }
            missing = [
                g.requirement.value for g in apps.resolve_grants(graph, plan)
                if (g.resource_sp_id, g.app_role_id) not in assigned
            ]
    except Exception:  # noqa: BLE001 - no Graph access is an expected outcome
        return None
    return DirectorySnapshot(
        app_found=True, object_id=cs.client_app_object_id, app_id=str(app_id),
        thumbprints=list(thumbprints), required=required, missing=missing,
    )


def check_entra_app(snap: DirectorySnapshot) -> CheckResult:
    if snap.app_found:
        return CheckResult(
            name="entra_app", passed=True, side="source",
            details=f"Entra app {snap.app_id} exists in the tenant.",
            data={"app_id": snap.app_id},
        )
    return CheckResult(
        name="entra_app", passed=False, side="source",
        details=(
            f"The Entra app recorded in state (app {snap.app_id}, object "
            f"{snap.object_id}) is not in the tenant. Re-run `kb-connector setup` "
            f"to create it again."
        ),
        data={"app_id": snap.app_id, "object_id": snap.object_id},
    )


def check_entra_consent(snap: DirectorySnapshot) -> CheckResult:
    if not snap.missing:
        return CheckResult(
            name="entra_consent", passed=True, side="source",
            details=(
                f"All {len(snap.required)} application permission(s) have admin "
                f"consent: {', '.join(snap.required)}."
            ),
            data={"required": snap.required},
        )
    return CheckResult(
        name="entra_consent", passed=False, side="source",
        details=(
            f"Admin consent is missing for: {', '.join(snap.missing)}. Re-run "
            f"`kb-connector setup`, or grant admin consent for them in Microsoft Entra."
        ),
        data={"required": snap.required, "missing": snap.missing},
    )


# --- knowledge base ------------------------------------------------------------


def _kb_missing(details: str, **data: Any) -> CheckResult:
    return CheckResult(name="quick_kb_active", passed=False, side="aws", details=details, data=data)


def find_knowledge_base(
    quick: Any, *, kb_id: str | None, cs: ConnectorState,
) -> tuple[dict | None, list[CheckResult], list[str]]:
    """The knowledge base to check: `--kb`, else state, else discovery.

    Discovery uses the data source that carries the app's client id. It reads
    only; what it finds is reported, not recorded in state.
    """
    try:
        if kb_id:
            kb = quick.describe_knowledge_base(kb_id)
            if kb is None:
                return None, [_kb_missing(f"Quick knowledge base {kb_id} does not exist.",
                                          kb_id=kb_id)], []
            return kb, [], []
        if cs.knowledge_base_id:
            kb = quick.describe_knowledge_base(cs.knowledge_base_id)
            if kb is None:
                return None, [_kb_missing(
                    f"Quick knowledge base {cs.knowledge_base_id} is recorded in state "
                    f"but does not exist. Run `kb-connector setup` to create it again.",
                    kb_id=cs.knowledge_base_id,
                )], []
            return kb, [], []
        if not cs.client_app_id:
            return None, [_kb_missing(
                "No Quick knowledge base: state records none and no Entra app. "
                "Run `kb-connector setup` first."
            )], []
        sources = quick.data_sources_for_app(cs.client_app_id)
        if not sources:
            return None, [_kb_missing(
                f"No Quick knowledge base: state records none, and no Quick data "
                f"source uses app {cs.client_app_id}. Run `kb-connector setup` to "
                f"create them."
            )], []
        if len(sources) > 1:
            ids = sorted(str(ds.get("DataSourceId")) for ds in sources)
            return None, [_kb_missing(
                f"Several Quick data sources use app {cs.client_app_id}: "
                f"{', '.join(ids)}. Pass --kb with the knowledge base to check.",
                data_source_ids=ids,
            )], []
        (ds,) = sources
        summaries = quick.knowledge_bases_for_data_source(str(ds.get("Arn")))
        if len(summaries) != 1:
            ids = sorted(str(s.get("KnowledgeBaseId")) for s in summaries)
            found = f": {', '.join(ids)}" if ids else ""
            return None, [_kb_missing(
                f"Quick data source {ds.get('DataSourceId')} has {len(summaries)} "
                f"knowledge base(s){found}. "
                + ("Pass --kb with the one to check." if ids
                   else "Run `kb-connector setup` to create one."),
                knowledge_base_ids=ids,
            )], []
        found_id = str(summaries[0].get("KnowledgeBaseId"))
        kb = quick.describe_knowledge_base(found_id)
        if kb is None:
            return None, [_kb_missing(f"Quick knowledge base {found_id} does not exist.",
                                      kb_id=found_id)], []
        note = (
            f"Checked Quick knowledge base {found_id} on data source "
            f"{ds.get('DataSourceId')}, found by the app's client id. State does "
            f"not record it; run `kb-connector setup` to record it."
        )
        return kb, [], [note]
    except ConnectorError as exc:
        return None, [_kb_missing(f"Could not read the Quick knowledge base: {exc}")], []


def check_kb_active(kb: dict) -> CheckResult:
    kb_id = kb.get("KnowledgeBaseId")
    status = kb.get("Status")
    data = {"kb_id": kb_id, "status": status}
    if status == "ACTIVE":
        return CheckResult(
            name="quick_kb_active", passed=True, side="aws",
            details=f"Quick knowledge base {kb_id} ({kb.get('Name')}) is ACTIVE.", data=data,
        )
    return CheckResult(
        name="quick_kb_active", passed=False, side="aws",
        details=f"Quick knowledge base {kb_id} is {status}, not ACTIVE.", data=data,
    )


def _template(kb: dict) -> dict:
    config = kb.get("KnowledgeBaseConfiguration") or {}
    template = (config.get("templateConfiguration") or {}).get("template")
    return template if isinstance(template, dict) else {}


def check_kb_acl(kb: dict, expected: bool) -> CheckResult:
    """The knowledge base enforces document ACLs exactly when the config asks for it."""
    actual = (kb.get("AccessControlConfiguration") or {}).get("isACLEnabled")
    crawl_acl = (_template(kb).get("accessControlConfiguration") or {}).get("crawlAcl")
    data = {"expected": expected, "isACLEnabled": actual, "crawlAcl": crawl_acl}
    wrong = []
    if actual is None:
        wrong.append("the knowledge base reports no isACLEnabled")
    elif bool(actual) != expected:
        wrong.append(f"isACLEnabled is {bool(actual)}")
    if crawl_acl is not None and bool(crawl_acl) != expected:
        wrong.append(f"the template's crawlAcl is {bool(crawl_acl)}")
    if wrong:
        return CheckResult(
            name="quick_kb_acl", passed=False, side="aws",
            details=(
                f"The config expects ACL {'on' if expected else 'off'}, but "
                f"{' and '.join(wrong)}. ACL is fixed when the knowledge base is "
                f"created: a different setting needs a new knowledge base."
            ),
            data=data,
        )
    return CheckResult(
        name="quick_kb_acl", passed=True, side="aws",
        details=f"Document ACLs are {'enforced' if expected else 'off'}, as configured.",
        data=data,
    )


def _latest_sync(kb: dict) -> tuple[str | None, str | None]:
    summary = kb.get("LatestIngestionSummary") or {}
    status = summary.get("IngestionStatus")
    return (str(status) if status else None), summary.get("IngestionId")


def kb_documents(kb: dict) -> CheckResult | str:
    """DocumentCount > 0 passes; none while the first sync runs is a note."""
    count = kb.get("DocumentCount")
    status, _ = _latest_sync(kb)
    if isinstance(count, int) and count > 0:
        return CheckResult(
            name="quick_kb_documents", passed=True, side="shared",
            details=f"The knowledge base holds {count} document(s).",
            data={"document_count": count},
        )
    if status in _SYNC_IN_PROGRESS:
        return (
            f"quick_kb_documents not checked: the knowledge base holds no documents "
            f"yet and its sync is {status}."
        )
    return CheckResult(
        name="quick_kb_documents", passed=False, side="shared",
        details=(
            f"The knowledge base holds no documents (latest sync: {status or 'none'}). "
            f"The knowledge base's sync report in the Quick console lists what was "
            f"skipped and why: {SYNC_REPORT_DOCS}"
        ),
        data={"document_count": count, "sync_status": status},
    )


def check_kb_latest_sync(kb: dict) -> CheckResult | str:
    """COMPLETED passes, QUEUED/RUNNING pass as in progress, the rest fail."""
    status, ingestion_id = _latest_sync(kb)
    data = {"status": status, "ingestion_id": ingestion_id}
    if status is None:
        return "quick_kb_latest_sync not checked: the knowledge base reports no sync yet."
    if status == "COMPLETED":
        return CheckResult(
            name="quick_kb_latest_sync", passed=True, side="shared",
            details=f"Latest sync {ingestion_id} COMPLETED.", data=data,
        )
    if status in _SYNC_IN_PROGRESS:
        return CheckResult(
            name="quick_kb_latest_sync", passed=True, side="shared",
            details=f"Latest sync {ingestion_id} is in progress ({status}).", data=data,
        )
    known = "" if status in _SYNC_FAILED else " (a status this tool does not recognize)"
    return CheckResult(
        name="quick_kb_latest_sync", passed=False, side="shared",
        details=(
            f"Latest sync {ingestion_id} ended {status}{known}. The Quick API gives no "
            f"reason: open the knowledge base's sync report in the Quick console "
            f"({SYNC_REPORT_DOCS})."
        ),
        data=data,
    )


# --- CloudTrail ----------------------------------------------------------------


def _event_time(event: dict) -> str:
    value = event.get("EventTime")
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    return str(value or "")


def _event_body(event: dict) -> dict | None:
    try:
        body = json.loads(event.get("CloudTrailEvent") or "{}")
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _names_key(event: dict, body: dict, key_arn: str) -> bool:
    """Whether an event names `key_arn` as its resource or its keyId."""
    for resource in event.get("Resources") or []:
        if isinstance(resource, dict) and resource.get("ResourceName") == key_arn:
            return True
    for resource in body.get("resources") or []:
        if isinstance(resource, dict) and resource.get("ARN") == key_arn:
            return True
    params = body.get("requestParameters")
    return isinstance(params, dict) and params.get("keyId") == key_arn


def _as_datetime(value: str) -> _dt.datetime | None:
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def _latest(found: list[dict]) -> _dt.datetime | None:
    times = [t for t in (_as_datetime(d["time"]) for d in found) if t is not None]
    return max(times) if times else None


def sign_successes(events: list[dict], key_arn: str, role_name: str) -> list[dict]:
    """kms:Sign calls on `key_arn` by the Quick role that succeeded.

    A successful Sign event names the key in `resources` or in
    `requestParameters.keyId`. Only the Quick role's calls count, so the
    certificate signing that setup does as the operator is not mistaken for
    Quick signing. Returns event ids and times only.
    """
    marker = f"assumed-role/{role_name}/"
    found: list[dict] = []
    for event in events:
        body = _event_body(event)
        if body is None or body.get("errorCode"):
            continue
        caller = str((body.get("userIdentity") or {}).get("arn") or "")
        if marker in caller and _names_key(event, body, key_arn):
            found.append({"event_id": event.get("EventId"), "time": _event_time(event)})
    return found


def sign_denials(events: list[dict], key_arn: str, role_name: str | None) -> list[dict]:
    """Denied kms:Sign events on `key_arn`, by the Quick role when it is known.

    The key ARN is matched in `errorMessage`, because a denied Sign event
    carries no `resources`. Returns event ids and times only.
    """
    found: list[dict] = []
    for event in events:
        body = _event_body(event)
        if body is None:
            continue
        if "AccessDenied" not in str(body.get("errorCode") or ""):
            continue
        message = str(body.get("errorMessage") or "")
        if key_arn not in message:
            continue
        if role_name:
            marker = f"assumed-role/{role_name}/"
            caller = str((body.get("userIdentity") or {}).get("arn") or "")
            if marker not in caller and marker not in message:
                continue
        found.append({"event_id": event.get("EventId"), "time": _event_time(event)})
    return found


def check_sign_denied(
    cloudtrail: Any, *, key_arn: str, signer: Any, lookback_minutes: int = 60,
) -> CheckResult:
    """CloudTrail kms:Sign calls on the key that were denied in the lookback window.

    Denials followed by a successful kms:Sign by the Quick role on the same key
    pass: the key was authorized after them.
    """
    name = "kms_sign_denied"
    now = _dt.datetime.now(_dt.timezone.utc)
    kwargs: dict[str, Any] = {
        "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "Sign"}],
        "StartTime": now - _dt.timedelta(minutes=lookback_minutes),
        "EndTime": now,
        "MaxResults": 50,
    }
    events: list[dict] = []
    try:
        for _ in range(_SIGN_LOOKUP_PAGES):
            resp = cloudtrail.lookup_events(**kwargs)
            events.extend(resp.get("Events") or [])
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
    except Exception as exc:  # noqa: BLE001 - can't check != connector is unhealthy
        return CheckResult(
            name=name, passed=True, side="aws",
            details=f"Could not scan CloudTrail for kms:Sign events ({_error_code(exc)}).",
            data={"error_code": _error_code(exc)},
        )
    role_arn = getattr(signer, "role_arn", None)
    role_name = _role_name(role_arn) if role_arn else None
    denials = sign_denials(events, key_arn, role_name)
    if denials:
        latest = max(d["time"] for d in denials)
        successes = sign_successes(events, key_arn, role_name) if role_name else []
        denied_at, signed_at = _latest(denials), _latest(successes)
        if denied_at and signed_at and signed_at > denied_at:
            return CheckResult(
                name=name, passed=True, side="aws",
                details=(
                    f"{len(denials)} denied kms:Sign call(s) on KMS key {key_arn} in "
                    f"the last {lookback_minutes}m (latest {latest}), followed by a "
                    f"successful kms:Sign by {role_name} at {signed_at.isoformat()}. "
                    f"Quick can sign with the key."
                ),
                data={"events": denials, "signed_at": signed_at.isoformat()},
            )
        return CheckResult(
            name=name, passed=False, side="aws",
            details=(
                f"{len(denials)} denied kms:Sign call(s) on KMS key {key_arn} in the "
                f"last {lookback_minutes}m (latest {latest}). Quick tried to sign and "
                f"was refused. {_SELECT_KEYS_STEP}"
            ),
            data={"events": denials},
        )
    return CheckResult(
        name=name, passed=True, side="aws",
        details=f"No denied kms:Sign calls on the key in the last {lookback_minutes}m.",
        data={},
    )


# --- all checks ------------------------------------------------------------------


def _add(checks: list[CheckResult], notes: list[str], outcome: CheckResult | str) -> None:
    if isinstance(outcome, str):
        notes.append(outcome)
    else:
        checks.append(outcome)


def run_quick_checks(
    *,
    session: Any,
    region: str | None,
    account_id: str,
    cfg: Any,
    cs: ConnectorState | None,
    kb_id: str | None,
    directory: DirectorySnapshot | None,
    directory_checked: bool,
    sign_denied_lookback: int | None = None,
) -> tuple[list[CheckResult], list[str]]:
    """Every Quick check in order, plus the notes for what was not checked.

    `directory` is the Graph snapshot (`read_directory`), None when Graph was
    not asked (`directory_checked` False) or could not be reached. With
    `sign_denied_lookback`, the CloudTrail kms:Sign denial check runs last.
    """
    from kb_connector.quick.client import QuickClient
    from kb_connector.quick import templates

    cs = cs or ConnectorState()
    checks: list[CheckResult] = []
    notes: list[str] = []
    key_arn = cs.signing_key_arn
    kms = session.client("kms", region_name=region)
    quick = QuickClient(session=session, region=region, account_id=account_id)

    checks.append(check_signing_key_usable(kms, key_arn, region))
    signer = None
    if key_arn:
        partition = key_arn.split(":")[1] if key_arn.count(":") >= 5 else "aws"
        signer = quick.signer_role(partition=partition, account_id=account_id)
        checks.append(check_key_authorized(
            iam=session.client("iam"), kms=kms, key_arn=key_arn, signer=signer,
        ))

    if directory is not None:
        checks.append(check_entra_app(directory))
        if directory.app_found:
            checks.append(check_certificate_installed(
                recorded_thumbprint=cs.cert_thumbprint_b64url,
                installed_thumbprints=directory.thumbprints,
            ))
            checks.append(check_entra_consent(directory))
        else:
            notes.append("Certificate and consent not checked: the Entra app is not in the tenant.")
    elif not directory_checked:
        notes.append(
            "Entra app, certificate and consent not checked: not requested "
            "(the kb-connector CLI checks them)."
        )
    elif not (cs.tenant_id and cs.client_app_object_id):
        notes.append("Entra app, certificate and consent not checked: state records no Entra app.")
    else:
        notes.append(
            "Entra app, certificate and consent not checked: could not reach "
            "Microsoft Graph (sign in with `az login`, or pass --auth-method device_code)."
        )

    kb, kb_checks, kb_notes = find_knowledge_base(quick, kb_id=kb_id, cs=cs)
    checks.extend(kb_checks)
    notes.extend(kb_notes)
    if kb is not None:
        checks.append(check_kb_active(kb))
        if cfg is not None:
            checks.append(check_kb_acl(kb, templates.quick_acl(cfg)))
        else:
            notes.append("quick_kb_acl not checked: no config entry for this connector.")
        _add(checks, notes, kb_documents(kb))
        _add(checks, notes, check_kb_latest_sync(kb))

    if sign_denied_lookback is not None and key_arn:
        checks.append(check_sign_denied(
            session.client("cloudtrail", region_name=region), key_arn=key_arn,
            signer=signer, lookback_minutes=sign_denied_lookback,
        ))
    return checks, notes
