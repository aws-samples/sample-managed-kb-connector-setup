"""Entra app-registration lifecycle for managed KB connectors.

Handles creating/finding app registrations, granting admin consent for
application permissions, uploading certificates, and adding client secrets.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from kb_connector.core.errors import GraphError
from kb_connector.providers.microsoft.certs import (
    GeneratedCertificate,
    KmsBackedCertificate,
    certificate_der_b64,
)
from kb_connector.providers.microsoft.client import (
    GraphClient,
    require_mapping,
    require_str,
)
from kb_connector.providers.microsoft.permissions import PermissionPlan, PermissionRequirement


@dataclass
class AppRegistration:
    """Identifiers for a created/located application registration."""

    app_id: str              # application (client) id
    object_id: str           # directory object id
    service_principal_id: str  # object id of the app's service principal


def escape_odata_literal(value: str) -> str:
    """Escape a string for use inside a single-quoted OData filter literal.

    OData escapes a single quote by doubling it. Without this, an app name
    containing an apostrophe terminates the literal early: the name
    `O'Brien Connector` produces `displayName eq 'O'Brien Connector'`, which
    Graph rejects as a malformed filter — and a deliberately crafted name could
    append clauses to change which application the query matches, which is the
    object the tool then uploads a certificate to and grants tenant-wide
    permissions on.
    """
    return value.replace("'", "''")


def find_application_by_name(graph: GraphClient, display_name: str) -> dict | None:
    """Return the application object with the given display name, or None.

    The match is re-verified client-side. `$filter` narrows the query, but the
    decision to reuse an existing app registration — and therefore to add
    credentials to it — is made on an exact local comparison rather than on
    trusting the server-side filter to have been interpreted as intended.
    """
    escaped = escape_odata_literal(display_name)
    resp = graph.get("/applications", **{"$filter": f"displayName eq '{escaped}'"})
    apps = (resp or {}).get("value", [])
    for app in apps:
        if app.get("displayName") == display_name:
            return require_mapping(app, field="applications[].value")
    return None


def ensure_service_principal(graph: GraphClient, app_id: str) -> dict:
    """Return the service principal for an app id, creating it if missing."""
    resp = graph.get("/servicePrincipals", **{"$filter": f"appId eq '{app_id}'"})
    existing = (resp or {}).get("value", [])
    if existing:
        return require_mapping(existing[0], field="servicePrincipals[0]")
    return require_mapping(
        graph.post("/servicePrincipals", {"appId": app_id}),
        field="servicePrincipals",
    )


def create_application(graph: GraphClient, display_name: str) -> AppRegistration:
    """Create a single-tenant application + its service principal."""
    app = graph.post(
        "/applications",
        {"displayName": display_name, "signInAudience": "AzureADMyOrg"},
    )
    app_id = app["appId"]
    object_id = app["id"]
    sp = ensure_service_principal(graph, app_id)
    return AppRegistration(app_id=app_id, object_id=object_id, service_principal_id=sp["id"])


# --- Permission resolution + admin consent -----------------------------------


@dataclass
class ResolvedGrant:
    """A permission resolved to concrete ids, ready to assign."""

    requirement: PermissionRequirement
    resource_sp_id: str
    app_role_id: str


def resolve_grants(graph: GraphClient, plan: PermissionPlan) -> list[ResolvedGrant]:
    """Resolve every requirement in a plan to (resource SP id, role id)."""
    cache: dict[str, dict] = {}
    resolved: list[ResolvedGrant] = []
    for req in plan.requirements:
        sp = cache.get(req.resource_app_id)
        if sp is None:
            sp = _resource_sp_by_app_id(graph, req.resource_app_id)
            cache[req.resource_app_id] = sp
        resolved.append(ResolvedGrant(
            requirement=req,
            resource_sp_id=sp["id"],
            app_role_id=_resolve_app_role_id(sp, req.value),
        ))
    return resolved


def grant_admin_consent(
    graph: GraphClient, client_sp_id: str, grants: list[ResolvedGrant]
) -> None:
    """Assign application permissions (== admin consent). Idempotent."""
    existing = graph.get(f"/servicePrincipals/{client_sp_id}/appRoleAssignments")
    already = {
        (a.get("resourceId"), a.get("appRoleId"))
        for a in (existing or {}).get("value", [])
    }
    for grant in grants:
        key = (grant.resource_sp_id, grant.app_role_id)
        if key in already:
            continue
        graph.post(
            f"/servicePrincipals/{client_sp_id}/appRoleAssignments",
            {
                "principalId": client_sp_id,
                "resourceId": grant.resource_sp_id,
                "appRoleId": grant.app_role_id,
            },
        )


def declare_required_resource_access(
    graph: GraphClient,
    app_object_id: str,
    grants: list[ResolvedGrant],
) -> None:
    """Update the application's requiredResourceAccess manifest.

    Makes the Entra portal's "Configured permissions" panel show the grants.
    """
    app = graph.get(f"/applications/{app_object_id}")
    existing: list[dict] = app.get("requiredResourceAccess") or []
    by_resource: dict[str, dict] = {
        r["resourceAppId"]: r for r in existing if r.get("resourceAppId")
    }

    for grant in grants:
        resource_app_id = grant.requirement.resource_app_id
        entry = by_resource.setdefault(
            resource_app_id,
            {"resourceAppId": resource_app_id, "resourceAccess": []},
        )
        access_list = entry.setdefault("resourceAccess", [])
        existing_ids = {a.get("id") for a in access_list if a.get("type") == "Role"}
        if grant.app_role_id not in existing_ids:
            access_list.append({"id": grant.app_role_id, "type": "Role"})

    graph.patch(
        f"/applications/{app_object_id}",
        {"requiredResourceAccess": list(by_resource.values())},
    )


# --- Certificate + secret management ----------------------------------------


def upload_certificate(
    graph: GraphClient,
    app_object_id: str,
    cert: GeneratedCertificate | KmsBackedCertificate,
) -> None:
    """Set the generated certificate as the application's keyCredential.

    Accepts either certificate kind: only the public DER and the expiry are used,
    and where the matching private key lives (locally, or inside KMS) makes no
    difference to what Entra stores.

    Note this PATCH replaces `keyCredentials` wholesale rather than appending, so
    an app shared by more than one connector keeps only the most recently
    uploaded certificate. Callers avoid re-uploading needlessly via their
    certificate-reuse checks.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    credential = {
        "type": "AsymmetricX509Cert",
        "usage": "Verify",
        "key": certificate_der_b64(cert.certificate_der),
        "displayName": "KB connector certificate",
        "startDateTime": now.replace(microsecond=0).isoformat(),
        "endDateTime": cert.not_after,
    }
    graph.patch(f"/applications/{app_object_id}", {"keyCredentials": [credential]})


def list_certificate_thumbprints(graph: GraphClient, app_object_id: str) -> list[str]:
    """Return the SHA-1 thumbprints of the certificates installed on an app.

    Thumbprints come back base64url without padding, matching
    `GeneratedCertificate.thumbprint_b64url` and `state.cert_thumbprint_b64url`
    so they compare directly. Each identifier is decoded to the raw SHA-1 bytes
    and re-encoded rather than compared as text, because Graph does not report
    them in the form state stores.

    This is the only way to tell whether the certificate the tool recorded is
    still the one the application will accept. The private key lives in Secrets
    Manager and S3, so the two halves of the credential can drift apart, and only
    the directory can confirm its side.

    Entries that are not certificates, or that carry no usable identifier, are
    skipped: an application may also hold client secrets, and the caller is
    asking which certificates are present.
    """
    resp = graph.get(
        f"/applications/{app_object_id}", **{"$select": "keyCredentials"}
    )
    thumbprints: list[str] = []
    for credential in (resp or {}).get("keyCredentials") or []:
        if not isinstance(credential, dict):
            continue
        if credential.get("type") != "AsymmetricX509Cert":
            continue
        raw = _decode_thumbprint(credential.get("customKeyIdentifier"))
        if raw is None:
            continue
        thumbprints.append(_b64url_no_padding(raw))
    return thumbprints


def _decode_thumbprint(identifier: object) -> bytes | None:
    """Decode a `customKeyIdentifier` to raw SHA-1 bytes, or None if unusable.

    Graph reports this field as hex in some tenants and base64 in others, so both
    are accepted. Hex is tried first: a 40-character hex string is also valid
    base64, and decoding it that way yields 30 meaningless bytes rather than an
    error, which would silently produce a thumbprint that matches nothing.

    The length check is what makes that safe in general. A SHA-1 digest is 20
    bytes, so anything else means the value was not the digest this is looking
    for, whichever encoding produced it.
    """
    import base64
    import binascii

    if not isinstance(identifier, str) or not identifier.strip():
        return None
    text = identifier.strip()

    raw: bytes | None = None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return None

    return raw if len(raw) == 20 else None


def _b64url_no_padding(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def add_client_secret(
    graph: GraphClient,
    app_object_id: str,
    *,
    display_name: str = "KB connector client secret",
    valid_days: int = 365,
) -> str:
    """Provision a client secret on an application; returns its value.

    Graph returns the secret value exactly once — callers must stash it.
    """
    expires = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=valid_days)
    resp = graph.post(
        f"/applications/{app_object_id}/addPassword",
        {
            "passwordCredential": {
                "displayName": display_name,
                "endDateTime": expires.replace(microsecond=0).isoformat(),
            }
        },
    )
    return require_str(resp.get("secretText"), field="secretText")


def delete_application(graph: GraphClient, app_object_id: str) -> None:
    """Delete an application registration by directory object id.

    Graph returns 204 on success and 404 if the app doesn't exist (which
    teardown treats as success — the desired end-state is "no app", and
    a missing one already satisfies that).
    """
    try:
        graph.delete(f"/applications/{app_object_id}")
    except GraphError as exc:
        if getattr(exc, "status", None) == 404:
            return
        raise


# --- internals ---------------------------------------------------------------


def _resource_sp_by_app_id(graph: GraphClient, resource_app_id: str) -> dict:
    """Fetch the resource service principal (Graph / SharePoint) by app id."""
    resp = graph.get(
        "/servicePrincipals", **{"$filter": f"appId eq '{resource_app_id}'"}
    )
    values = (resp or {}).get("value", [])
    if not values:
        raise GraphError(
            f"Resource service principal for appId {resource_app_id} not found."
        )
    return require_mapping(values[0], field="servicePrincipals[0]")


def _resolve_app_role_id(resource_sp: dict, value: str) -> str:
    """Map an app-role value to its role id."""
    for role in resource_sp.get("appRoles", []):
        is_app_role = "Application" in (role.get("allowedMemberTypes") or [])
        if role.get("value") == value and is_app_role and role.get("isEnabled", True):
            return require_str(role.get("id"), field="appRoles[].id")
    raise GraphError(
        f"Resource {resource_sp.get('appDisplayName')!r} exposes no enabled "
        f"application role named {value!r}."
    )
