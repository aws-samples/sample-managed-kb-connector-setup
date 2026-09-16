"""Sites.Selected least-privilege grants for SharePoint.

When the connector app uses Sites.Selected scope, it can only access sites
it has been explicitly granted. Granting access requires a temporary "admin"
app that holds Sites.FullControl.All and calls Graph POST /sites/{id}/permissions.

This module:
  1. Creates (or reuses) the temporary admin app + client secret
  2. Mints a client-credentials Graph token for it
  3. Resolves each site URL to a site id
  4. Grants the connector app a per-site role ("read" or "fullcontrol")

The temporary admin app is local-only; its credentials never go to AWS.
Per-site grants persist independently of the admin app.
"""

from __future__ import annotations

import datetime as _dt
import time as _time
import urllib.parse
from dataclasses import dataclass

import requests

from kb_connector.core.errors import GraphError
from kb_connector.providers.microsoft.apps import (
    create_application,
    ensure_service_principal,
    find_application_by_name,
)
from kb_connector.providers.microsoft.client import (
    GraphClient,
    require_mapping,
    require_str,
)
from kb_connector.providers.microsoft.permissions import GRAPH_APP_ID

_TIMEOUT = 30


@dataclass
class AdminAppCredentials:
    """The temporary granter app and a freshly minted client secret."""

    app_id: str
    object_id: str
    service_principal_id: str
    client_secret: str


def create_admin_granter_app(
    graph: GraphClient, display_name: str
) -> AdminAppCredentials:
    """Create the temporary admin app with Sites.FullControl.All + a secret.

    Reuses an existing app of the same name if present.
    """
    existing = find_application_by_name(graph, display_name)
    if existing:
        app_id = existing["appId"]
        object_id = existing["id"]
        sp = ensure_service_principal(graph, app_id)
        sp_id = sp["id"]
    else:
        reg = create_application(graph, display_name)
        app_id, object_id, sp_id = reg.app_id, reg.object_id, reg.service_principal_id

    # Assign Sites.FullControl.All (Graph) to the admin app.
    graph_sp = _graph_service_principal(graph)
    role_id = _resolve_role(graph_sp, "Sites.FullControl.All")
    _assign_app_role_if_missing(graph, sp_id, graph_sp["id"], role_id)

    secret = _add_short_lived_secret(graph, object_id)
    return AdminAppCredentials(
        app_id=app_id,
        object_id=object_id,
        service_principal_id=sp_id,
        client_secret=secret,
    )


def grant_sites(
    *,
    tenant_id: str,
    admin: AdminAppCredentials,
    connector_app_id: str,
    connector_app_name: str,
    site_urls: list[str],
    role: str,
) -> list[dict]:
    """Grant the connector app `role` on each site in `site_urls`.

    Returns a list of per-site result dicts: {site_url, site_id, status}.
    """
    token = _mint_admin_token(tenant_id, admin.app_id, admin.client_secret)
    admin_graph = GraphClient(token)

    results: list[dict] = []
    for url in site_urls:
        site_id = _resolve_site_id(admin_graph, url)
        admin_graph.post(
            f"/sites/{site_id}/permissions",
            {
                "roles": [role],
                "grantedToIdentities": [
                    {"application": {"id": connector_app_id, "displayName": connector_app_name}}
                ],
            },
        )
        results.append({"site_url": url, "site_id": site_id, "status": "granted"})
    return results


# --- internals ---------------------------------------------------------------


def _graph_service_principal(graph: GraphClient) -> dict:
    # GRAPH_APP_ID is a well-known constant GUID, not user input, so no
    # escaping is needed here.
    resp = graph.get("/servicePrincipals", **{"$filter": f"appId eq '{GRAPH_APP_ID}'"})
    values = (resp or {}).get("value", [])
    if not values:
        raise GraphError("Microsoft Graph service principal not found in tenant.")
    return require_mapping(values[0], field="servicePrincipals[0]")


def _resolve_role(resource_sp: dict, value: str) -> str:
    for role in resource_sp.get("appRoles", []):
        if (
            role.get("value") == value
            and "Application" in (role.get("allowedMemberTypes") or [])
            and role.get("isEnabled", True)
        ):
            return require_str(role.get("id"), field="appRoles[].id")
    raise GraphError(f"Graph exposes no application role named {value!r}.")


def _assign_app_role_if_missing(
    graph: GraphClient, principal_sp_id: str, resource_sp_id: str, role_id: str
) -> None:
    existing = graph.get(f"/servicePrincipals/{principal_sp_id}/appRoleAssignments")
    for a in (existing or {}).get("value", []):
        if a.get("resourceId") == resource_sp_id and a.get("appRoleId") == role_id:
            return
    graph.post(
        f"/servicePrincipals/{principal_sp_id}/appRoleAssignments",
        {"principalId": principal_sp_id, "resourceId": resource_sp_id, "appRoleId": role_id},
    )


def _add_short_lived_secret(graph: GraphClient, app_object_id: str) -> str:
    expires = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=2)
    resp = graph.post(
        f"/applications/{app_object_id}/addPassword",
        {
            "passwordCredential": {
                "displayName": "kb-connector Sites.Selected granter (short-lived)",
                "endDateTime": expires.replace(microsecond=0).isoformat(),
            }
        },
    )
    return require_str(resp.get("secretText"), field="secretText")


def _mint_admin_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Mint a client-credentials Graph token with propagation retry."""
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    delays = (2, 4, 8, 16, 32)
    last_body = None
    last_status = None
    for attempt, delay in enumerate((0,) + delays):
        if delay:
            _time.sleep(delay)
        resp = requests.post(token_url, data=data, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return require_str(resp.json().get("access_token"), field="access_token")
        last_status = resp.status_code
        last_body = _safe_json(resp)
        if not _is_propagation_error(last_body):
            break
    raise GraphError(
        "Admin granter app couldn't obtain a Graph token after retries.",
        status=last_status,
        body=last_body,
    )


_PROPAGATION_CODES = ("AADSTS7000215", "AADSTS700016")


def _is_propagation_error(body: object) -> bool:
    if isinstance(body, dict):
        haystack = " ".join(str(v) for v in body.values() if v is not None)
    elif isinstance(body, str):
        haystack = body
    else:
        return False
    return any(code in haystack for code in _PROPAGATION_CODES)


def _resolve_site_id(admin_graph: GraphClient, site_url: str) -> str:
    """Resolve a SharePoint site URL to its Graph site id."""
    parsed = urllib.parse.urlparse(site_url)
    host = parsed.netloc
    path = parsed.path.rstrip("/")
    if not host:
        raise GraphError(f"Could not parse hostname from site URL {site_url!r}.")
    addressing = f"{host}:{path}" if path else host
    resp = admin_graph.get(f"/sites/{addressing}")
    site_id = (resp or {}).get("id")
    if not site_id:
        raise GraphError(f"Graph did not return a site id for {site_url!r}.")
    return require_str(site_id, field="sites.id")


def _safe_json(resp: requests.Response) -> object:
    try:
        return resp.json()
    except ValueError:
        return resp.text[:1000] if resp.text else None
