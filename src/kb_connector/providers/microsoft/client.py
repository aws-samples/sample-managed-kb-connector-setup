"""Microsoft Graph HTTP client and token acquisition.

Two acquisition strategies for admin-scoped Graph tokens:
  * "az"          - borrow a token from Azure CLI (`az account get-access-token`)
  * "device_code" - interactive device-code flow against a public client

The acquisition strategy is separated from the HTTP layer so validation can
also mint *application* tokens (client-credentials) without entangling concerns.
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any

import requests

from kb_connector.core.errors import GraphError

GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_RESOURCE = "https://graph.microsoft.com"

# Azure CLI first-party app id (public, well-known).
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

_DEFAULT_TIMEOUT = 30


# --- Token acquisition -------------------------------------------------------


def graph_token_via_az() -> str:
    """Return a Graph access token from the local Azure CLI session."""
    try:
        out = subprocess.run(
            ["az", "account", "get-access-token", "--resource", GRAPH_RESOURCE, "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise GraphError(
            "Azure CLI ('az') not found. Install it and run 'az login', "
            "or use --auth-method device_code."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise GraphError(
            "Couldn't get a Graph token from 'az'. Run 'az login' first. "
            f"Details: {exc.stderr.strip()}"
        ) from exc
    return require_str(json.loads(out.stdout).get("accessToken"), field="accessToken")


def graph_token_via_device_code(
    tenant_id: str, *, client_id: str = AZURE_CLI_CLIENT_ID
) -> str:
    """Acquire a Graph token interactively using the device-code flow.

    Prints the verification URL + user code to stdout and polls until
    the operator completes sign-in in a browser.
    """
    base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0"
    scope = "https://graph.microsoft.com/.default offline_access openid profile"

    init = requests.post(
        f"{base}/devicecode",
        data={"client_id": client_id, "scope": scope},
        timeout=_DEFAULT_TIMEOUT,
    )
    if init.status_code != 200:
        body = _safe_json(init)
        raise GraphError(
            "Couldn't start device-code sign-in. "
            + _explain_failure(body, client_id),
            status=init.status_code,
            body=body,
        )
    flow = init.json()
    print(flow["message"])

    interval = int(flow.get("interval", 5))
    deadline = time.time() + int(flow.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        poll = requests.post(
            f"{base}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": flow["device_code"],
            },
            timeout=_DEFAULT_TIMEOUT,
        )
        if poll.status_code == 200:
            return require_str(poll.json().get("access_token"), field="access_token")
        body = _safe_json(poll)
        error = (body or {}).get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise GraphError(
            "Device-code sign-in failed. " + _explain_failure(body, client_id),
            status=poll.status_code,
            body=body,
        )
    raise GraphError(
        "Device-code sign-in timed out. Re-run and complete sign-in within "
        "the time shown, or use --auth-method az."
    )


# --- Graph HTTP client -------------------------------------------------------


class GraphClient:
    """Thin authenticated wrapper over the Microsoft Graph REST API.

    Holds a bearer token and exposes get/post/patch/delete that raise
    GraphError with the parsed body on non-2xx responses.
    """

    def __init__(self, token: str, *, base: str = GRAPH_V1) -> None:
        self._token = token
        self._base = base
        self._session = requests.Session()

    @classmethod
    def from_auth(
        cls,
        *,
        method: str,
        tenant_id: str | None = None,
        base: str = GRAPH_V1,
        device_client_id: str | None = None,
    ) -> "GraphClient":
        """Build a client using the chosen acquisition method."""
        if method == "az":
            return cls(graph_token_via_az(), base=base)
        if method == "device_code":
            if not tenant_id:
                raise GraphError("device_code auth requires --tenant-id.")
            client_id = device_client_id or AZURE_CLI_CLIENT_ID
            return cls(
                graph_token_via_device_code(tenant_id, client_id=client_id), base=base
            )
        raise GraphError(f"Unknown auth method {method!r}; expected 'az' or 'device_code'.")

    # -- HTTP verbs ----------------------------------------------------------

    def get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params=params or None)

    def post(self, path: str, body: Any) -> Any:
        return self._request("POST", path, json_body=body)

    def patch(self, path: str, body: Any) -> Any:
        return self._request("PATCH", path, json_body=body)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # -- internals -----------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: Any = None,
    ) -> Any:
        # An absolute path is honored so callers can follow an @odata.nextLink,
        # but only over TLS. Every request here carries the operator's Graph
        # bearer token, which holds their full directory privileges, so a
        # plaintext URL — from a paging link in a response body, or a caller
        # passing one by mistake — would put that token on the wire.
        if path.startswith("https://"):
            url = path
        elif path.startswith("http://"):
            raise GraphError(
                f"Refusing to send a Graph request to {path!r} over plaintext "
                f"http. The request carries a bearer token with the operator's "
                f"full directory privileges."
            )
        else:
            url = f"{self._base}{path}"
        resp = self._session.request(
            method,
            url,
            params=params,
            json=json_body,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
            },
            timeout=_DEFAULT_TIMEOUT,
        )
        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return None
        raise GraphError(
            f"{method} {url} -> {resp.status_code}",
            status=resp.status_code,
            body=_safe_json(resp),
        )


# --- helpers -----------------------------------------------------------------


_AADSTS_GUIDANCE: dict[str, str] = {
    "AADSTS7000218": (
        "This tenant requires a pre-authorized app for device-code flow. "
        "Register a public client app and pass its id via --device-client-id."
    ),
    "AADSTS700016": (
        "The device-code client app isn't recognized in this tenant. "
        "Supply your own public client app id or use '--auth-method az'."
    ),
    "AADSTS53003": (
        "Sign-in blocked by Conditional Access policy. Use '--auth-method az' "
        "from a compliant session."
    ),
}


def _explain_failure(body: Any, client_id: str) -> str:
    """Build an actionable message from an Entra error body."""
    desc = ""
    if isinstance(body, dict):
        desc = body.get("error_description") or ""
    for code, guidance in _AADSTS_GUIDANCE.items():
        if code in desc:
            return f"Cause: {code} — {guidance}"
    if client_id == AZURE_CLI_CLIENT_ID:
        return (
            "The default Azure CLI client may be blocked in this tenant. "
            "Try --device-client-id or '--auth-method az'."
        )
    return "Verify the --device-client-id app allows device-code flow."


def _safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text[:2000] if resp.text else None


def require_str(value: Any, *, field: str) -> str:
    """Return a string pulled out of a Graph response.

    Graph replies are parsed JSON, so every value taken out of one arrives
    untyped. Checking the type here turns a renamed or omitted field into an
    error naming the field, at the call that needed it, instead of an obscure
    failure further along. It can only fire where the response already differed
    from what the caller expected.

    The message names the type, not the value: one call site reads `secretText`,
    and the field name plus the type is what makes a renamed or omitted field
    actionable anyway.
    """
    if not isinstance(value, str):
        raise GraphError(
            f"Graph response field {field!r} was {type(value).__name__}, "
            f"expected a string."
        )
    return value


def require_mapping(value: Any, *, field: str) -> dict[str, Any]:
    """Return a JSON object pulled out of a Graph response.

    Same reasoning as `require_str`: valid JSON can decode to a list or a
    scalar, so a caller expecting an object needs to say so.
    """
    if not isinstance(value, dict):
        raise GraphError(
            f"Graph response field {field!r} was {type(value).__name__}, "
            f"expected an object."
        )
    return value
