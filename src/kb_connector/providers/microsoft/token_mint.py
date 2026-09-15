"""Mint Entra app-only tokens for validation.

Reproduces the connector's exact token flows against the live Entra tenant:
  * client-secret client-credentials -> Graph token
  * certificate client-assertion -> SharePoint REST token (ACL check)

This module is validation-only. It never persists tokens.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import secrets as _secrets

import requests

from kb_connector.core.errors import GraphError

_TIMEOUT = 30


def token_endpoint(tenant_id: str) -> str:
    """v2.0 token endpoint for the tenant."""
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


def mint_with_client_secret(
    *, tenant_id: str, client_id: str, client_secret: str, scope: str
) -> dict:
    """Client-credentials token using a client secret. Returns the JSON body."""
    # _parse_token_response reads the JSON error body (Microsoft's OAuth endpoint
    # returns structured error_description on 4xx) and raises GraphError with
    # that context. raise_for_status would discard the body before we could
    # surface it.
    # nosemgrep: use-raise-for-status
    resp = requests.post(
        token_endpoint(tenant_id),
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
        timeout=_TIMEOUT,
    )
    return _parse_token_response(resp)


def mint_with_certificate(
    *,
    tenant_id: str,
    client_id: str,
    private_key_pem: str,
    thumbprint_b64url: str,
    scope: str,
) -> dict:
    """Client-credentials token using a certificate client assertion.

    Args:
        private_key_pem: PEM private key (with headers).
        thumbprint_b64url: base64url(no padding) SHA-1 cert thumbprint.
        scope: e.g. "https://graph.microsoft.com/.default"
    """
    assertion = _build_client_assertion(
        tenant_id=tenant_id,
        client_id=client_id,
        private_key_pem=private_key_pem,
        thumbprint_b64url=thumbprint_b64url,
    )
    # See mint_with_client_secret above for why raise_for_status is skipped.
    # nosemgrep: use-raise-for-status
    resp = requests.post(
        token_endpoint(tenant_id),
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": assertion,
            "scope": scope,
        },
        timeout=_TIMEOUT,
    )
    return _parse_token_response(resp)


def decode_jwt_claims(token: str) -> dict:
    """Best-effort decode of a JWT payload (no signature check).

    Used to inspect the `roles` claim during validation.
    """
    try:
        _header, payload, _sig = token.split(".")
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception as exc:
        return {"_decode_error": str(exc)}


# --- internals ---------------------------------------------------------------


def _build_client_assertion(
    *, tenant_id: str, client_id: str, private_key_pem: str, thumbprint_b64url: str
) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    # load_pem_private_key returns any key type, but the assertion below is
    # signed RS256 with PKCS1v15 padding, which only RSA keys support. Reject a
    # non-RSA key here: without this the failure surfaces as a TypeError or
    # AttributeError from inside cryptography, which reads like a bug in this
    # tool rather than the wrong key file being configured.
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GraphError(
            f"Certificate private key must be RSA, got {type(key).__name__}. "
            f"Entra certificate client assertions are signed with RS256, so "
            f"generate the app's certificate with an RSA key pair."
        )

    now = _dt.datetime.now(_dt.timezone.utc)
    header = {"alg": "RS256", "typ": "JWT", "x5t": thumbprint_b64url}
    claims = {
        "aud": token_endpoint(tenant_id),
        "iss": client_id,
        "sub": client_id,
        "jti": _secrets.token_urlsafe(16),
        "nbf": int(now.timestamp()),
        "exp": int((now + _dt.timedelta(minutes=10)).timestamp()),
    }
    signing_input = (
        _b64url(json.dumps(header).encode()) + b"." + _b64url(json.dumps(claims).encode())
    )
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _parse_token_response(resp: requests.Response) -> dict:
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text[:2000]}
    if resp.status_code != 200:
        raise GraphError(
            f"Token request failed ({resp.status_code}).",
            status=resp.status_code,
            body=body,
        )
    return body
