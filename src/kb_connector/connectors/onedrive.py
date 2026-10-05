"""OneDrive connector — params, secret schema, auth types.

Handles the full connector surface for OneDrive managed connectors.
OneDrive crawling is hosted on SharePoint, so similar auth requirements apply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kb_connector.connectors.base import (
    BuildContext,
    ConnectorSpec,
    Field,
    MICROSOFT_FIELDS,
)

if TYPE_CHECKING:
    from kb_connector.core.config import ConnectorConfig


# --- Auth type mapping -------------------------------------------------------

# Maps our credential mode onto the bedrock-agent `authType` enum. The values
# are API constants, not secrets; bandit's B105 fires only because one dict key
# is spelled the same as a credential field. Keep the suppression comment bare:
# bandit reads anything after the test id as further test ids, so a trailing
# justification silently stops it applying.
_AUTH_TYPES = {  # nosec B105
    "cert": "ENTRA_APP_ID",
    "client_secret": "ENTRA_APP_ID",
    "oauth2_refresh": "OAUTH2",
}


def connector_auth_type(credential: str) -> str:
    """Map credential to OneDrive connector authType enum."""
    cred = credential.strip().lower()
    auth_type = _AUTH_TYPES.get(cred)
    if auth_type is None:
        valid = ", ".join(sorted(_AUTH_TYPES.keys()))
        raise ValueError(
            f"Credential {credential!r} is not valid for OneDrive. Valid: {valid}."
        )
    return auth_type


# --- Connector parameters builder --------------------------------------------


def build_connector_params(
    *,
    credential: str,
    tenant_id: str,
    secret_arn: str,
    acl: bool,
    cert_s3_bucket: str | None = None,
    cert_s3_key: str | None = None,
    crawl_personal_drives: bool = True,
    crawl_shared_with_me: bool = False,
    inclusion_user_emails: list[str] | None = None,
) -> dict:
    """Build the connectorParameters JSON for a OneDrive data source."""
    auth_type = connector_auth_type(credential)

    connection: dict = {
        "secretArn": secret_arn,
        "tenantId": tenant_id,
        "authType": auth_type,
    }
    if credential.strip().lower() == "cert":
        if not (cert_s3_bucket and cert_s3_key):
            raise ValueError("cert credential requires cert_s3_bucket and cert_s3_key.")
        connection["certificateS3Path"] = {
            "s3BucketName": cert_s3_bucket,
            "s3KeyName": cert_s3_key,
        }

    data_entity: dict = {
        "crawlPersonalDrives": crawl_personal_drives,
        "crawlSharedWithMe": crawl_shared_with_me,
    }
    if inclusion_user_emails:
        data_entity["inclusionUserEmailAddresses"] = inclusion_user_emails

    params: dict = {
        "type": "ONEDRIVE",
        "version": "1",
        "aclEnabled": acl,
        "crawlIdentities": acl,
        "connectionConfiguration": connection,
        "dataEntityConfiguration": data_entity,
    }
    return params


# --- Secret body builder -----------------------------------------------------


def build_secret_body(
    *,
    credential: str,
    client_id: str,
    client_secret: str | None = None,
    certificate_password: str | None = None,
    private_key_b64_pkcs8: str | None = None,
    refresh_token: str | None = None,
) -> dict:
    """Build the Secrets Manager secret JSON for a OneDrive connector."""
    cred = credential.strip().lower()

    if cred == "cert":
        if not certificate_password:
            raise ValueError("certificate_password required for cert credential.")
        if not client_secret:
            raise ValueError(
                "client_secret required for OneDrive cert (ACL verification path "
                "mints a Graph token with the client secret)."
            )
        body: dict = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "certificatePassword": certificate_password,
        }
        if private_key_b64_pkcs8:
            body["privateKey"] = private_key_b64_pkcs8
        return body

    if cred == "client_secret":
        if not client_secret:
            raise ValueError("client_secret required for client_secret credential.")
        return {"clientId": client_id, "clientSecret": client_secret}

    if cred == "oauth2_refresh":
        if not (client_secret and refresh_token):
            raise ValueError(
                "client_secret and refresh_token required for oauth2_refresh credential."
            )
        return {
            "clientId": client_id,
            "clientSecret": client_secret,
            "refreshToken": refresh_token,
        }

    raise ValueError(f"Unknown credential {credential!r} for OneDrive.")


# --- ConnectorSpec implementation --------------------------------------------


class OneDriveConnector(ConnectorSpec):
    """OneDrive managed connector spec."""

    type = "onedrive"
    api_type = "ONEDRIVE"
    provider = "microsoft"
    fields = MICROSOFT_FIELDS + (
        Field("credential", str, "Credential mode.", default="cert",
              choices=("cert", "client_secret", "oauth2_refresh"), ask=True),
        Field("acl", bool, "Document-level access control. Cannot be changed later.",
              default=False, ask=True),
        Field("crawl_personal_drives", bool, "Crawl users' personal drives.", default=True),
        Field("crawl_shared_with_me", bool, "Crawl items shared with each user.",
              default=False),
        Field("inclusion_user_emails", list, "Only crawl these users' drives.", ask=True),
    )

    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        credential = cfg.credential or self.field("credential").default
        uses_cert = credential.strip().lower() == "cert"
        return build_connector_params(
            credential=credential,
            tenant_id=cfg.tenant_id or "",
            secret_arn=ctx.secret_arn or "",
            acl=cfg.acl if ctx.acl is None else ctx.acl,
            cert_s3_bucket=ctx.cert_s3_bucket if uses_cert else None,
            cert_s3_key=ctx.cert_s3_key if uses_cert else None,
            crawl_personal_drives=self.value(cfg, "crawl_personal_drives"),
            crawl_shared_with_me=self.value(cfg, "crawl_shared_with_me"),
            inclusion_user_emails=self.value(cfg, "inclusion_user_emails"),
        )
