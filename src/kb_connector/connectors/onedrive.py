"""OneDrive connector — params, secret schema, auth types.

Handles the full connector surface for OneDrive managed connectors.
OneDrive crawling is hosted on SharePoint, so similar auth requirements apply.
"""

from __future__ import annotations

from kb_connector.connectors.base import ConfigField, ConnectorSpec
from kb_connector.interactive import SetupStep


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

    connector_type = "ONEDRIVE"
    provider = "microsoft"

    def setup_steps(self, config: dict) -> list[SetupStep]:
        return []  # OneDrive setup is driven directly by cli/setup.py

    def build_connector_params(self, config: dict, state: dict) -> dict:
        return build_connector_params(
            credential=config.get("credential", "cert"),
            tenant_id=config["tenant_id"],
            secret_arn=state["secret_arn"],
            acl=config.get("acl", False),
            cert_s3_bucket=state.get("cert_s3_bucket"),
            cert_s3_key=state.get("cert_s3_key"),
        )

    def build_secret_body(self, config: dict, state: dict) -> dict | None:
        return build_secret_body(
            credential=config.get("credential", "cert"),
            client_id=state["client_app_id"],
            client_secret=state.get("client_secret"),
            certificate_password=state.get("certificate_password"),
            private_key_b64_pkcs8=state.get("private_key_b64_pkcs8"),
        )

    def config_fields(self) -> list[ConfigField]:
        return [
            ConfigField("credential", default="cert", prompt="Credential mode (cert, client_secret, oauth2_refresh)"),
            ConfigField("acl", type=bool, default=False, prompt="Enable document-level ACL?"),
            ConfigField("crawl_personal_drives", type=bool, default=True, prompt="Crawl personal drives?"),
            ConfigField("crawl_shared_with_me", type=bool, default=False, prompt="Crawl shared-with-me items?"),
            ConfigField("inclusion_user_emails", type=list, required=False, prompt="Filter to specific user emails"),
        ]
