"""Google Drive connector — params + guided setup steps.

Google Drive uses Google Workspace OAuth2 or service account authentication.
Stage 1 is guided; Stage 2 is automated.

Shape validated against the live bedrock-agent API:
  * type=GOOGLEDRIVE, version=1
  * connectionConfiguration.{secretArn, authType (OAUTH2/SERVICE_ACCOUNT)}
    (no hostUrl)
  * aclEnabled (top-level) — OAUTH2 is NOT supported with ACL
    (SERVICE_ACCOUNT only)
  * dataEntityConfiguration.{crawlMyDrive, crawlSharedWithMe,
    crawlSharedDrives}
  * filterConfiguration.{inclusion/exclusionSharedDriveIds, inclusion/
    exclusionMimeTypes, inclusionFolderIds, inclusionFileIds,
    inclusionSharedFolderIds, inclusionSharedFileIds, modifiedDateBefore,
    modifiedDateAfter}  (some OAUTH2-only)
"""

from __future__ import annotations

from kb_connector.connectors.base import ConfigField, ConnectorSpec
from kb_connector.interactive import SetupStep


_AUTH_TYPES = {
    "oauth2": "OAUTH2",
    "service_account": "SERVICE_ACCOUNT",
}

_DATA_ENTITY_KEYS = {
    "crawl_my_drive": "crawlMyDrive",
    "crawl_shared_with_me": "crawlSharedWithMe",
    "crawl_shared_drives": "crawlSharedDrives",
}


def connector_auth_type(credential: str) -> str:
    """Map credential to Google Drive connector authType enum."""
    cred = credential.strip().lower()
    auth_type = _AUTH_TYPES.get(cred)
    if auth_type is None:
        valid = ", ".join(sorted(_AUTH_TYPES.keys()))
        raise ValueError(f"Credential {credential!r} not valid for Google Drive. Valid: {valid}.")
    return auth_type


def build_connector_params(
    *,
    credential: str = "oauth2",
    secret_arn: str,
    acl: bool = False,
    shared_drive_ids: list[str] | None = None,
    exclusion_shared_drive_ids: list[str] | None = None,
    inclusion_mime_types: list[str] | None = None,
    exclusion_mime_types: list[str] | None = None,
    inclusion_folder_ids: list[str] | None = None,
    inclusion_file_ids: list[str] | None = None,
    data_entities: dict | None = None,
) -> dict:
    """Build the connectorParameters JSON for a Google Drive data source."""
    auth_type = connector_auth_type(credential)

    if acl and auth_type == "OAUTH2":
        raise ValueError(
            "OAUTH2 is not supported for ACL-enabled Google Drive. Use "
            "SERVICE_ACCOUNT or disable ACL."
        )

    params: dict = {
        "type": "GOOGLEDRIVE",
        "version": "1",
        "connectionConfiguration": {
            "secretArn": secret_arn,
            "authType": auth_type,
        },
    }
    if acl:
        params["aclEnabled"] = True

    # dataEntityConfiguration is REQUIRED by the service (same as Confluence).
    # Default to My Drive + shared-with-me (matching the doc example).
    if data_entities is None:
        data_entities = {
            "crawl_my_drive": True,
            "crawl_shared_with_me": True,
            "crawl_shared_drives": False,
        }
    de: dict = {}
    for friendly, value in data_entities.items():
        key = _DATA_ENTITY_KEYS.get(friendly, friendly)
        if value is not None:
            de[key] = value
    if de:
        params["dataEntityConfiguration"] = de

    filter_config: dict = {}
    if shared_drive_ids:
        filter_config["inclusionSharedDriveIds"] = shared_drive_ids
    if exclusion_shared_drive_ids:
        filter_config["exclusionSharedDriveIds"] = exclusion_shared_drive_ids
    if inclusion_mime_types:
        filter_config["inclusionMimeTypes"] = inclusion_mime_types
    if exclusion_mime_types:
        filter_config["exclusionMimeTypes"] = exclusion_mime_types
    if inclusion_folder_ids:
        filter_config["inclusionFolderIds"] = inclusion_folder_ids
    if inclusion_file_ids:
        filter_config["inclusionFileIds"] = inclusion_file_ids
    if filter_config:
        params["filterConfiguration"] = filter_config

    return params


def build_secret_body(
    *,
    credential: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    refresh_token: str | None = None,
    service_account_json: str | None = None,
) -> dict:
    """Build the Secrets Manager secret JSON for a Google Drive connector."""
    cred = credential.strip().lower()

    if cred == "oauth2":
        if not (client_id and client_secret and refresh_token):
            raise ValueError(
                "client_id, client_secret, and refresh_token required for oauth2."
            )
        return {
            "clientId": client_id,
            "clientSecret": client_secret,
            "refreshToken": refresh_token,
        }

    if cred == "service_account":
        if not service_account_json:
            raise ValueError("service_account_json required for service_account credential.")
        return {"serviceAccountCredentials": service_account_json}

    raise ValueError(f"Unknown credential {credential!r} for Google Drive.")


class GoogleDriveConnector(ConnectorSpec):
    """Google Drive managed connector spec."""

    connector_type = "GOOGLEDRIVE"
    provider = "google"

    def setup_steps(self, config: dict) -> list[SetupStep]:
        """Google Drive setup is guided: user creates OAuth/SA in GCP."""
        credential = config.get("credential", "oauth2")
        if credential == "service_account":
            return [
                SetupStep(
                    name="create-service-account",
                    description="Create a service account in Google Cloud Console",
                    mode="guided",
                    execute=_guide_create_service_account,
                    validate=_validate_service_account,
                ),
            ]
        return [
            SetupStep(
                name="create-oauth-client",
                description="Create an OAuth 2.0 client in Google Cloud Console",
                mode="guided",
                execute=_guide_create_oauth_client,
                validate=_validate_oauth_credentials,
            ),
        ]

    def build_connector_params(self, config: dict, state: dict) -> dict:
        return build_connector_params(
            credential=config.get("credential", "oauth2"),
            secret_arn=state["secret_arn"],
            acl=config.get("acl", False),
            shared_drive_ids=config.get("shared_drives") or config.get("shared_drive_ids"),
            exclusion_shared_drive_ids=config.get("exclusion_shared_drive_ids"),
            inclusion_mime_types=config.get("inclusion_mime_types"),
            exclusion_mime_types=config.get("exclusion_mime_types"),
            inclusion_folder_ids=config.get("inclusion_folder_ids"),
            inclusion_file_ids=config.get("inclusion_file_ids"),
            data_entities=config.get("data_entities"),
        )

    def build_secret_body(self, config: dict, state: dict) -> dict | None:
        return build_secret_body(
            credential=config.get("credential", "oauth2"),
            client_id=state.get("client_id"),
            client_secret=state.get("client_secret"),
            refresh_token=state.get("refresh_token"),
            service_account_json=state.get("service_account_json"),
        )

    def config_fields(self) -> list[ConfigField]:
        return [
            ConfigField("credential", default="oauth2",
                        prompt="Credential mode (oauth2, service_account)"),
            ConfigField("acl", type=bool, default=False, prompt="Enable document-level ACL?"),
            ConfigField("shared_drives", type=list, required=False,
                        prompt="Shared Drive IDs to include (blank for all)"),
        ]


# --- Guided setup helpers ----------------------------------------------------


def _guide_create_oauth_client(config: dict) -> None:
    """Print instructions for creating a Google OAuth 2.0 client."""
    print("""
  ┌─────────────────────────────────────────────────────────────┐
  │  Google Drive OAuth 2.0 Setup (Guided)                      │
  ├─────────────────────────────────────────────────────────────┤
  │  1. console.cloud.google.com/apis/credentials               │
  │  2. Create OAuth 2.0 Client ID (Web application)            │
  │  3. Enable the Google Drive API                             │
  │  4. Configure consent screen, add drive.readonly scope      │
  │  5. Obtain a refresh token (oauthplayground)                │
  │  6. Collect: Client ID, Client Secret, Refresh Token        │
  │  Note: ACL-enabled Drive requires SERVICE_ACCOUNT, not OAUTH2│
  └─────────────────────────────────────────────────────────────┘
""")


def _guide_create_service_account(config: dict) -> None:
    """Print instructions for creating a Google service account."""
    print("""
  ┌─────────────────────────────────────────────────────────────┐
  │  Google Drive Service Account Setup (Guided)                │
  ├─────────────────────────────────────────────────────────────┤
  │  1. console.cloud.google.com/iam-admin/serviceaccounts      │
  │  2. Create a service account + JSON key                     │
  │  3. Enable the Google Drive API                             │
  │  4. If Workspace: enable domain-wide delegation             │
  │     (add SA client ID with drive.readonly scope in Admin)   │
  │  5. Share target Drives/folders with the SA email           │
  │  6. Collect: the JSON key file content                      │
  └─────────────────────────────────────────────────────────────┘
""")


def _validate_oauth_credentials(config: dict) -> bool:
    """Validate OAuth credentials are present."""
    return bool(
        config.get("client_id")
        and config.get("client_secret")
        and config.get("refresh_token")
    )


def _validate_service_account(config: dict) -> bool:
    """Validate service account JSON is present."""
    return bool(config.get("service_account_json"))
