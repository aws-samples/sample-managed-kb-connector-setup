"""Confluence connector — params + guided setup steps.

Confluence uses Atlassian-hosted OAuth2 or Basic (API token) authentication.
Stage 1 is guided; Stage 2 is automated.

Shape validated against the live bedrock-agent API:
  * type=CONFLUENCE, version=1
  * connectionConfiguration.{secretArn, type (SAAS/SERVER/DATA_CENTER),
    authType (OAUTH2/BASIC), hostUrl}
  * aclEnabled (top-level) — OAUTH2 is NOT supported with ACL (BASIC only)
  * dataEntityConfiguration.{crawlPage, crawlBlog, crawlPageAttachment,
    crawlBlogAttachment, crawlArchivedSpace, crawlArchivedPage,
    crawlPersonalSpace}
  * filterConfiguration.{inclusion/exclusionSpaceKeys, inclusion/
    exclusionSpaceUrls, inclusion/exclusionMimeTypes, inclusionPageTitles,
    inclusionBlogPostTitles, inclusionAttachmentTitles}
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kb_connector.connectors.base import BuildContext, ConnectorSpec, Field

if TYPE_CHECKING:
    from kb_connector.core.config import ConnectorConfig

from kb_connector.interactive import SetupStep


# Auth type mapping. The service value for basic auth is "BASIC" (not "BASIC_AUTH").
_AUTH_TYPES = {
    "oauth2": "OAUTH2",
    "basic": "BASIC",
    "basic_auth": "BASIC",  # accept the friendlier alias
}

_DATA_ENTITY_KEYS = {
    "crawl_page": "crawlPage",
    "crawl_blog": "crawlBlog",
    "crawl_page_attachment": "crawlPageAttachment",
    "crawl_blog_attachment": "crawlBlogAttachment",
    "crawl_archived_space": "crawlArchivedSpace",
    "crawl_archived_page": "crawlArchivedPage",
    "crawl_personal_space": "crawlPersonalSpace",
}


def connector_auth_type(credential: str) -> str:
    """Map credential to Confluence connector authType enum."""
    cred = credential.strip().lower()
    auth_type = _AUTH_TYPES.get(cred)
    if auth_type is None:
        valid = "oauth2, basic"
        raise ValueError(f"Credential {credential!r} not valid for Confluence. Valid: {valid}.")
    return auth_type


def build_connector_params(
    *,
    host_url: str,
    credential: str = "oauth2",
    secret_arn: str,
    acl: bool = False,
    hosting_type: str = "SAAS",
    space_keys: list[str] | None = None,
    exclusion_space_keys: list[str] | None = None,
    inclusion_mime_types: list[str] | None = None,
    exclusion_mime_types: list[str] | None = None,
    data_entities: dict | None = None,
) -> dict:
    """Build the connectorParameters JSON for a Confluence data source.

    `data_entities` is a dict of friendly keys (crawl_page, crawl_blog, ...)
    to booleans; only the provided ones are sent.
    """
    auth_type = connector_auth_type(credential)

    if acl and auth_type == "OAUTH2":
        raise ValueError(
            "OAUTH2 is not supported for ACL-enabled Confluence. Use BASIC auth "
            "or disable ACL."
        )

    params: dict = {
        "type": "CONFLUENCE",
        "version": "1",
        "connectionConfiguration": {
            "secretArn": secret_arn,
            "type": hosting_type,
            "authType": auth_type,
            "hostUrl": host_url,
        },
    }
    if acl:
        params["aclEnabled"] = True

    # dataEntityConfiguration is required by the service (CreateDataSource fails
    # with "dataEntityConfiguration ... must not be null" if omitted). Default
    # to crawling pages + blogs + attachments.
    if data_entities is None:
        data_entities = {
            "crawl_page": True,
            "crawl_blog": True,
            "crawl_page_attachment": True,
            "crawl_blog_attachment": True,
        }
    de: dict = {}
    for friendly, value in data_entities.items():
        key = _DATA_ENTITY_KEYS.get(friendly, friendly)
        if value is not None:
            de[key] = value
    if de:
        params["dataEntityConfiguration"] = de

    filter_config: dict = {}
    if space_keys:
        filter_config["inclusionSpaceKeys"] = space_keys
    if exclusion_space_keys:
        filter_config["exclusionSpaceKeys"] = exclusion_space_keys
    if inclusion_mime_types:
        filter_config["inclusionMimeTypes"] = inclusion_mime_types
    if exclusion_mime_types:
        filter_config["exclusionMimeTypes"] = exclusion_mime_types
    if filter_config:
        params["filterConfiguration"] = filter_config

    return params


def build_secret_body(
    *,
    credential: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    access_token: str | None = None,
    refresh_token: str | None = None,
    username: str | None = None,
    api_token: str | None = None,
) -> dict:
    """Build the Secrets Manager secret JSON for a Confluence connector."""
    cred = credential.strip().lower()

    if cred == "oauth2":
        if not (client_id and client_secret):
            raise ValueError("client_id and client_secret required for oauth2.")
        body: dict = {"clientId": client_id, "clientSecret": client_secret}
        if access_token:
            body["accessToken"] = access_token
        if refresh_token:
            body["refreshToken"] = refresh_token
        return body

    if cred in ("basic", "basic_auth"):
        if not (username and api_token):
            raise ValueError("username and api_token required for basic auth.")
        return {"username": username, "password": api_token}

    raise ValueError(f"Unknown credential {credential!r} for Confluence.")


class ConfluenceConnector(ConnectorSpec):
    """Confluence managed connector spec."""

    type = "confluence"
    api_type = "CONFLUENCE"
    provider = "atlassian"
    fields = (
        Field("host_url", str, "Confluence URL, for example https://company.atlassian.net.",
              required=True, ask=True),
        Field("credential", str, "Credential mode. ACL requires basic.", default="oauth2",
              choices=("oauth2", "basic", "basic_auth"), ask=True),
        Field("hosting_type", str, "Hosting type.", default="SAAS"),
        Field("acl", bool, "Document-level access control. Cannot be changed later.",
              default=False, ask=True),
        Field("space_keys", list, "Only crawl these spaces.", ask=True),
        Field("exclusion_space_keys", list, "Skip these spaces."),
        Field("inclusion_mime_types", list, "Only crawl these MIME types."),
        Field("exclusion_mime_types", list, "Skip these MIME types."),
        Field("data_entities", dict,
              "Content types to crawl, for example { crawl_page = true, crawl_blog = false }."),
    )

    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        return build_connector_params(
            host_url=self.value(cfg, "host_url") or "",
            credential=cfg.credential or self.field("credential").default,
            secret_arn=ctx.secret_arn or "",
            acl=cfg.acl if ctx.acl is None else ctx.acl,
            hosting_type=self.value(cfg, "hosting_type"),
            space_keys=self.value(cfg, "space_keys"),
            exclusion_space_keys=self.value(cfg, "exclusion_space_keys"),
            inclusion_mime_types=self.value(cfg, "inclusion_mime_types"),
            exclusion_mime_types=self.value(cfg, "exclusion_mime_types"),
            data_entities=self.value(cfg, "data_entities"),
        )

    def setup_steps(self, config: dict) -> list[SetupStep]:
        """Confluence setup is guided: user creates OAuth app in Atlassian."""
        return [
            SetupStep(
                name="create-oauth-app",
                # The strings inside the parens below are an intentional implicit
                # concat to wrap the description across two lines, not a missing
                # comma in a list.
                # nosemgrep: string-concat-in-list
                description=(
                    "Create an OAuth 2.0 app in Atlassian Developer Console "
                    "(developer.atlassian.com/console/myapps)"
                ),
                mode="guided",
                execute=_guide_create_oauth_app,
                validate=_validate_oauth_credentials,
            ),
        ]



# --- Guided setup helpers ----------------------------------------------------


def _guide_create_oauth_app(config: dict) -> None:
    """Print instructions for creating the Atlassian OAuth app."""
    print("""
  ┌─────────────────────────────────────────────────────────────┐
  │  Confluence OAuth 2.0 Setup (Guided)                        │
  ├─────────────────────────────────────────────────────────────┤
  │  1. Go to: developer.atlassian.com/console/myapps           │
  │  2. Click "Create" -> "OAuth 2.0 integration"               │
  │  3. Add Confluence API permissions:                         │
  │     • read:confluence-content.all                            │
  │     • read:confluence-space.summary                          │
  │  4. Set callback URL: https://localhost/callback            │
  │  5. Copy the Client ID and Client Secret                    │
  │  Note: ACL-enabled Confluence requires BASIC auth, not OAUTH2│
  └─────────────────────────────────────────────────────────────┘
""")


def _validate_oauth_credentials(config: dict) -> bool:
    """Validate that OAuth credentials are present."""
    return bool(config.get("client_id") and config.get("client_secret"))
