"""SharePoint connector — params, secret schema, auth types.

Handles the full connector surface for SharePoint managed connectors:
  * connector parameters (connectorParameters JSON body)
  * secret body (Secrets Manager JSON for the connector)
  * auth type mapping (credential -> authType enum)
  * setup steps (Entra source-side + AWS-side)
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
    "cert": "ENTRA_ID_APP_ONLY",
    "client_secret": "ENTRA_ID_APP_ONLY",
    "ropc": "OAUTH2_APP",
}


def connector_auth_type(credential: str) -> str:
    """Map credential to SharePoint connector authType enum."""
    cred = credential.strip().lower()
    auth_type = _AUTH_TYPES.get(cred)
    if auth_type is None:
        valid = ", ".join(sorted(_AUTH_TYPES.keys()))
        raise ValueError(
            f"Credential {credential!r} is not valid for SharePoint. Valid: {valid}."
        )
    return auth_type


# --- Connector parameters builder --------------------------------------------


def build_filter_config(
    *,
    inclusion_item_paths: list[str] | None = None,
    exclusion_item_paths: list[str] | None = None,
    inclusion_file_name_patterns: list[str] | None = None,
    exclusion_file_name_patterns: list[str] | None = None,
    inclusion_file_path: list[str] | None = None,
    exclusion_file_path: list[str] | None = None,
    modified_date_after: str | None = None,
    modified_date_before: str | None = None,
) -> dict:
    """Build the SharePoint `filterConfiguration` block, omitting empty keys.

    Field names follow the service's SharePointFilterConfiguration. Empty lists
    are dropped rather than sent: `inclusionItemPaths` in particular is not an
    inert filter when present, it changes which crawl path the connector takes,
    so an empty list must not be indistinguishable from an intended one.

    A note on `inclusionItemPaths`, because it surprises people. It does not
    narrow a `site_urls` crawl, it *replaces* it — the service skips site-URL
    validation entirely when the list is non-empty, and scopes the crawl to the
    paths given. Listing a site root here is therefore not equivalent to putting
    that site in `site_urls`; see KNOWN-LIMITATIONS.md.
    """
    out: dict = {}
    if inclusion_item_paths:
        out["inclusionItemPaths"] = list(inclusion_item_paths)
    if exclusion_item_paths:
        out["exclusionItemPaths"] = list(exclusion_item_paths)
    if inclusion_file_name_patterns:
        out["inclusionFileNamePatterns"] = list(inclusion_file_name_patterns)
    if exclusion_file_name_patterns:
        out["exclusionFileNamePatterns"] = list(exclusion_file_name_patterns)
    if inclusion_file_path:
        out["inclusionFilePath"] = list(inclusion_file_path)
    if exclusion_file_path:
        out["exclusionFilePath"] = list(exclusion_file_path)
    if modified_date_after:
        out["modifiedDateAfter"] = modified_date_after
    if modified_date_before:
        out["modifiedDateBefore"] = modified_date_before
    return out


def filter_config_from_config(config: dict) -> dict:
    """Map the connector's TOML keys onto `build_filter_config` arguments.

    Kept separate from the builder so that the ConnectorSpec path and the CLI
    setup path derive the filter from config identically. Two independent
    mappings would drift, and a field honored on one path but ignored on the
    other is invisible until an ingest crawls the wrong thing.
    """
    return build_filter_config(
        inclusion_item_paths=config.get("inclusion_item_paths"),
        exclusion_item_paths=config.get("exclusion_item_paths"),
        inclusion_file_name_patterns=config.get("inclusion_file_name_patterns"),
        exclusion_file_name_patterns=config.get("exclusion_file_name_patterns"),
        inclusion_file_path=config.get("inclusion_file_path"),
        exclusion_file_path=config.get("exclusion_file_path"),
        modified_date_after=config.get("modified_date_after"),
        modified_date_before=config.get("modified_date_before"),
    )


def build_connector_params(
    *,
    credential: str,
    tenant_id: str,
    secret_arn: str,
    acl: bool,
    site_urls: list[str],
    cert_s3_bucket: str | None = None,
    cert_s3_key: str | None = None,
    crawl_files: bool = True,
    crawl_pages: bool = True,
    filter_config: dict | None = None,
) -> dict:
    """Build the connectorParameters JSON for a SharePoint data source."""
    auth_type = connector_auth_type(credential)

    connection: dict = {
        "secretArn": secret_arn,
        "tenantId": tenant_id,
        "authType": auth_type,
    }
    # Only 'cert' populates certificateS3Path. The Bedrock SharePoint connector
    # requires certificateS3Path for app-only auth, so 'client_secret' produces
    # a body the service rejects; setup rejects that combination before reaching
    # this builder. This branch stays credential-scoped: the builder doesn't
    # invent cert material it wasn't given.
    if credential.strip().lower() == "cert":
        if not (cert_s3_bucket and cert_s3_key):
            raise ValueError("cert credential requires cert_s3_bucket and cert_s3_key.")
        connection["certificateS3Path"] = {
            "s3BucketName": cert_s3_bucket,
            "s3KeyName": cert_s3_key,
        }

    params: dict = {
        "type": "SHAREPOINT",
        "version": "1",
        "aclEnabled": acl,
        "crawlIdentities": acl,
        "connectionConfiguration": connection,
        "dataEntityConfiguration": {
            "crawlFiles": crawl_files,
            "crawlPages": crawl_pages,
            "siteUrls": site_urls,
        },
    }
    if filter_config:
        params["filterConfiguration"] = filter_config
    return params


# --- Secret body builder -----------------------------------------------------


def build_secret_body(
    *,
    credential: str,
    client_id: str,
    client_secret: str | None = None,
    certificate_password: str | None = None,
    private_key_b64_pkcs8: str | None = None,
    admin_username: str | None = None,
    admin_password: str | None = None,
) -> dict:
    """Build the Secrets Manager secret JSON for a SharePoint connector."""
    cred = credential.strip().lower()

    if cred == "cert":
        if not certificate_password:
            raise ValueError("certificate_password required for cert credential.")
        body: dict = {"clientId": client_id, "certificatePassword": certificate_password}
        if private_key_b64_pkcs8:
            body["privateKey"] = private_key_b64_pkcs8
        if client_secret:
            body["clientSecret"] = client_secret
        return body

    if cred == "client_secret":
        if not client_secret:
            raise ValueError("client_secret required for client_secret credential.")
        return {
            "clientId": client_id,
            "clientSecret": client_secret,
            "entraIdAppOnlyWithClientSecret": True,
        }

    if cred == "ropc":
        if not (client_secret and admin_username and admin_password):
            raise ValueError(
                "client_secret, admin_username, and admin_password required for ropc."
            )
        return {
            "clientId": client_id,
            "clientSecret": client_secret,
            "userName": admin_username,
            "password": admin_password,
        }

    raise ValueError(f"Unknown credential {credential!r} for SharePoint.")


# --- ConnectorSpec implementation --------------------------------------------


class SharePointConnector(ConnectorSpec):
    """SharePoint managed connector spec."""

    type = "sharepoint"
    api_type = "SHAREPOINT"
    provider = "microsoft"
    fields = MICROSOFT_FIELDS + (
        Field("credential", str, "Credential mode. Only cert is automated.",
              default="cert", choices=("cert", "client_secret", "ropc")),
        Field("acl", bool, "Document-level access control. Cannot be changed later.",
              default=False, ask=True),
        Field("site_urls", list, "Sites to crawl, as /sites/<name> URLs.",
              required=True, ask=True),
        Field("sharepoint_host", str, "Tenant host, for example contoso.sharepoint.com.",
              in_params=False, ask=True),
        Field("sharepoint_domain", str,
              "Quick target: tenant root URL the Quick console asks for.", in_params=False),
        Field("crawl_files", bool, "Crawl files.", default=True),
        Field("crawl_pages", bool, "Crawl pages.", default=True),
        Field("inclusion_item_paths", list,
              "Paths to crawl. Replaces the site_urls crawl rather than narrowing it."),
        Field("exclusion_item_paths", list, "Paths to skip."),
        Field("inclusion_file_name_patterns", list, "File name patterns to include (regex)."),
        Field("exclusion_file_name_patterns", list, "File name patterns to skip (regex)."),
        Field("inclusion_file_path", list, "File path patterns to include (regex)."),
        Field("exclusion_file_path", list, "File path patterns to skip (regex)."),
        Field("modified_date_after", str, "Only items modified after this ISO 8601 time."),
        Field("modified_date_before", str, "Only items modified before this ISO 8601 time."),
    )

    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        credential = cfg.credential or self.field("credential").default
        uses_cert = credential.strip().lower() == "cert"
        return build_connector_params(
            credential=credential,
            tenant_id=cfg.tenant_id or "",
            secret_arn=ctx.secret_arn or "",
            acl=cfg.acl if ctx.acl is None else ctx.acl,
            site_urls=self.value(cfg, "site_urls") or [],
            cert_s3_bucket=ctx.cert_s3_bucket if uses_cert else None,
            cert_s3_key=ctx.cert_s3_key if uses_cert else None,
            crawl_files=self.value(cfg, "crawl_files"),
            crawl_pages=self.value(cfg, "crawl_pages"),
            filter_config=filter_config_from_config(cfg.raw),
        )
