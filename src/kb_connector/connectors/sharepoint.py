"""SharePoint connector — params, secret schema, auth types.

Handles the full connector surface for SharePoint managed connectors:
  * connector parameters (connectorParameters JSON body)
  * secret body (Secrets Manager JSON for the connector)
  * auth type mapping (credential -> authType enum)
  * setup steps (Entra source-side + AWS-side)
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

    connector_type = "SHAREPOINT"
    provider = "microsoft"

    def setup_steps(self, config: dict) -> list[SetupStep]:
        return []  # SharePoint setup is driven directly by cli/setup.py

    def build_connector_params(self, config: dict, state: dict) -> dict:
        return build_connector_params(
            credential=config.get("credential", "cert"),
            tenant_id=config["tenant_id"],
            secret_arn=state["secret_arn"],
            acl=config.get("acl", False),
            site_urls=config.get("site_urls", []),
            cert_s3_bucket=state.get("cert_s3_bucket"),
            cert_s3_key=state.get("cert_s3_key"),
            crawl_files=config.get("crawl_files", True),
            crawl_pages=config.get("crawl_pages", True),
            filter_config=filter_config_from_config(config),
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
            ConfigField("site_urls", type=list, prompt="SharePoint site URLs"),
            ConfigField("sharepoint_host", required=False, prompt="SharePoint host (e.g. contoso.sharepoint.com)"),
            ConfigField("credential", default="cert", prompt="Credential mode (cert)"),
            ConfigField("acl", type=bool, default=False, prompt="Enable document-level ACL?"),
            ConfigField("sites_selected", type=bool, default=False, prompt="Use Sites.Selected (least-privilege)?"),
            ConfigField("crawl_files", type=bool, default=True, prompt="Crawl files?"),
            ConfigField("crawl_pages", type=bool, default=True, prompt="Crawl pages?"),
            # filterConfiguration. inclusion_item_paths is deliberately first and
            # carries a warning: it is the one filter key that changes the crawl
            # mode rather than narrowing the result set.
            ConfigField(
                "inclusion_item_paths", type=list, required=False,
                prompt="Inclusion item paths (full URLs; REPLACES the site_urls crawl)",
                warning=(
                    "inclusionItemPaths overrides site_urls: when set, the service "
                    "skips site-URL validation and crawls only these paths. A site "
                    "root listed here does not produce the same result as the same "
                    "site in site_urls."
                ),
            ),
            ConfigField("exclusion_item_paths", type=list, required=False,
                        prompt="Exclusion item paths (full URLs)"),
            ConfigField("inclusion_file_name_patterns", type=list, required=False,
                        prompt="Inclusion file name patterns (regex)"),
            ConfigField("exclusion_file_name_patterns", type=list, required=False,
                        prompt="Exclusion file name patterns (regex)"),
            ConfigField("inclusion_file_path", type=list, required=False,
                        prompt="Inclusion file path patterns (regex)"),
            ConfigField("exclusion_file_path", type=list, required=False,
                        prompt="Exclusion file path patterns (regex)"),
            ConfigField("modified_date_after", required=False,
                        prompt="Only crawl items modified after (ISO8601)"),
            ConfigField("modified_date_before", required=False,
                        prompt="Only crawl items modified before (ISO8601)"),
        ]
