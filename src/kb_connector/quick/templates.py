"""Request bodies for the Amazon Quick data source and knowledge base.

Pure functions over the resolved connector config. The knowledge base templates
copy the shape of the templates the Quick console writes for SharePoint
(SHAREPOINTV3) and OneDrive (ONEDRIVEV3). Neither carries
`connectionConfiguration`: the template documented in the model with
`connectionConfiguration.tenantId` fails with "Data source validation failed."
The data source holds the tenant and app.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from kb_connector.connectors import get_spec
from kb_connector.connectors.sharepoint import filter_config_from_config
from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import ConfigError

AUTH_TYPE = "TWO_LEGGED_OAUTH"
MAX_FILE_SIZE_MB = "500"
DELETION_PROTECTION = {
    "enableDeletionProtection": False,
    "deletionProtectionThreshold": "15",
}


def _value(cfg: ConnectorConfig, key: str) -> Any:
    spec = get_spec(cfg.type)
    if spec is None:
        raise ConfigError(f"Unknown connector type {cfg.type!r}.")
    return spec.value(cfg, key)


def _is_sharepoint(cfg: ConnectorConfig) -> bool:
    if cfg.type == "sharepoint":
        return True
    if cfg.type == "onedrive":
        return False
    raise ConfigError(
        f"target = \"quick\" supports sharepoint and onedrive connectors, not "
        f"{cfg.type!r}."
    )


def _host(value: Any, *, require_https: bool) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if "://" not in raw:
        if require_https:
            return None
        return raw.split("/", 1)[0] or None
    parsed = urlparse(raw)
    if require_https and parsed.scheme != "https":
        return None
    return parsed.netloc or None


def sharepoint_domain(cfg: ConnectorConfig) -> str | None:
    """The SharePoint host Quick expects, for example `contoso.sharepoint.com`.

    Taken from `sharepoint_domain` (scheme and path stripped), else
    `sharepoint_host`, else the host of the first https site URL. Returns None
    rather than guessing when none of them yields a host.
    """
    domain = _host(cfg.get("sharepoint_domain"), require_https=False)
    if domain:
        return domain
    host = _host(cfg.get("sharepoint_host"), require_https=False)
    if host:
        return host
    site_urls = cfg.get("site_urls")
    if isinstance(site_urls, list) and site_urls:
        return _host(site_urls[0], require_https=True)
    return None


def quick_acl(cfg: ConnectorConfig) -> bool:
    """Whether the knowledge base enforces document ACLs.

    OneDrive always does: Quick crawls OneDrive per user, so setup turns ACL on
    for it whatever the config says.
    """
    if not _is_sharepoint(cfg):
        return True
    return bool(cfg.acl)


def data_source_request(
    cfg: ConnectorConfig, *, tenant_id: str, client_id: str
) -> tuple[str, dict]:
    """The CreateDataSource `Type` and `DataSourceParameters`."""
    common = {"TenantId": tenant_id, "ClientId": client_id, "AuthType": AUTH_TYPE}
    if not _is_sharepoint(cfg):
        return "ONE_DRIVE", {"OneDriveParameters": common}
    domain = sharepoint_domain(cfg)
    if not domain:
        raise ConfigError(
            f"Connector {cfg.name!r} has no SharePoint domain. Set "
            f"`sharepoint_domain` (for example \"contoso.sharepoint.com\") or "
            f"give https `site_urls`."
        )
    return "SHAREPOINT", {"SharePointParameters": {"SharePointDomain": domain, **common}}


def _sharepoint_template(cfg: ConnectorConfig) -> dict:
    site_urls = cfg.get("site_urls")
    if not isinstance(site_urls, list) or not site_urls:
        raise ConfigError(
            f"Connector {cfg.name!r} has no site_urls. The Quick SharePoint "
            f"knowledge base needs at least one site to crawl."
        )
    sites = [str(url) for url in site_urls]
    acl = quick_acl(cfg)
    filters: dict = {"maxFileSizeInMegaBytes": MAX_FILE_SIZE_MB}
    filters.update(filter_config_from_config(cfg.raw))
    # The console sets inclusionItemPaths to the site URLs.
    filters.setdefault("inclusionItemPaths", list(sites))
    return {
        "type": "SHAREPOINTV3",
        "crawlIdentities": acl,
        "selectedFiles": [],
        "dataEntityConfiguration": {
            "siteUrls": sites,
            "crawlPages": bool(_value(cfg, "crawl_pages")),
            "crawlFiles": bool(_value(cfg, "crawl_files")),
        },
        "accessControlConfiguration": {"crawlAcl": acl},
        "deletionProtectionConfiguration": dict(DELETION_PROTECTION),
        "filterConfiguration": filters,
    }


def _onedrive_template(cfg: ConnectorConfig) -> dict:
    return {
        "type": "ONEDRIVEV3",
        "authType": AUTH_TYPE,
        "crawlIdentities": True,
        "dataEntityConfiguration": {
            "crawlPersonalDrives": bool(_value(cfg, "crawl_personal_drives")),
            "crawlSharedWithMe": bool(_value(cfg, "crawl_shared_with_me")),
            # OneNote cannot be crawled with app-only access.
            "crawlOneNoteNotebooks": False,
        },
        "accessControlConfiguration": {"crawlAcl": True},
        "deletionProtectionConfiguration": dict(DELETION_PROTECTION),
        # The filter keys and empty lists the console writes.
        "filterConfiguration": {
            "maxFileSizeInMegaBytes": MAX_FILE_SIZE_MB,
            "includeMimeTypes": [],
            "excludeMimeTypes": [],
            "inclusionDriveItems": [],
            "exclusionDriveItems": [],
            "inclusionSharedDriveIds": [],
            "exclusionSharedDriveIds": [],
        },
    }


def knowledge_base_template(cfg: ConnectorConfig) -> dict:
    """The `KnowledgeBaseConfiguration.templateConfiguration.template` body."""
    if _is_sharepoint(cfg):
        return _sharepoint_template(cfg)
    return _onedrive_template(cfg)


def ignored_keys(cfg: ConnectorConfig) -> list[str]:
    """Config keys set on this connector that the Quick template has no field for."""
    if cfg.type == "onedrive" and cfg.get("inclusion_user_emails"):
        return ["inclusion_user_emails"]
    return []
