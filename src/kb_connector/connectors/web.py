"""Web crawler connector — seeds, sitemap, crawl configuration.

The web connector supports multiple auth modes:
  * NO_AUTH — public websites, no credentials needed
  * BASIC_AUTH — username/password in Secrets Manager

Stage 1: None for NO_AUTH; secret setup for BASIC_AUTH.
Stage 2: Always automated (KB + DS creation with web crawl config).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kb_connector.connectors.base import (
    BuildContext,
    ConnectorSpec,
    Field,
    MAX_FILE_SIZE_HELP,
    check_max_file_size,
)

if TYPE_CHECKING:
    from kb_connector.core.config import ConnectorConfig
    from kb_connector.core.overrides import RequestOverrides


# Auth type mapping
_AUTH_TYPES = {
    "no_auth": "NO_AUTH",
    "basic_auth": "BASIC_AUTH",
}

# Valid crawlConfiguration.syncScope values accepted by the Bedrock web
# connector. Validated client-side so a bad value (e.g. the plausible-but-wrong
# "HOST_ONLY") fails instantly instead of creating a data source that the API
# rejects into a FAILED terminal state.
_SYNC_SCOPES = {
    "PATH_SPECIFIC",
    "SUB_DOMAINS",
    "ALL_DOMAINS",
    "DOMAINS_ONLY",
}


def connector_auth_type(auth_mode: str) -> str:
    """Map auth_mode to Web connector authType enum."""
    mode = auth_mode.strip().lower()
    auth_type = _AUTH_TYPES.get(mode)
    if auth_type is None:
        valid = ", ".join(sorted(_AUTH_TYPES.keys()))
        raise ValueError(f"Auth mode {auth_mode!r} not valid for Web. Valid: {valid}.")
    return auth_type


def _validate_sync_scope(sync_scope: str) -> str:
    """Validate syncScope against the connector's enum before the API call."""
    normalized = sync_scope.strip().upper()
    if normalized not in _SYNC_SCOPES:
        valid = ", ".join(sorted(_SYNC_SCOPES))
        raise ValueError(
            f"sync_scope {sync_scope!r} is not valid for the Web connector. "
            f"Valid values: {valid}."
        )
    return normalized


# Hosts that should never be crawl targets. The tool itself never fetches these
# URLs — the Bedrock managed crawler does, from AWS's own network — so this is
# not a classic SSRF against the caller. It is still worth blocking:
#
#  * Link-local (169.254.0.0/16) covers the instance metadata endpoint.
#  * Loopback and private ranges are not reachable from the managed crawler, so
#    a config naming them is a mistake that would otherwise surface much later
#    as an opaque, wholly-failed ingestion.
#
# Whatever the crawler does reach is chunked, embedded, and returned by
# Retrieve, so a crawl target is also a data path into the knowledge base.
_BLOCKED_URL_SCHEMES_HINT = "http, https"


def _validate_crawl_url(url: str, *, field_name: str) -> str:
    """Validate a single seed or sitemap URL. Returns it unchanged.

    Raises ValueError for a non-http(s) scheme, a missing host, or a host in a
    range the managed crawler cannot legitimately reach.
    """
    import ipaddress
    from urllib.parse import urlparse

    raw = (url or "").strip()
    if not raw:
        raise ValueError(f"{field_name} contains an empty URL.")

    parsed = urlparse(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"{field_name} entry {raw!r} uses scheme {parsed.scheme or '(none)'!r}. "
            f"The Web connector crawls over {_BLOCKED_URL_SCHEMES_HINT} only."
        )

    host = (parsed.hostname or "").strip()
    if not host:
        raise ValueError(
            f"{field_name} entry {raw!r} has no hostname. Expected an absolute "
            f"URL like https://example.com/docs."
        )

    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(".localhost"):
        raise ValueError(
            f"{field_name} entry {raw!r} points at localhost. The crawl runs in "
            f"the Bedrock service, not on this machine, so a loopback address "
            f"can never be reached."
        )

    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return raw  # a hostname; DNS resolution is the service's business

    # `is_link_local`, `is_loopback`, `is_private`, `is_reserved` and
    # `is_multicast` are properties on ipaddress.IPv4Address / IPv6Address, not
    # methods, so reading them without parentheses is correct and returns a real
    # bool. Static analyzers that cannot distinguish a property from a bound
    # method read these as always-truthy; they are not. Verify with:
    #   ipaddress.ip_address("203.0.113.1").is_private    -> False
    #   ipaddress.ip_address("127.0.0.1").is_private      -> True
    # nosemgrep: is-function-without-parentheses
    if ip.is_link_local:
        raise ValueError(
            f"{field_name} entry {raw!r} is a link-local address "
            f"({ip}). This range includes the cloud instance metadata "
            f"endpoint and is never a valid crawl target."
        )
    # nosemgrep: is-function-without-parentheses
    if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_multicast:
        raise ValueError(
            f"{field_name} entry {raw!r} is a non-routable address ({ip}). "
            f"The Bedrock managed crawler reaches targets over the public "
            f"internet, so this address cannot be crawled. Use a publicly "
            f"resolvable hostname."
        )
    return raw


def validate_crawl_urls(
    urls: list[str] | None, *, field_name: str
) -> list[str] | None:
    """Validate every URL in a seed or sitemap list, preserving order."""
    if not urls:
        return urls
    return [_validate_crawl_url(u, field_name=field_name) for u in urls]


def build_connector_params(
    *,
    seed_urls: list[str] | None = None,
    auth_mode: str = "no_auth",
    secret_arn: str | None = None,
    sitemap_urls: list[str] | None = None,
    crawl_depth: int | None = None,
    max_links_per_url: int | None = None,
    max_crawled_urls_per_minute: int | None = None,
    sync_scope: str | None = None,
    crawl_attachments: bool = False,
    max_file_size_mb: int | None = None,
    inclusion_filters: list[str] | None = None,
    exclusion_filters: list[str] | None = None,
) -> dict:
    """Build the connectorParameters JSON for a Web data source.

    Shape validated against the live bedrock-agent API: seedUrls, siteMapUrls,
    authType, and secretArn all live inside connectionConfiguration.
    crawlConfiguration and filterConfiguration are siblings.
    """
    auth_type = connector_auth_type(auth_mode)

    if not seed_urls and not sitemap_urls:
        raise ValueError("Web connector requires seed_urls or sitemap_urls.")

    # Validated client-side for the same reason as sync_scope: fail now with a
    # specific message rather than creating a data source whose crawl fails
    # opaquely later. Crawl targets also determine what content ends up
    # retrievable from the knowledge base, so they are worth checking.
    seed_urls = validate_crawl_urls(seed_urls, field_name="seed_urls")
    sitemap_urls = validate_crawl_urls(sitemap_urls, field_name="sitemap_urls")

    connection: dict = {"authType": auth_type}
    if seed_urls:
        connection["seedUrls"] = seed_urls
    if sitemap_urls:
        connection["siteMapUrls"] = sitemap_urls
    if auth_type != "NO_AUTH" and secret_arn:
        connection["secretArn"] = secret_arn

    params: dict = {
        "type": "WEB",
        "version": "1",
        "connectionConfiguration": connection,
    }

    crawl_config: dict = {}
    if crawl_depth is not None:
        crawl_config["crawlDepth"] = crawl_depth
    if max_links_per_url is not None:
        crawl_config["maxLinksPerUrl"] = max_links_per_url
    if max_crawled_urls_per_minute is not None:
        crawl_config["maxCrawledUrlsPerMinute"] = max_crawled_urls_per_minute
    if sync_scope:
        crawl_config["syncScope"] = _validate_sync_scope(sync_scope)
    if crawl_attachments:
        crawl_config["crawlAttachments"] = True
    if crawl_config:
        params["crawlConfiguration"] = crawl_config

    filter_config: dict = {}
    if max_file_size_mb is not None:
        filter_config["maxFileSizeInMegaBytes"] = max_file_size_mb
    if inclusion_filters:
        filter_config["inclusionFilters"] = inclusion_filters
    if exclusion_filters:
        filter_config["exclusionFilters"] = exclusion_filters
    if filter_config:
        params["filterConfiguration"] = filter_config

    return params


def build_secret_body(
    *,
    auth_mode: str,
    username: str | None = None,
    password: str | None = None,
) -> dict | None:
    """Build the Secrets Manager secret JSON for a Web connector.

    Returns None for NO_AUTH (no secret needed).
    """
    mode = auth_mode.strip().lower()
    if mode == "no_auth":
        return None
    if mode == "basic_auth":
        if not (username and password):
            raise ValueError("username and password required for basic_auth.")
        return {"username": username, "password": password}
    raise ValueError(f"Unknown auth_mode {auth_mode!r} for Web connector.")


class WebConnector(ConnectorSpec):
    """Web crawler managed connector spec."""

    type = "web"
    api_type = "WEB"
    provider = None
    fields = (
        Field("seed_urls", list, "URLs to start crawling from. Set this or sitemap_urls.",
              ask=True),
        Field("sitemap_urls", list, "Sitemap URLs to crawl."),
        Field("auth_mode", str, "Authentication for the crawl target.", default="no_auth",
              choices=("no_auth", "basic_auth"), ask=True),
        Field("username", str, "basic_auth user name.", in_params=False),
        Field("password", str,
              "basic_auth password. Prefer leaving this out and entering it when prompted.",
              in_params=False),
        Field("crawl_depth", int, "Maximum link depth from the seed URLs.", ask=True),
        Field("max_links_per_url", int, "Maximum links followed per page."),
        Field("max_crawled_urls_per_minute", int, "Crawl rate limit."),
        Field("sync_scope", str, "How far the crawler follows links.",
              choices=tuple(sorted(_SYNC_SCOPES))),
        Field("crawl_attachments", bool, "Crawl linked attachments.", default=False),
        Field("max_file_size_mb", (int, str), MAX_FILE_SIZE_HELP),
        Field("inclusion_filters", list, "Only crawl URLs matching these patterns."),
        Field("exclusion_filters", list, "Skip URLs matching these patterns."),
    )

    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        return build_connector_params(
            seed_urls=self.value(cfg, "seed_urls"),
            auth_mode=self.value(cfg, "auth_mode"),
            secret_arn=ctx.secret_arn,
            sitemap_urls=self.value(cfg, "sitemap_urls"),
            crawl_depth=self.value(cfg, "crawl_depth"),
            max_links_per_url=self.value(cfg, "max_links_per_url"),
            max_crawled_urls_per_minute=self.value(cfg, "max_crawled_urls_per_minute"),
            sync_scope=self.value(cfg, "sync_scope"),
            crawl_attachments=self.value(cfg, "crawl_attachments"),
            max_file_size_mb=self.value(cfg, "max_file_size_mb"),
            inclusion_filters=self.value(cfg, "inclusion_filters"),
            exclusion_filters=self.value(cfg, "exclusion_filters"),
        )

    def check(self, cfg: ConnectorConfig, overrides: RequestOverrides) -> None:
        check_max_file_size(cfg.get("max_file_size_mb"), overrides)
