"""Request bodies for the Amazon Quick data source and knowledge base."""
from __future__ import annotations

import pytest

from kb_connector.core.config import ConnectorConfig
from kb_connector.core.errors import ConfigError
from kb_connector.quick import templates

_TENANT = "11111111-1111-1111-1111-111111111111"
_CLIENT = "22222222-2222-2222-2222-222222222222"
_SITE = "https://contoso.sharepoint.com/sites/eng"


def _sp(acl: bool = True, **raw) -> ConnectorConfig:
    body = {"type": "sharepoint", "site_urls": [_SITE], **raw}
    return ConnectorConfig(name="c", type="sharepoint", raw=body, target="quick", acl=acl)


def _od(acl: bool = False, **raw) -> ConnectorConfig:
    body = {"type": "onedrive", **raw}
    return ConnectorConfig(name="c", type="onedrive", raw=body, target="quick", acl=acl)


def test_sharepoint_template_defaults():
    t = templates.knowledge_base_template(_sp())
    assert t["type"] == "SHAREPOINTV3"
    assert t["dataEntityConfiguration"] == {
        "siteUrls": [_SITE], "crawlPages": True, "crawlFiles": True,
    }
    assert t["filterConfiguration"] == {
        "maxFileSizeInMegaBytes": "500", "inclusionItemPaths": [_SITE],
    }
    assert t["accessControlConfiguration"] == {"crawlAcl": True}
    assert t["crawlIdentities"] is True
    assert t["selectedFiles"] == []
    assert t["deletionProtectionConfiguration"] == {
        "enableDeletionProtection": False, "deletionProtectionThreshold": "15",
    }


def test_sharepoint_crawl_flags_follow_config():
    t = templates.knowledge_base_template(_sp(crawl_files=False, crawl_pages=False))
    assert t["dataEntityConfiguration"]["crawlFiles"] is False
    assert t["dataEntityConfiguration"]["crawlPages"] is False


def test_explicit_inclusion_item_paths_win_over_site_urls():
    paths = ["https://contoso.sharepoint.com/sites/eng/Shared Documents/specs"]
    t = templates.knowledge_base_template(_sp(inclusion_item_paths=paths))
    assert t["filterConfiguration"]["inclusionItemPaths"] == paths


def test_exclusion_file_name_patterns_reach_the_filter():
    t = templates.knowledge_base_template(_sp(exclusion_file_name_patterns=[r".*\.tmp"]))
    assert t["filterConfiguration"]["exclusionFileNamePatterns"] == [r".*\.tmp"]


def test_acl_false_turns_off_acl_crawl_and_identities():
    cfg = _sp(acl=False)
    t = templates.knowledge_base_template(cfg)
    assert t["accessControlConfiguration"] == {"crawlAcl": False}
    assert t["crawlIdentities"] is False
    assert templates.quick_acl(cfg) is False


def test_sharepoint_template_needs_site_urls():
    cfg = ConnectorConfig(name="c", type="sharepoint", raw={"type": "sharepoint"},
                          target="quick")
    with pytest.raises(ConfigError, match="site_urls"):
        templates.knowledge_base_template(cfg)


@pytest.mark.parametrize("raw, expected", [
    ({"sharepoint_domain": "https://contoso.sharepoint.com/"}, "contoso.sharepoint.com"),
    ({"sharepoint_domain": "contoso.sharepoint.com"}, "contoso.sharepoint.com"),
    ({"sharepoint_host": "fabrikam.sharepoint.com"}, "fabrikam.sharepoint.com"),
    ({}, "contoso.sharepoint.com"),
])
def test_sharepoint_domain_sources(raw, expected):
    assert templates.sharepoint_domain(_sp(**raw)) == expected


def test_sharepoint_domain_ignores_a_non_https_site_url():
    cfg = _sp(site_urls=["http://contoso.sharepoint.com/sites/eng"])
    assert templates.sharepoint_domain(cfg) is None
    with pytest.raises(ConfigError, match="sharepoint_domain"):
        templates.data_source_request(cfg, tenant_id=_TENANT, client_id=_CLIENT)


def test_sharepoint_data_source_request():
    ds_type, params = templates.data_source_request(_sp(), tenant_id=_TENANT, client_id=_CLIENT)
    assert ds_type == "SHAREPOINT"
    assert params == {"SharePointParameters": {
        "SharePointDomain": "contoso.sharepoint.com", "TenantId": _TENANT,
        "ClientId": _CLIENT, "AuthType": "TWO_LEGGED_OAUTH",
    }}


def test_onedrive_data_source_request():
    ds_type, params = templates.data_source_request(_od(), tenant_id=_TENANT, client_id=_CLIENT)
    assert ds_type == "ONE_DRIVE"
    assert params == {"OneDriveParameters": {
        "TenantId": _TENANT, "ClientId": _CLIENT, "AuthType": "TWO_LEGGED_OAUTH",
    }}


def test_onedrive_template_shape_and_forced_acl():
    cfg = _od(acl=False, crawl_shared_with_me=True)
    t = templates.knowledge_base_template(cfg)
    assert t["type"] == "ONEDRIVEV3"
    assert t["authType"] == "TWO_LEGGED_OAUTH"
    assert t["dataEntityConfiguration"] == {
        "crawlPersonalDrives": True, "crawlSharedWithMe": True,
        "crawlOneNoteNotebooks": False,
    }
    assert t["accessControlConfiguration"] == {"crawlAcl": True}
    assert t["crawlIdentities"] is True
    assert t["filterConfiguration"]["maxFileSizeInMegaBytes"] == "500"
    assert templates.quick_acl(cfg) is True


@pytest.mark.parametrize("cfg", [_sp(), _od()])
def test_no_connection_configuration(cfg):
    assert "connectionConfiguration" not in templates.knowledge_base_template(cfg)


def test_ignored_keys_names_inclusion_user_emails_on_onedrive():
    assert templates.ignored_keys(_od(inclusion_user_emails=["a@contoso.com"])) == [
        "inclusion_user_emails"
    ]
    assert templates.ignored_keys(_od()) == []
    assert templates.ignored_keys(_sp()) == []


def test_other_connector_types_are_refused():
    cfg = ConnectorConfig(name="c", type="s3", raw={"type": "s3"}, target="quick")
    with pytest.raises(ConfigError, match="sharepoint and onedrive"):
        templates.knowledge_base_template(cfg)
