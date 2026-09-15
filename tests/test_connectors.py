"""Unit tests for connector params builders and secret schemas."""

import pytest

from kb_connector.connectors.sharepoint import (
    build_connector_params as sp_params,
    build_filter_config as sp_filter_config,
    build_secret_body as sp_secret,
    connector_auth_type as sp_auth_type,
    filter_config_from_config as sp_filter_config_from_config,
)
from kb_connector.connectors.onedrive import (
    build_connector_params as od_params,
    build_secret_body as od_secret,
    connector_auth_type as od_auth_type,
)


# --- SharePoint auth types ---------------------------------------------------


def test_sp_cert_auth_type():
    assert sp_auth_type("cert") == "ENTRA_ID_APP_ONLY"


def test_sp_client_secret_auth_type():
    assert sp_auth_type("client_secret") == "ENTRA_ID_APP_ONLY"


def test_sp_ropc_auth_type():
    assert sp_auth_type("ropc") == "OAUTH2_APP"


def test_sp_invalid_credential():
    with pytest.raises(ValueError, match="not valid for SharePoint"):
        sp_auth_type("oauth2_refresh")


# --- OneDrive auth types -----------------------------------------------------


def test_od_cert_auth_type():
    assert od_auth_type("cert") == "ENTRA_APP_ID"


def test_od_oauth2_refresh_auth_type():
    assert od_auth_type("oauth2_refresh") == "OAUTH2"


def test_od_invalid_credential():
    with pytest.raises(ValueError, match="not valid for OneDrive"):
        od_auth_type("ropc")


# --- SharePoint connector params ---------------------------------------------


def test_sp_params_cert_with_acl():
    params = sp_params(
        credential="cert",
        tenant_id="tenant-123",
        secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:test",
        acl=True,
        site_urls=["https://contoso.sharepoint.com/sites/eng"],
        cert_s3_bucket="my-bucket",
        cert_s3_key="certs/sp.p12",
    )
    assert params["type"] == "SHAREPOINT"
    assert params["aclEnabled"] is True
    assert params["crawlIdentities"] is True
    assert params["connectionConfiguration"]["authType"] == "ENTRA_ID_APP_ONLY"
    assert params["connectionConfiguration"]["certificateS3Path"]["s3BucketName"] == "my-bucket"
    assert params["dataEntityConfiguration"]["siteUrls"] == ["https://contoso.sharepoint.com/sites/eng"]


def test_sp_params_cert_missing_bucket():
    with pytest.raises(ValueError, match="cert_s3_bucket"):
        sp_params(
            credential="cert",
            tenant_id="t",
            secret_arn="arn",
            acl=False,
            site_urls=[],
        )


def test_sp_params_no_acl():
    params = sp_params(
        credential="cert",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        site_urls=["https://x.sharepoint.com/sites/a"],
        cert_s3_bucket="my-bucket",
        cert_s3_key="certs/sp.p12",
    )
    assert params["aclEnabled"] is False
    assert params["crawlIdentities"] is False


def test_sp_params_non_cert_omits_certificate_path():
    """Only 'cert' populates certificateS3Path.

    Exercises the builder's credential scoping. Note setup rejects non-cert
    SharePoint credentials before this builder runs (see KNOWN-LIMITATIONS.md);
    this is builder-level behavior, not a supported configuration.
    """
    params = sp_params(
        credential="client_secret",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        site_urls=["https://x.sharepoint.com/sites/a"],
    )
    assert "certificateS3Path" not in params["connectionConfiguration"]


# --- OneDrive connector params -----------------------------------------------


def test_od_params_cert():
    params = od_params(
        credential="cert",
        tenant_id="t",
        secret_arn="arn",
        acl=True,
        cert_s3_bucket="b",
        cert_s3_key="k",
    )
    assert params["type"] == "ONEDRIVE"
    assert params["aclEnabled"] is True
    assert params["connectionConfiguration"]["certificateS3Path"]["s3BucketName"] == "b"


def test_od_params_with_user_filter():
    params = od_params(
        credential="client_secret",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        inclusion_user_emails=["alice@example.com"],
    )
    assert params["dataEntityConfiguration"]["inclusionUserEmailAddresses"] == ["alice@example.com"]


def test_sp_params_crawl_toggles():
    """crawl_files and crawl_pages flow through to dataEntityConfiguration."""
    params = sp_params(
        credential="cert",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        site_urls=["https://x.sharepoint.com/sites/a"],
        cert_s3_bucket="my-bucket",
        cert_s3_key="certs/sp.p12",
        crawl_files=False,
        crawl_pages=True,
    )
    de = params["dataEntityConfiguration"]
    assert de["crawlFiles"] is False
    assert de["crawlPages"] is True


def test_od_params_data_entity_toggles():
    """OD's data-entity flags flow through (crawl_personal_drives, crawl_shared_with_me)."""
    params = od_params(
        credential="client_secret",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        crawl_personal_drives=False,
        crawl_shared_with_me=True,
    )
    de = params["dataEntityConfiguration"]
    assert de["crawlPersonalDrives"] is False
    assert de["crawlSharedWithMe"] is True


# --- SharePoint secret body --------------------------------------------------


def test_sp_secret_cert():
    body = sp_secret(
        credential="cert",
        client_id="app-123",
        certificate_password="pw",
        private_key_b64_pkcs8="base64key",
        client_secret="cs",
    )
    assert body["clientId"] == "app-123"
    assert body["certificatePassword"] == "pw"
    assert body["privateKey"] == "base64key"
    assert body["clientSecret"] == "cs"


def test_sp_secret_client_secret(fixture_secret):
    body = sp_secret(
        credential="client_secret",
        client_id="app-123",
        client_secret=fixture_secret,
    )
    assert body["clientSecret"] == fixture_secret
    assert body["entraIdAppOnlyWithClientSecret"] is True


def test_sp_secret_ropc():
    body = sp_secret(
        credential="ropc",
        client_id="app-123",
        client_secret="cs",
        admin_username="admin@contoso.com",
        admin_password="pass",
    )
    assert body["userName"] == "admin@contoso.com"
    assert body["password"] == "pass"


def test_sp_secret_cert_missing_password():
    with pytest.raises(ValueError, match="certificate_password"):
        sp_secret(credential="cert", client_id="app")


# --- OneDrive secret body ----------------------------------------------------


def test_od_secret_cert():
    body = od_secret(
        credential="cert",
        client_id="app-123",
        client_secret="cs",
        certificate_password="pw",
    )
    assert body["clientId"] == "app-123"
    assert body["clientSecret"] == "cs"
    assert body["certificatePassword"] == "pw"


def test_od_secret_cert_missing_client_secret():
    with pytest.raises(ValueError, match="client_secret required"):
        od_secret(credential="cert", client_id="app", certificate_password="pw")


def test_od_secret_oauth2_refresh(fixture_secret):
    body = od_secret(
        credential="oauth2_refresh",
        client_id="app-123",
        client_secret="cs",
        refresh_token=fixture_secret,
    )
    assert body["refreshToken"] == fixture_secret


# --- S3 connector params -----------------------------------------------------

from kb_connector.connectors.s3 import (
    build_connector_params as s3_params,
)
from kb_connector.connectors.web import (
    build_connector_params as web_params,
    build_secret_body as web_secret,
    connector_auth_type as web_auth_type,
)


def test_s3_params_minimal():
    params = s3_params(bucket_name="my-docs-bucket")
    assert params["type"] == "S3"
    assert params["version"] == "1"
    assert params["connectionConfiguration"]["bucketName"] == "my-docs-bucket"


def test_s3_params_bucket_owner():
    params = s3_params(bucket_name="docs", bucket_owner_account_id="123456789012")
    assert params["connectionConfiguration"]["bucketOwnerAccountId"] == "123456789012"


def test_s3_params_with_acl():
    params = s3_params(
        bucket_name="docs",
        acl=True,
        acl_s3_uri="s3://docs/acl.json",
    )
    assert params["aclEnabled"] is True
    assert params["aclConfiguration"]["globalAccessControlListS3Uri"] == "s3://docs/acl.json"


def test_s3_params_with_filters():
    params = s3_params(
        bucket_name="docs",
        inclusion_prefixes=["docs/"],
        exclusion_prefixes=["archive/"],
        inclusion_patterns=[".*\\.pdf"],
        exclusion_patterns=[".*\\.tmp"],
        max_file_size_mb="100",
    )
    fc = params["filterConfiguration"]
    assert fc["inclusionPrefixes"] == ["docs/"]
    assert fc["exclusionPrefixes"] == ["archive/"]
    assert fc["inclusionPatterns"] == [".*\\.pdf"]
    assert fc["exclusionPatterns"] == [".*\\.tmp"]
    assert fc["maxFileSizeInMegaBytes"] == "100"


def test_s3_params_metadata_prefix():
    params = s3_params(bucket_name="docs", metadata_files_prefix="metadata/")
    assert params["metadataFilesPrefix"] == "metadata/"


# --- Web connector params ----------------------------------------------------


def test_web_auth_type_no_auth():
    assert web_auth_type("no_auth") == "NO_AUTH"


def test_web_auth_type_basic():
    assert web_auth_type("basic_auth") == "BASIC_AUTH"


def test_web_auth_type_invalid():
    with pytest.raises(ValueError, match="not valid for Web"):
        web_auth_type("oauth2")


def test_web_params_no_auth():
    params = web_params(seed_urls=["https://docs.example.com"])
    assert params["type"] == "WEB"
    assert params["connectionConfiguration"]["authType"] == "NO_AUTH"
    assert params["connectionConfiguration"]["seedUrls"] == ["https://docs.example.com"]
    assert "secretArn" not in params["connectionConfiguration"]


def test_web_params_basic_auth():
    params = web_params(
        seed_urls=["https://internal.example.com"],
        auth_mode="basic_auth",
        secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:web-creds",
    )
    assert params["connectionConfiguration"]["authType"] == "BASIC_AUTH"
    assert params["connectionConfiguration"]["secretArn"] == "arn:aws:secretsmanager:us-west-2:123:secret:web-creds"


def test_web_params_sitemap_only():
    params = web_params(sitemap_urls=["https://docs.example.com/sitemap.xml"])
    assert params["connectionConfiguration"]["siteMapUrls"] == ["https://docs.example.com/sitemap.xml"]
    assert "seedUrls" not in params["connectionConfiguration"]


def test_web_params_requires_seed_or_sitemap():
    with pytest.raises(ValueError, match="seed_urls or sitemap_urls"):
        web_params()


def test_web_params_crawl_config():
    params = web_params(
        seed_urls=["https://docs.example.com"],
        crawl_depth=3,
        max_links_per_url=50,
        sync_scope="ALL_DOMAINS",
        crawl_attachments=True,
    )
    assert params["crawlConfiguration"]["crawlDepth"] == 3
    assert params["crawlConfiguration"]["maxLinksPerUrl"] == 50
    assert params["crawlConfiguration"]["syncScope"] == "ALL_DOMAINS"
    assert params["crawlConfiguration"]["crawlAttachments"] is True


def test_web_params_with_filters():
    params = web_params(
        seed_urls=["https://docs.example.com"],
        max_file_size_mb=100,
        inclusion_filters=[".*\\.html"],
        exclusion_filters=[".*\\.pdf"],
    )
    assert params["filterConfiguration"]["maxFileSizeInMegaBytes"] == 100
    assert params["filterConfiguration"]["inclusionFilters"] == [".*\\.html"]
    assert params["filterConfiguration"]["exclusionFilters"] == [".*\\.pdf"]


def test_web_secret_no_auth():
    assert web_secret(auth_mode="no_auth") is None


def test_web_secret_basic_auth():
    body = web_secret(auth_mode="basic_auth", username="user", password="pass")
    assert body == {"username": "user", "password": "pass"}


def test_web_secret_basic_auth_missing_creds():
    with pytest.raises(ValueError, match="username and password"):
        web_secret(auth_mode="basic_auth")


# --- Confluence connector ----------------------------------------------------

from kb_connector.connectors.confluence import (
    build_connector_params as conf_params,
    build_secret_body as conf_secret,
    connector_auth_type as conf_auth_type,
)
from kb_connector.connectors.googledrive import (
    build_connector_params as gd_params,
    build_secret_body as gd_secret,
    connector_auth_type as gd_auth_type,
)


def test_conf_auth_type_oauth2():
    assert conf_auth_type("oauth2") == "OAUTH2"


def test_conf_auth_type_basic():
    assert conf_auth_type("basic") == "BASIC"
    assert conf_auth_type("basic_auth") == "BASIC"


def test_conf_params():
    params = conf_params(
        host_url="https://company.atlassian.net",
        credential="basic",
        secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:conf",
        acl=True,
        space_keys=["ENG", "DOCS"],
    )
    assert params["type"] == "CONFLUENCE"
    assert params["aclEnabled"] is True
    cc = params["connectionConfiguration"]
    assert cc["hostUrl"] == "https://company.atlassian.net"
    assert cc["type"] == "SAAS"
    assert cc["authType"] == "BASIC"
    assert params["filterConfiguration"]["inclusionSpaceKeys"] == ["ENG", "DOCS"]


def test_conf_params_oauth2_acl_rejected():
    import pytest
    with pytest.raises(ValueError, match="OAUTH2 is not supported"):
        conf_params(
            host_url="https://company.atlassian.net",
            credential="oauth2",
            secret_arn="arn:x",
            acl=True,
        )


def test_conf_params_data_entities():
    params = conf_params(
        host_url="https://x.atlassian.net",
        credential="basic",
        secret_arn="arn:x",
        data_entities={"crawl_page": True, "crawl_blog": False},
    )
    de = params["dataEntityConfiguration"]
    assert de["crawlPage"] is True
    assert de["crawlBlog"] is False


def test_conf_secret_oauth2():
    body = conf_secret(
        credential="oauth2",
        client_id="cid",
        client_secret="cs",
        refresh_token="rt",
    )
    assert body["clientId"] == "cid"
    assert body["refreshToken"] == "rt"


def test_conf_secret_basic_auth(fixture_secret):
    body = conf_secret(
        credential="basic",
        username="user@company.com",
        api_token=fixture_secret,
    )
    assert body["username"] == "user@company.com"
    assert body["password"] == fixture_secret


# --- Google Drive connector --------------------------------------------------


def test_gd_auth_type_oauth2():
    assert gd_auth_type("oauth2") == "OAUTH2"


def test_gd_auth_type_service_account():
    assert gd_auth_type("service_account") == "SERVICE_ACCOUNT"


def test_gd_params():
    params = gd_params(
        credential="oauth2",
        secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:gd",
        acl=False,
        shared_drive_ids=["drive-id-1"],
    )
    assert params["type"] == "GOOGLEDRIVE"
    assert params["connectionConfiguration"]["authType"] == "OAUTH2"
    assert "hostUrl" not in params["connectionConfiguration"]
    assert params["filterConfiguration"]["inclusionSharedDriveIds"] == ["drive-id-1"]


def test_gd_params_oauth2_acl_rejected():
    import pytest
    with pytest.raises(ValueError, match="OAUTH2 is not supported"):
        gd_params(credential="oauth2", secret_arn="arn:x", acl=True)


def test_gd_params_data_entities():
    params = gd_params(
        credential="service_account",
        secret_arn="arn:x",
        data_entities={"crawl_my_drive": True, "crawl_shared_drives": False},
    )
    de = params["dataEntityConfiguration"]
    assert de["crawlMyDrive"] is True
    assert de["crawlSharedDrives"] is False


def test_gd_secret_oauth2():
    body = gd_secret(
        credential="oauth2",
        client_id="cid",
        client_secret="cs",
        refresh_token="rt",
    )
    assert body == {"clientId": "cid", "clientSecret": "cs", "refreshToken": "rt"}


def test_gd_secret_service_account():
    # Deliberately not a real service-account JSON shape — the builder passes
    # this value through verbatim, so a placeholder exercises the path without
    # tripping public-repo secret scanners on a "type: service_account" string.
    fake_sa = "REDACTED_FAKE_SERVICE_ACCOUNT_JSON"
    body = gd_secret(
        credential="service_account",
        service_account_json=fake_sa,
    )
    assert body["serviceAccountCredentials"] == fake_sa


def test_gd_secret_oauth2_missing_fields():
    with pytest.raises(ValueError, match="client_id"):
        gd_secret(credential="oauth2", client_id=None, client_secret="cs", refresh_token="rt")


# --- SharePoint filterConfiguration ------------------------------------------


def _sp_cert_params(**kwargs):
    """SharePoint params with the cert plumbing filled in."""
    base = dict(
        credential="cert",
        tenant_id="t",
        secret_arn="arn",
        acl=False,
        site_urls=["https://x.sharepoint.com/sites/a"],
        cert_s3_bucket="b",
        cert_s3_key="k.p12",
    )
    base.update(kwargs)
    return sp_params(**base)


def test_sp_filter_config_omitted_when_empty():
    # An absent filterConfiguration and an empty one are not equivalent to the
    # service: a present-but-empty inclusionItemPaths would still be a signal.
    assert "filterConfiguration" not in _sp_cert_params()
    assert "filterConfiguration" not in _sp_cert_params(filter_config={})


def test_sp_filter_config_attached_when_present():
    params = _sp_cert_params(
        filter_config=sp_filter_config(inclusion_item_paths=["https://x/sites/a/Shared%20Documents/f.docx"])
    )
    assert params["filterConfiguration"] == {
        "inclusionItemPaths": ["https://x/sites/a/Shared%20Documents/f.docx"]
    }
    # filterConfiguration is a sibling of dataEntityConfiguration, not nested in it.
    assert "filterConfiguration" not in params["dataEntityConfiguration"]


def test_sp_filter_config_full_surface():
    fc = sp_filter_config(
        inclusion_item_paths=["https://x/a"],
        exclusion_item_paths=["https://x/b"],
        inclusion_file_name_patterns=[r".*\.pdf$"],
        exclusion_file_name_patterns=[r".*\.tmp$"],
        inclusion_file_path=["/Shared Documents/.*"],
        exclusion_file_path=[".*/Forms/.*"],
        modified_date_after="2026-01-01T00:00:00Z",
        modified_date_before="2026-12-31T00:00:00Z",
    )
    assert fc == {
        "inclusionItemPaths": ["https://x/a"],
        "exclusionItemPaths": ["https://x/b"],
        "inclusionFileNamePatterns": [r".*\.pdf$"],
        "exclusionFileNamePatterns": [r".*\.tmp$"],
        "inclusionFilePath": ["/Shared Documents/.*"],
        "exclusionFilePath": [".*/Forms/.*"],
        "modifiedDateAfter": "2026-01-01T00:00:00Z",
        "modifiedDateBefore": "2026-12-31T00:00:00Z",
    }


def test_sp_filter_config_drops_empty_lists():
    assert sp_filter_config(inclusion_item_paths=[], exclusion_item_paths=None) == {}


def test_sp_filter_config_copies_input_lists():
    # The caller's list must not alias into the params body, or a later mutation
    # of config would silently change an already-built request.
    paths = ["https://x/a"]
    fc = sp_filter_config(inclusion_item_paths=paths)
    paths.append("https://x/b")
    assert fc["inclusionItemPaths"] == ["https://x/a"]


def test_sp_filter_config_from_config_maps_toml_keys():
    fc = sp_filter_config_from_config({
        "inclusion_item_paths": ["https://x/a"],
        "modified_date_before": "2026-01-01T00:00:00Z",
        "site_urls": ["ignored-here"],
    })
    assert fc == {
        "inclusionItemPaths": ["https://x/a"],
        "modifiedDateBefore": "2026-01-01T00:00:00Z",
    }


def test_sp_filter_config_from_config_empty_for_plain_connector():
    assert sp_filter_config_from_config({"site_urls": ["https://x/sites/a"]}) == {}


def test_sp_spec_threads_crawl_toggles_and_filter():
    # Guards the two paths against diverging: the ConnectorSpec path must honor
    # crawl_files / crawl_pages exactly as the CLI path does.
    from kb_connector.connectors.sharepoint import SharePointConnector

    params = SharePointConnector().build_connector_params(
        {
            "credential": "cert",
            "tenant_id": "t",
            "site_urls": ["https://x.sharepoint.com/sites/a"],
            "crawl_pages": False,
            "inclusion_item_paths": ["https://x.sharepoint.com/sites/a"],
        },
        {"secret_arn": "arn", "cert_s3_bucket": "b", "cert_s3_key": "k.p12"},
    )
    assert params["dataEntityConfiguration"]["crawlPages"] is False
    assert params["dataEntityConfiguration"]["crawlFiles"] is True
    assert params["filterConfiguration"]["inclusionItemPaths"] == [
        "https://x.sharepoint.com/sites/a"
    ]
