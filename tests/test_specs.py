"""Tests for connector specs: the one mapping from config to connectorParameters."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from kb_connector.connectors import all_specs, get_spec
from kb_connector.connectors.base import BuildContext
from kb_connector.core.config import ConfigWarning, ToolConfig
from kb_connector.core.errors import ConfigError
from kb_connector.core.overrides import load as load_overrides

_TENANT = "11111111-2222-3333-4444-555555555555"
_CTX = BuildContext(
    account_id="111122223333",
    secret_arn="arn:aws:secretsmanager:us-west-2:111122223333:secret:s-a1",
    cert_s3_bucket="certs", cert_s3_key="kb-connector/c.p12",
)

# A config each connector accepts, with every key a build needs.
_BASE = {
    "sharepoint": {"tenant_id": _TENANT, "site_urls": ["https://x.sharepoint.com/sites/a"]},
    "onedrive": {"tenant_id": _TENANT},
    "s3": {"bucket_name": "b"},
    "web": {"seed_urls": ["https://example.com/docs"]},
    "confluence": {"host_url": "https://x.atlassian.net"},
    "googledrive": {},
}


def _cfg(connector_type: str, **raw):
    body = {"type": connector_type, **_BASE[connector_type], **raw}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConfigWarning)
        return ToolConfig(connectors={"c": body}).resolve_connector("c")


def _params(connector_type: str, **raw) -> dict:
    return get_spec(connector_type).build_connector_params(_cfg(connector_type, **raw), _CTX)


def _sample(field):
    """A value for `field` that differs from its default."""
    if field.choices:
        return next(c for c in field.choices if c != field.default)
    if field.kind is bool:
        return not field.default
    if field.kind is list:
        return ["https://example.com/sample"]
    if field.kind is dict:
        return {"crawl_page": False} if "page" in field.help else {"crawl_my_drive": False}
    if field.kind is int or (isinstance(field.kind, tuple) and int in field.kind):
        return 7
    return "https://example.com/sample"


@pytest.mark.parametrize("connector_type", sorted(_BASE))
def test_every_declared_param_field_reaches_the_request(connector_type):
    """A field marked in_params must change connectorParameters when set."""
    spec = get_spec(connector_type)
    baseline = _params(connector_type)
    for f in spec.fields:
        if not f.in_params or f.key in _BASE[connector_type] or f.key == "tenant_id":
            continue
        extra = {f.key: _sample(f)}
        if f.key == "acl_s3_uri":
            extra["acl"] = True
        if f.key == "acl" and connector_type in ("confluence", "googledrive"):
            extra["credential"] = "basic" if connector_type == "confluence" else "service_account"
        if f.key == "credential" and connector_type == "sharepoint":
            continue  # non-cert SharePoint is refused by setup before the builder
        assert _params(connector_type, **extra) != baseline, f"{connector_type}.{f.key}"


def test_registry_covers_every_type():
    assert set(all_specs()) == set(_BASE)


# --- the keys setup used to drop ---------------------------------------------------


def test_confluence_filters_and_entities_reach_the_request():
    p = _params(
        "confluence",
        exclusion_space_keys=["ARCHIVE"],
        inclusion_mime_types=["text/html"],
        exclusion_mime_types=["image/png"],
        data_entities={"crawl_blog": False},
    )
    assert p["filterConfiguration"]["exclusionSpaceKeys"] == ["ARCHIVE"]
    assert p["filterConfiguration"]["inclusionMimeTypes"] == ["text/html"]
    assert p["filterConfiguration"]["exclusionMimeTypes"] == ["image/png"]
    assert p["dataEntityConfiguration"] == {"crawlBlog": False}


def test_google_drive_filters_and_alias_reach_the_request():
    p = _params(
        "googledrive",
        shared_drive_ids=["D1"],
        exclusion_shared_drive_ids=["D2"],
        inclusion_folder_ids=["F1"],
        inclusion_file_ids=["X1"],
    )
    fc = p["filterConfiguration"]
    assert fc["inclusionSharedDriveIds"] == ["D1"]
    assert fc["exclusionSharedDriveIds"] == ["D2"]
    assert fc["inclusionFolderIds"] == ["F1"] and fc["inclusionFileIds"] == ["X1"]


def test_s3_defaults_bucket_owner_to_the_caller_and_sends_size_as_string():
    p = _params("s3", max_file_size_mb=100)
    assert p["connectionConfiguration"]["bucketOwnerAccountId"] == "111122223333"
    assert p["filterConfiguration"]["maxFileSizeInMegaBytes"] == "100"


def test_onedrive_crawl_scope_reaches_the_request():
    p = _params("onedrive", crawl_shared_with_me=True, inclusion_user_emails=["a@x.com"])
    assert p["dataEntityConfiguration"]["crawlSharedWithMe"] is True
    assert p["dataEntityConfiguration"]["inclusionUserEmailAddresses"] == ["a@x.com"]


def test_sharepoint_uses_cert_paths_from_the_context():
    p = _params("sharepoint", crawl_pages=False)
    assert p["connectionConfiguration"]["certificateS3Path"] == {
        "s3BucketName": "certs", "s3KeyName": "kb-connector/c.p12",
    }
    assert p["dataEntityConfiguration"]["crawlPages"] is False
    assert p["dataEntityConfiguration"]["crawlFiles"] is True


def test_context_acl_overrides_config():
    spec = get_spec("onedrive")
    p = spec.build_connector_params(_cfg("onedrive", acl=False), BuildContext(
        secret_arn="arn", cert_s3_bucket="b", cert_s3_key="k", acl=True))
    assert p["aclEnabled"] is True


# --- config checks -----------------------------------------------------------------


def _warnings_for(raw: dict, defaults: dict | None = None) -> list[str]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ToolConfig(defaults=defaults or {}, connectors={"c": raw}).resolve_connector("c")
    return [str(w.message) for w in caught if issubclass(w.category, ConfigWarning)]


def test_a_misspelled_key_warns_with_the_closest_match():
    (msg,) = _warnings_for({"type": "s3", "bucket_name": "b", "max_file_size": 100})
    assert "'max_file_size'" in msg and "'max_file_size_mb'" in msg


def test_a_quoted_boolean_warns_that_it_is_treated_as_true():
    (msg,) = _warnings_for({"type": "s3", "bucket_name": "b", "acl": "false"})
    assert "treated as true" in msg


@pytest.mark.parametrize("raw,needle", [
    ({"type": "web", "seed_urls": "https://x"}, "list of strings"),
    ({"type": "web", "seed_urls": ["https://x"], "crawl_depth": "2"}, "integer"),
    ({"type": "web", "seed_urls": ["https://x"], "sync_scope": "HOST_ONLY"}, "expected one of"),
    ({"type": "s3", "bucket_name": "b", "validation": {"querry": "q"}}, "'query'"),
    ({"type": "nope"}, "unknown type"),
])
def test_wrong_kinds_and_values_warn(raw, needle):
    assert any(needle in m for m in _warnings_for(raw))


def test_unknown_defaults_keys_warn():
    msgs = _warnings_for(
        {"type": "s3", "bucket_name": "b"},
        defaults={"regoin": "x", "microsoft": {"device_code_client_id": "y"}},
    )
    assert any("'regoin'" in m and "'region'" in m for m in msgs)
    assert any("[defaults.microsoft]" in m for m in msgs)


def test_a_clean_config_does_not_warn():
    assert _warnings_for({
        "type": "sharepoint", "tenant_id": _TENANT, "site_urls": ["https://x/sites/a"],
        "acl": True, "region": "us-west-2", "tags": {"a": "b"},
        "validation": {"query": "q"}, "overrides": {}, "connector_params_overrides": {},
    }) == []


def test_example_toml_uses_only_declared_keys():
    """The shipped example must not document keys the tool ignores.

    Reads every `key = value` line, commented out or not, under its nearest
    table header, so the commented-out examples are checked too.
    """
    import re

    from kb_connector.connectors.base import VALIDATION_KEYS
    from kb_connector.core.config import _DEFAULT_KEYS, _MICROSOFT_DEFAULT_KEYS

    path = Path(__file__).resolve().parent.parent / "kb-connector.example.toml"
    header = re.compile(r"^#?\s*\[([A-Za-z0-9_.\-]+)\]\s*$")
    assign = re.compile(r"^#?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
    free_form = ("tags", "overrides", "connector_params_overrides")
    table, types, keys = "", {}, []
    for line in path.read_text().splitlines():
        if line.startswith("# #"):
            continue  # an option nested inside a commented-out example
        if m := header.match(line):
            table = m.group(1)
        elif m := assign.match(line):
            keys.append((table, m.group(1)))
            if m.group(1) == "type" and table.count(".") == 1:
                types[table] = line.split("=", 1)[1].split("#")[0].strip().strip('"')

    problems = []
    for table, key in keys:
        parts = table.split(".")
        if parts[0] == "defaults":
            allowed = {1: _DEFAULT_KEYS}.get(len(parts))
            if parts[1:] == ["microsoft"]:
                allowed = _MICROSOFT_DEFAULT_KEYS
            elif len(parts) > 1 and parts[1] in free_form:
                continue
        elif parts[0] == "connectors" and len(parts) >= 2:
            if len(parts) > 2 and parts[2] in free_form:
                continue
            if len(parts) > 2 and parts[2] == "validation":
                allowed = set(VALIDATION_KEYS)
            else:
                spec = get_spec(types.get(".".join(parts[:2]), ""))
                allowed = {f.key for f in spec.all_fields()} if spec else None
        else:
            allowed = None
        if allowed is None or key not in allowed:
            problems.append(f"[{table}] {key}")
    assert problems == []


# --- max_file_size_mb --------------------------------------------------------------

_MEDIA_ON = {"overrides": {"create_data_source": {"dataSourceConfiguration": {
    "managedKnowledgeBaseConnectorConfiguration": {"mediaExtractionConfiguration": {
        "videoExtractionConfiguration": {"videoExtractionStatus": "ENABLED"}}}}}}}


def _check(size, **raw):
    cfg = _cfg("s3", max_file_size_mb=size, **raw)
    get_spec("s3").check(cfg, load_overrides(cfg.raw))


@pytest.mark.parametrize("size", [1, 500, "500"])
def test_sizes_within_the_limit_pass(size):
    _check(size)


@pytest.mark.parametrize("size,match", [
    (501, "media extraction"), ("1500", "media extraction"),
    (0, "at least 1"), ("big", "whole number"), (True, "whole number"),
])
def test_sizes_the_service_rejects_fail_before_setup(size, match):
    with pytest.raises(ConfigError, match=match):
        _check(size)


def test_media_extraction_raises_the_limit():
    _check(1500, **_MEDIA_ON)


def test_above_the_verified_media_limit_warns():
    with pytest.warns(ConfigWarning, match="1500"):
        _check(2000, **_MEDIA_ON)


def test_config_reference_is_current():
    """CONFIG-REFERENCE.md is generated; regenerate it after changing a Field."""
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "gen_config_reference", root / "scripts" / "gen_config_reference.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (root / "CONFIG-REFERENCE.md").read_text() == module.render(), (
        "Run: python scripts/gen_config_reference.py"
    )
