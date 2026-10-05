"""Tests for `init`: prompts come from the connector specs."""

from __future__ import annotations

import argparse
import tomllib
import warnings

import pytest

from kb_connector.core.config import ConfigWarning, ToolConfig

_TENANT = "11111111-2222-3333-4444-555555555555"


def _run_init(tmp_path, monkeypatch, answers: list[str]) -> dict:
    from kb_connector.cli.init_cmd import _init_interactive

    feed = iter(answers)

    def _input(prompt=""):
        try:
            return next(feed)
        except StopIteration:
            pytest.fail(f"init asked more than expected: {prompt!r}")

    monkeypatch.setattr("builtins.input", _input)
    out = tmp_path / "kb-connector.toml"
    assert _init_interactive(argparse.Namespace(output=str(out), add=False)) == 0
    return tomllib.loads(out.read_text())


_NO_DEFAULTS = ["", "", "", "", "n"]  # region, profile, prefix, cert bucket, Microsoft?


def test_s3_prompts_include_the_patterns_and_size(tmp_path, monkeypatch):
    doc = _run_init(tmp_path, monkeypatch, _NO_DEFAULTS + [
        "", "media", "s3",
        "media-bucket",            # bucket_name
        "",                        # acl -> default
        "videos/", "",             # inclusion_prefixes
        "*.mp4", "",               # inclusion_patterns
        "",                        # exclusion_patterns
        "1500",                    # max_file_size_mb
        "n",                       # add another
    ])
    assert doc["connectors"]["media"] == {
        "type": "s3",
        "bucket_name": "media-bucket",
        "inclusion_prefixes": ["videos/"],
        "inclusion_patterns": ["*.mp4"],
        "max_file_size_mb": 1500,
    }


def test_sharepoint_asks_for_tenant_and_sites(tmp_path, monkeypatch):
    doc = _run_init(tmp_path, monkeypatch, _NO_DEFAULTS + [
        "", "eng", "sharepoint",
        _TENANT,                                       # tenant_id
        "y",                                           # sites_selected
        "y",                                           # acl
        "https://x.sharepoint.com/sites/eng", "",      # site_urls
        "x.sharepoint.com",                            # sharepoint_host
        "n",
    ])
    assert doc["connectors"]["eng"] == {
        "type": "sharepoint", "tenant_id": _TENANT, "sites_selected": True,
        "acl": True, "site_urls": ["https://x.sharepoint.com/sites/eng"],
        "sharepoint_host": "x.sharepoint.com",
    }


def test_init_output_resolves_without_warnings(tmp_path, monkeypatch):
    doc = _run_init(tmp_path, monkeypatch, _NO_DEFAULTS + [
        "", "site", "web", "https://example.com/docs", "", "", "3", "n",
    ])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ToolConfig(defaults=doc["defaults"], connectors=doc["connectors"]).resolve_connector("site")
    assert [w for w in caught if issubclass(w.category, ConfigWarning)] == []
    assert doc["connectors"]["site"] == {
        "type": "web", "seed_urls": ["https://example.com/docs"], "crawl_depth": 3,
    }
