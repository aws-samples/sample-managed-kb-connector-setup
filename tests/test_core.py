"""Unit tests for core modules: config, state, errors, knowledge_base payloads."""

import os
import tempfile

from kb_connector.core.config import load_config
from kb_connector.core.state import load_state, save_state, StateFile, ConnectorState
from kb_connector.core.errors import (
    ConnectorError, ConfigError, StateError, AwsError, GraphError,
)
from kb_connector.core.knowledge_base import (
    build_knowledge_base_payload, build_data_source_payload,
)
from kb_connector.core.provisioning import build_trust_policy, build_inline_policy
from kb_connector.core.monitor import IngestionStats


# --- Errors ------------------------------------------------------------------


def test_error_hierarchy():
    """All expected errors inherit from ConnectorError."""
    assert issubclass(ConfigError, ConnectorError)
    assert issubclass(StateError, ConnectorError)
    assert issubclass(AwsError, ConnectorError)
    assert issubclass(GraphError, ConnectorError)


def test_graph_error_carries_status():
    err = GraphError("auth failed", status=401, body={"error": "unauthorized"})
    assert err.status == 401
    assert err.body == {"error": "unauthorized"}
    assert "auth failed" in str(err)


# --- Config ------------------------------------------------------------------


def test_load_config_missing_file():
    """Loading config with a nonexistent explicit path raises ConfigError."""
    import pytest
    from kb_connector.core.errors import ConfigError
    with pytest.raises(ConfigError):
        load_config("/nonexistent/path.toml")


def test_load_config_no_file_found():
    """Loading config with no path and no file on disk returns empty ToolConfig."""
    # Use a directory with no kb-connector.toml
    with tempfile.TemporaryDirectory() as td:
        old_cwd = os.getcwd()
        os.chdir(td)
        try:
            cfg = load_config(None)
            assert cfg.connector_names() == []
        finally:
            os.chdir(old_cwd)


def test_load_config_from_toml():
    """Load a valid TOML config file."""
    content = """
[defaults]
region = "us-west-2"
owner = "testuser"

[defaults.microsoft]
tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

[connectors.my-sp]
type = "sharepoint"
credential = "cert"
acl = true
site_urls = ["https://contoso.sharepoint.com/sites/test"]
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(content)
        f.flush()
        try:
            cfg = load_config(f.name)
            assert "my-sp" in cfg.connector_names()
            resolved = cfg.resolve_connector("my-sp")
            assert resolved.type == "sharepoint"
            assert resolved.region == "us-west-2"
            assert resolved.acl is True
            assert resolved.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            assert resolved.credential == "cert"
            assert resolved.owner == "testuser"
        finally:
            os.unlink(f.name)


def test_config_cli_override():
    """CLI overrides take precedence over config values."""
    content = """
[defaults]
region = "us-west-2"

[connectors.test]
type = "s3"
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(content)
        f.flush()
        try:
            cfg = load_config(f.name)
            resolved = cfg.resolve_connector("test", cli_overrides={"region": "eu-west-1"})
            assert resolved.region == "eu-west-1"
        finally:
            os.unlink(f.name)


# --- State -------------------------------------------------------------------


def test_state_roundtrip():
    """Save and load state preserves values."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        state = StateFile()
        cs = ConnectorState(
            connector_type="sharepoint",
            knowledge_base_id="KB123",
            data_source_id="DS456",
        )
        state.set("my-connector", cs)
        save_state(state, path)

        loaded = load_state(path)
        loaded_cs = loaded.get("my-connector")
        assert loaded_cs.knowledge_base_id == "KB123"
        assert loaded_cs.data_source_id == "DS456"
        assert loaded_cs.connector_type == "sharepoint"
    finally:
        os.unlink(path)


def test_state_load_missing_file():
    """Loading state from a missing file returns empty StateFile."""
    state = load_state("/nonexistent/state.json")
    assert state.connectors == {}


def test_connector_state_merge():
    """ConnectorState.merge returns a copy with updates applied."""
    cs = ConnectorState(connector_type="s3", knowledge_base_id="KB1")
    updated = cs.merge(data_source_id="DS2")
    assert updated.data_source_id == "DS2"
    assert updated.knowledge_base_id == "KB1"
    # Original is unchanged
    assert cs.data_source_id is None


# --- Knowledge Base payloads -------------------------------------------------


def test_build_kb_payload_minimal():
    """Minimal KB payload with just name and role."""
    payload = build_knowledge_base_payload(
        name="test-kb",
        role_arn="arn:aws:iam::123456789012:role/test-role",
    )
    assert payload["name"] == "test-kb"
    assert payload["roleArn"] == "arn:aws:iam::123456789012:role/test-role"
    assert payload["knowledgeBaseConfiguration"]["type"] == "MANAGED"
    assert "kmsKeyArn" not in payload


def test_build_kb_payload_with_kms():
    """KB payload includes kmsKeyArn when provided."""
    payload = build_knowledge_base_payload(
        name="test-kb",
        role_arn="arn:aws:iam::123456789012:role/test-role",
        kms_key_arn="arn:aws:kms:us-west-2:123456789012:key/abc-123",
    )
    assert payload["kmsKeyArn"] == "arn:aws:kms:us-west-2:123456789012:key/abc-123"


def test_build_ds_payload():
    """DS payload wraps connector params correctly."""
    params = {"type": "SHAREPOINT", "version": "1", "aclEnabled": True}
    payload = build_data_source_payload(name="my-ds", connector_parameters=params)
    assert payload["name"] == "my-ds"
    config = payload["dataSourceConfiguration"]
    assert config["type"] == "MANAGED_KNOWLEDGE_BASE_CONNECTOR"
    inner = config["managedKnowledgeBaseConnectorConfiguration"]["connectorParameters"]
    assert inner == params


# --- Provisioning policies ---------------------------------------------------


def test_trust_policy_shape():
    """Trust policy has correct structure."""
    policy = build_trust_policy(account_id="123456789012", region="us-west-2")
    assert policy["Version"] == "2012-10-17"
    stmt = policy["Statement"][0]
    assert stmt["Principal"]["Service"] == "bedrock.amazonaws.com"
    assert stmt["Condition"]["StringEquals"]["aws:SourceAccount"] == "123456789012"


def test_inline_policy_with_secret_and_cert():
    """Inline policy includes SecretsManager + S3 statements."""
    policy = build_inline_policy(
        account_id="123456789012",
        region="us-west-2",
        secret_arn="arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
        cert_bucket="my-bucket",
        cert_key="certs/test.p12",
    )
    sids = [s["Sid"] for s in policy["Statement"]]
    assert "CloudWatchWritePermissionStatement" in sids
    assert "SecretsManagerGetStatement" in sids
    assert "S3ListBucketStatement" in sids
    assert "S3GetObjectStatement" in sids


def test_inline_policy_no_secret_no_cert():
    """Inline policy for NO_AUTH web crawler has only CloudWatch."""
    policy = build_inline_policy(
        account_id="123456789012",
        region="us-west-2",
        secret_arn=None,
        cert_bucket=None,
        cert_key=None,
    )
    assert len(policy["Statement"]) == 1
    assert policy["Statement"][0]["Sid"] == "CloudWatchWritePermissionStatement"


# --- Monitor stats -----------------------------------------------------------


def test_ingestion_stats_acl_warning():
    """ACL warning triggers when skipped > 0 and indexed < scanned."""
    stats = IngestionStats(
        status="COMPLETE", scanned=100, new_indexed=10,
        modified_indexed=0, skipped=90, failed=0,
    )
    assert stats.has_acl_warning is True
    assert stats.indexed_total == 10


def test_ingestion_stats_no_warning():
    """No warning when all docs are indexed."""
    stats = IngestionStats(
        status="COMPLETE", scanned=100, new_indexed=95,
        modified_indexed=5, skipped=0, failed=0,
    )
    assert stats.has_acl_warning is False
    assert stats.indexed_total == 100


def test_ingestion_stats_no_warning_for_handful_of_skips():
    """Handful of skipped docs in an otherwise healthy run shouldn't warn.

    The shape here — 33 scanned, 28 indexed, 4 failed on an unsupported
    format, 1 skipped — is a normal SharePoint crawl, not a broken ACL. Both
    the skip count and the skip ratio are well below what a permissions
    problem looks like, so flagging it would train operators to ignore the
    warning.
    """
    stats = IngestionStats(
        status="COMPLETE", scanned=33, new_indexed=24,
        modified_indexed=4, failed=4, skipped=1,
    )
    assert stats.has_acl_warning is False


def test_ingestion_stats_no_warning_for_low_skip_ratio():
    """Many skipped docs but a tiny ratio shouldn't warn either."""
    stats = IngestionStats(
        status="COMPLETE", scanned=1000, new_indexed=950,
        modified_indexed=0, failed=0, skipped=50,  # 5% — well below threshold
    )
    assert stats.has_acl_warning is False


def test_ingestion_stats_warning_at_threshold():
    """Skip ratio at the 25% threshold trips the warning."""
    stats = IngestionStats(
        status="COMPLETE", scanned=100, new_indexed=75,
        modified_indexed=0, failed=0, skipped=25,
    )
    assert stats.has_acl_warning is True



# --- Deep-merge for connector_params_overrides --------------------------------


def test_deep_merge_adds_new_top_level_key():
    """A top-level override key absent from base is added intact."""
    from kb_connector.cli.setup import _deep_merge
    base = {"type": "SHAREPOINT", "version": "1"}
    out = _deep_merge(base, {"filterConfiguration": {"modifiedDateBefore": "2026-01-01T00:00:00Z"}})
    assert out["filterConfiguration"] == {"modifiedDateBefore": "2026-01-01T00:00:00Z"}
    assert out["type"] == "SHAREPOINT"
    # Base unchanged
    assert "filterConfiguration" not in base


def test_deep_merge_recurses_into_nested_dicts():
    """Overrides on nested keys merge with the base, not replace it."""
    from kb_connector.cli.setup import _deep_merge
    base = {
        "dataEntityConfiguration": {
            "crawlFiles": True,
            "siteUrls": ["https://example.com/sites/a"],
        },
    }
    overrides = {"dataEntityConfiguration": {"crawlPages": False}}
    out = _deep_merge(base, overrides)
    de = out["dataEntityConfiguration"]
    assert de["crawlFiles"] is True
    assert de["crawlPages"] is False
    assert de["siteUrls"] == ["https://example.com/sites/a"]


def test_deep_merge_lists_replace_not_concatenate():
    """List values replace; concatenation rarely matches user intent."""
    from kb_connector.cli.setup import _deep_merge
    base = {"siteUrls": ["https://a.example.com"]}
    out = _deep_merge(base, {"siteUrls": ["https://b.example.com"]})
    assert out["siteUrls"] == ["https://b.example.com"]


def test_deep_merge_overrides_leaf_value():
    """Scalar overrides replace the base value."""
    from kb_connector.cli.setup import _deep_merge
    base = {"aclEnabled": False}
    out = _deep_merge(base, {"aclEnabled": True})
    assert out["aclEnabled"] is True
