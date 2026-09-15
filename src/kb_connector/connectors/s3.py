"""S3 connector — bucket, filter, ACL sidecar configuration.

The S3 connector needs no third-party identity provider. Like every other
managed connector, it uses the managed-connector envelope (not the classic
first-class S3 data source shape):

  * type=S3, version=1
  * connectionConfiguration.{bucketName, bucketOwnerAccountId}
  * filterConfiguration.{inclusionPrefixes, exclusionPrefixes,
    inclusionPatterns, exclusionPatterns, maxFileSizeInMegaBytes}
  * aclEnabled (top-level) + aclConfiguration.globalAccessControlListS3Uri
  * metadataFilesPrefix (top-level)

Notes: the field is bucketName (not bucketArn); ACL uses aclConfiguration (not
accessControlConfiguration); maxFileSizeInMegaBytes is a string.
"""

from __future__ import annotations

from kb_connector.connectors.base import ConfigField, ConnectorSpec
from kb_connector.interactive import SetupStep


def build_connector_params(
    *,
    bucket_name: str,
    bucket_owner_account_id: str | None = None,
    acl: bool = False,
    acl_s3_uri: str | None = None,
    inclusion_prefixes: list[str] | None = None,
    exclusion_prefixes: list[str] | None = None,
    inclusion_patterns: list[str] | None = None,
    exclusion_patterns: list[str] | None = None,
    max_file_size_mb: str | int | None = None,
    metadata_files_prefix: str | None = None,
) -> dict:
    """Build the connectorParameters JSON for an S3 managed-connector data source.

    Wrapped in the MANAGED_KNOWLEDGE_BASE_CONNECTOR envelope by the target,
    same as every other managed connector.

    Note: the service requires bucketOwnerAccountId — CreateDataSource fails
    with "connectionConfiguration.bucketOwnerAccountId ... must not be null" if
    omitted. Callers should pass the caller's account for same-account buckets,
    or the owner's account for cross-account.
    """
    connection: dict = {"bucketName": bucket_name}
    if bucket_owner_account_id:
        connection["bucketOwnerAccountId"] = bucket_owner_account_id

    params: dict = {
        "type": "S3",
        "version": "1",
        "connectionConfiguration": connection,
    }

    filter_config: dict = {}
    if inclusion_prefixes:
        filter_config["inclusionPrefixes"] = inclusion_prefixes
    if exclusion_prefixes:
        filter_config["exclusionPrefixes"] = exclusion_prefixes
    if inclusion_patterns:
        filter_config["inclusionPatterns"] = inclusion_patterns
    if exclusion_patterns:
        filter_config["exclusionPatterns"] = exclusion_patterns
    if max_file_size_mb is not None:
        filter_config["maxFileSizeInMegaBytes"] = max_file_size_mb
    if filter_config:
        params["filterConfiguration"] = filter_config

    # ACL: aclEnabled is the top-level toggle; aclConfiguration carries the
    # global ACL file URI (declarative — no crawl-time permission checking).
    if acl:
        params["aclEnabled"] = True
        if acl_s3_uri:
            params["aclConfiguration"] = {"globalAccessControlListS3Uri": acl_s3_uri}

    if metadata_files_prefix:
        params["metadataFilesPrefix"] = metadata_files_prefix

    return params


class S3Connector(ConnectorSpec):
    """S3 managed connector spec."""

    connector_type = "S3"
    provider = None  # no 3P identity provider

    def setup_steps(self, config: dict) -> list[SetupStep]:
        return []  # S3 setup is driven directly by cli/setup.py

    def build_connector_params(self, config: dict, state: dict) -> dict:
        return build_connector_params(
            bucket_name=config["bucket_name"],
            bucket_owner_account_id=config.get("bucket_owner_account_id"),
            acl=config.get("acl", False),
            acl_s3_uri=config.get("acl_s3_uri"),
            inclusion_prefixes=config.get("inclusion_prefixes"),
            exclusion_prefixes=config.get("exclusion_prefixes"),
            inclusion_patterns=config.get("inclusion_patterns"),
            exclusion_patterns=config.get("exclusion_patterns"),
            max_file_size_mb=config.get("max_file_size_mb"),
            metadata_files_prefix=config.get("metadata_files_prefix"),
        )

    def build_secret_body(self, config: dict, state: dict) -> dict | None:
        return None  # S3 connector uses no secret

    def config_fields(self) -> list[ConfigField]:
        return [
            ConfigField("bucket_name", required=True, prompt="S3 bucket name"),
            ConfigField("bucket_owner_account_id", required=False,
                        prompt="Bucket owner account (12-digit, for cross-account)"),
            ConfigField("acl", type=bool, default=False,
                        prompt="Enable document-level ACL?",
                        warning="Permanent — cannot be disabled after creation"),
            ConfigField("acl_s3_uri", required_if="acl",
                        prompt="S3 URI to global ACL JSON file"),
            ConfigField("inclusion_prefixes", type=list, required=False,
                        prompt="Include only objects with these prefixes"),
            ConfigField("exclusion_prefixes", type=list, required=False,
                        prompt="Exclude objects with these prefixes"),
            ConfigField("metadata_files_prefix", required=False,
                        prompt="Prefix for .metadata.json sidecar files"),
        ]
