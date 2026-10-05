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

    type = "s3"
    api_type = "S3"
    provider = None
    fields = (
        Field("bucket_name", str, "Bucket to crawl.", required=True, ask=True),
        Field("bucket_owner_account_id", str,
              "Account that owns the bucket. Defaults to the caller's account."),
        Field("acl", bool, "Document-level access control. Cannot be changed later.",
              default=False, ask=True),
        Field("acl_s3_uri", str, "S3 URI of the global ACL file. Used when acl is true."),
        Field("inclusion_prefixes", list, "Only crawl these key prefixes.", ask=True),
        Field("exclusion_prefixes", list, "Skip these key prefixes."),
        Field("inclusion_patterns", list, "Only crawl keys matching these patterns.",
              ask=True),
        Field("exclusion_patterns", list, "Skip keys matching these patterns.", ask=True),
        Field("max_file_size_mb", (int, str), MAX_FILE_SIZE_HELP, ask=True),
        Field("metadata_files_prefix", str, "Prefix of .metadata.json sidecar files."),
    )

    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        max_size = self.value(cfg, "max_file_size_mb")
        return build_connector_params(
            bucket_name=self.value(cfg, "bucket_name") or "",
            bucket_owner_account_id=(
                self.value(cfg, "bucket_owner_account_id") or ctx.account_id
            ),
            acl=cfg.acl if ctx.acl is None else ctx.acl,
            acl_s3_uri=self.value(cfg, "acl_s3_uri"),
            inclusion_prefixes=self.value(cfg, "inclusion_prefixes"),
            exclusion_prefixes=self.value(cfg, "exclusion_prefixes"),
            inclusion_patterns=self.value(cfg, "inclusion_patterns"),
            exclusion_patterns=self.value(cfg, "exclusion_patterns"),
            # The service takes this field as a string.
            max_file_size_mb=None if max_size is None else str(max_size),
            metadata_files_prefix=self.value(cfg, "metadata_files_prefix"),
        )

    def check(self, cfg: ConnectorConfig, overrides: RequestOverrides) -> None:
        check_max_file_size(cfg.get("max_file_size_mb"), overrides)
