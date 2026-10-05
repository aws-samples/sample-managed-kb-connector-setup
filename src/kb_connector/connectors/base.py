"""Connector specs: the config keys each connector reads and its request builder.

Each connector declares its keys once, as `Field`s. The same declarations drive
config checking (unknown keys and wrong types), `init` prompts, and
CONFIG-REFERENCE.md. `build_connector_params` is the only mapping from config to
`connectorParameters`; setup calls it, and so do the tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from kb_connector.interactive import SetupStep

if TYPE_CHECKING:
    from kb_connector.core.config import ConnectorConfig
    from kb_connector.core.overrides import RequestOverrides


@dataclass(frozen=True)
class Field:
    """One config key.

    `kind` is the TOML type, or a tuple of accepted types. `in_params` is False
    for keys setup uses that do not appear in `connectorParameters` (resource
    names, test inputs, credentials collected at setup). `ask` makes `init`
    prompt for the key.
    """

    key: str
    kind: type | tuple[type, ...]
    help: str
    required: bool = False
    default: Any = None
    choices: tuple[str, ...] = ()
    in_params: bool = True
    ask: bool = False


@dataclass(frozen=True)
class BuildContext:
    """Values setup resolves at run time, which config does not hold."""

    account_id: str | None = None
    secret_arn: str | None = None
    cert_s3_bucket: str | None = None
    cert_s3_key: str | None = None
    # Set when setup changes the configured ACL (Quick OneDrive forces it on).
    acl: bool | None = None


# Keys every connector accepts. None of them reach connectorParameters directly.
COMMON_FIELDS: tuple[Field, ...] = (
    Field("type", str, "Connector type.", required=True, in_params=False,
          choices=("sharepoint", "onedrive", "s3", "web", "confluence", "googledrive")),
    Field("target", str, "Control plane that holds the knowledge base: bmkb or quick.",
          default="bmkb", in_params=False),
    Field("region", str, "AWS Region for every resource the connector creates.",
          in_params=False),
    Field("profile", str, "AWS profile to use.", in_params=False),
    Field("resource_prefix", str,
          "Prefix for derived resource names, so connectors in one account cannot collide.",
          in_params=False),
    Field("kms_key_arn", str,
          "Customer-managed KMS key for the knowledge base, secret and certificate object.",
          in_params=False),
    Field("owner", str, "Free-form owner label. Not used by setup.", in_params=False),
    Field("tags", dict, "Extra tags applied to every resource the tool creates.",
          in_params=False),
    Field("validation", dict,
          "Inputs for `validate`: query, authorized_user, unauthorized_user.",
          in_params=False),
    Field("overrides", dict,
          "Request overrides for create_data_source and create_knowledge_base.",
          in_params=False),
    Field("connector_params_overrides", dict,
          "Deep-merged into connectorParameters.", in_params=False),
)

VALIDATION_KEYS = ("query", "authorized_user", "unauthorized_user")

# Keys shared by SharePoint and OneDrive. Setup reads them; none reach
# connectorParameters except tenant_id.
MICROSOFT_FIELDS: tuple[Field, ...] = (
    Field("tenant_id", str,
          "Microsoft Entra tenant id. Can be set once in [defaults.microsoft].",
          required=True, ask=True),
    Field("auth_method", str, "How setup gets a Microsoft Graph token.",
          default="az", choices=("az", "device_code"), in_params=False),
    Field("cert_s3_bucket", str,
          "Bucket for the certificate. Defaults to `kb-connector-certs-<account>-<region>`.",
          in_params=False),
    Field("cert_s3_key_prefix", str, "Key prefix for the certificate object.",
          in_params=False),
    Field("cert_valid_days", int, "Certificate lifetime in days.", default=365,
          in_params=False),
    Field("signing_key_arn", str, "Quick target: existing KMS signing key to use.",
          in_params=False),
    Field("signing_key_alias", str, "Quick target: alias for the KMS signing key.",
          in_params=False),
    Field("sites_selected", bool,
          "Grant per-site access with Sites.Selected instead of tenant-wide read. "
          "SharePoint only.",
          default=False, in_params=False, ask=True),
)


class ConnectorSpec(ABC):
    """A connector's config keys and how they become `connectorParameters`."""

    type: str               # config `type`
    api_type: str           # connectorParameters `type`
    provider: str | None    # identity provider, if any
    fields: tuple[Field, ...] = ()

    @abstractmethod
    def build_connector_params(self, cfg: ConnectorConfig, ctx: BuildContext) -> dict:
        """Build the connectorParameters body from config and run-time values."""

    def check(self, cfg: ConnectorConfig, overrides: RequestOverrides) -> None:
        """Raise ConfigError for a value the service would reject.

        Runs before setup makes any call, so a bad value never leaves partly
        created resources.
        """

    def setup_steps(self, config: dict) -> list[SetupStep]:
        """Guided source-side steps, for connectors whose provider is not automated."""
        return []

    def all_fields(self) -> tuple[Field, ...]:
        return COMMON_FIELDS + self.fields

    def field(self, key: str) -> Field:
        for f in self.all_fields():
            if f.key == key:
                return f
        raise KeyError(key)

    def value(self, cfg: ConnectorConfig, key: str) -> Any:
        """The configured value for `key`, or the field's default."""
        return cfg.get(key, self.field(key).default)


def fields_by_key(fields: Iterable[Field]) -> dict[str, Field]:
    return {f.key: f for f in fields}


# --- max_file_size_mb ------------------------------------------------------------

MAX_FILE_SIZE_HELP = (
    "Largest file to crawl, in MB. 1 to 500 without media extraction; "
    "up to 1500 with it."
)
_MAX_WITHOUT_MEDIA = 500
# The service accepted 1500 with media extraction on. The documented per-file
# video limit is 1.5 GB; a larger value is passed through with a warning.
_MAX_WITH_MEDIA = 1500


def media_extraction_enabled(overrides: RequestOverrides) -> bool:
    """Whether the data source overrides turn on any media extraction."""
    managed = (
        overrides.create_data_source.get("dataSourceConfiguration", {})
        .get("managedKnowledgeBaseConnectorConfiguration", {})
    )
    media = managed.get("mediaExtractionConfiguration") or {}
    for sub in media.values():
        if isinstance(sub, dict) and any(v == "ENABLED" for v in sub.values()):
            return True
    return False


def check_max_file_size(raw: Any, overrides: RequestOverrides) -> None:
    """Raise ConfigError for a max_file_size_mb the service rejects."""
    import warnings

    from kb_connector.core.config import ConfigWarning
    from kb_connector.core.errors import ConfigError

    if raw is None:
        return
    try:
        if isinstance(raw, bool):
            raise ValueError
        size = int(str(raw).strip())
    except ValueError:
        raise ConfigError(
            f"max_file_size_mb must be a whole number of megabytes, got {raw!r}."
        ) from None
    if size < 1:
        raise ConfigError(f"max_file_size_mb must be at least 1, got {size}.")
    if media_extraction_enabled(overrides):
        if size > _MAX_WITH_MEDIA:
            warnings.warn(
                f"max_file_size_mb = {size} is above {_MAX_WITH_MEDIA}, the largest "
                f"value verified with media extraction. The service may reject it.",
                ConfigWarning, stacklevel=2,
            )
        return
    if size > _MAX_WITHOUT_MEDIA:
        raise ConfigError(
            f"max_file_size_mb = {size} is above {_MAX_WITHOUT_MEDIA}, the service's "
            f"limit without media extraction. Lower it, or turn on media extraction "
            f"with overrides.create_data_source (see README, Request overrides)."
        )
