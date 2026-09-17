"""Configuration resolution: TOML config + env vars + CLI flags.

Precedence (highest wins):
    CLI flag > [connectors.<name>] > [defaults] > env var > built-in default

Config file location (git-style lookup):
    1. --config <path>  (explicit flag)
    2. ./kb-connector.toml  (project-local — primary expected location)
    3. ~/.config/kb-connector/config.toml  (user-global defaults)

The config file is TOML (stdlib tomllib for reading, tomli-w for writing).
State is a separate JSON file (see state.py).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROJECT_LOCAL = "kb-connector.toml"
_USER_GLOBAL = Path.home() / ".config" / "kb-connector" / "config.toml"

# Environment variables honored as a low-priority fallback (below TOML config).
# Only variables that the resolver actually consumes are listed here — keep this
# in sync with .env.example. The .env file is NOT auto-loaded; these must be
# present in the process environment (e.g. exported, or injected by CI).
_ENV_VARS = {
    "AWS_REGION": "region",
    "AWS_PROFILE": "profile",
    "AZURE_TENANT_ID": "tenant_id",
}


@dataclass
class ConnectorConfig:
    """Resolved configuration for a single connector."""

    name: str
    type: str  # "sharepoint", "onedrive", "s3", "web", "confluence", "googledrive"
    raw: dict = field(default_factory=dict)  # all raw TOML fields

    # Which control plane creates the knowledge base: "bmkb" (Bedrock managed
    # KB, the default) or "quick" (Amazon Quick). The source-side setup is the
    # same either way. This selects only the AWS-side calls. See targets/base.py.
    target: str = "bmkb"

    # Common fields resolved from raw + defaults
    region: str | None = None
    profile: str | None = None
    credential: str | None = None
    acl: bool = False
    tenant_id: str | None = None
    auth_method: str | None = None

    # AWS infra
    cert_s3_bucket: str | None = None
    cert_s3_key_prefix: str | None = None
    owner: str | None = None

    # Operator-supplied tags applied to every resource the tool creates, on top
    # of the ownership tags. Exists for organizations that mandate tags such as
    # CostCenter via an SCP or tag policy, where an untagged create is denied.
    # Merged (not replaced) across [defaults.tags] and [connectors.<n>.tags].
    tags: dict = field(default_factory=dict)

    # Customer-managed KMS key for the connector secret + certificate object.
    # Unset means the AWS-managed key, which is free and needs no key
    # administration. See core/provisioning.put_secret for the tradeoff.
    kms_key_arn: str | None = None

    # KMS asymmetric signing key for the Quick admin-managed flow. Distinct from
    # kms_key_arn above in both algorithm and purpose: this one is RSA_2048
    # SIGN_VERIFY and signs Entra OAuth assertions, and its private half never
    # leaves KMS. Set `signing_key_arn` to reuse an existing key, or leave it
    # unset and the tool creates one under `signing_key_alias`.
    signing_key_arn: str | None = None
    signing_key_alias: str | None = None

    # Certificate lifetime in days. None means the CLI default. Lives in config
    # because it is a standing policy choice rather than a per-run one.
    cert_valid_days: int | None = None

    # Prefix applied to derived resource names (role, secret, KB, data source).
    # Exists for accounts running this tool more than once: two teams can use
    # the same connector name without colliding on `kb-connector-<name>-role`.
    resource_prefix: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the raw connector config."""
        return self.raw.get(key, default)


@dataclass
class ToolConfig:
    """Top-level resolved tool configuration (defaults + all connectors)."""

    defaults: dict = field(default_factory=dict)
    connectors: dict[str, dict] = field(default_factory=dict)
    config_path: str | None = None  # path to the loaded config file

    def connector_names(self) -> list[str]:
        """Return all configured connector names."""
        return list(self.connectors.keys())

    def resolve_connector(
        self,
        name: str,
        *,
        cli_overrides: dict | None = None,
    ) -> ConnectorConfig:
        """Resolve full configuration for a named connector.

        Resolution precedence: CLI flag > connector section > defaults > env var.
        """
        connector_raw = self.connectors.get(name)
        if connector_raw is None:
            from kb_connector.core.errors import ConfigError
            available = ", ".join(self.connector_names()) or "(none)"
            raise ConfigError(
                f"Connector {name!r} not found in config. "
                f"Available connectors: {available}"
            )

        connector_type = connector_raw.get("type")
        if not connector_type:
            from kb_connector.core.errors import ConfigError
            raise ConfigError(
                f"Connector {name!r} is missing required 'type' field."
            )

        overrides = cli_overrides or {}

        # The connector name and these two prefixes are interpolated into
        # derived AWS resource names, which are then interpolated into the
        # Resource ARNs of the KB role's inline policy. Validate them here, at
        # the single point every command resolves config through, so a name
        # carrying an IAM wildcard fails before the first AWS call rather than
        # silently widening a grant. See identifiers.validate_name_component.
        #
        # CLI overrides are included, and validated with the same precedence
        # `pick` applies. A key ARN supplied on the command line reaches a policy
        # Resource exactly like one from the config file, so checking only the
        # file would leave the flag as a way around the wildcard check.
        _validate_derived_name_inputs(
            name, connector_raw, self.defaults, overrides=overrides
        )
        env = _read_env_vars()
        defaults = self.defaults
        microsoft_defaults = defaults.get("microsoft", {})

        def pick(key: str, *, from_microsoft: bool = False) -> Any:
            """Pick value using resolution precedence."""
            if key in overrides and overrides[key] is not None:
                return overrides[key]
            if key in connector_raw and connector_raw[key] is not None:
                return connector_raw[key]
            if from_microsoft and key in microsoft_defaults:
                return microsoft_defaults[key]
            if key in defaults and defaults[key] is not None:
                return defaults[key]
            if key in env and env[key] is not None:
                return env[key]
            return None

        return ConnectorConfig(
            name=name,
            type=connector_type,
            raw=connector_raw,
            target=_validate_target(pick("target")),
            region=pick("region"),
            profile=pick("profile"),
            credential=pick("credential"),
            acl=bool(pick("acl")),
            tenant_id=pick("tenant_id", from_microsoft=True),
            auth_method=pick("auth_method", from_microsoft=True),
            cert_s3_bucket=pick("cert_s3_bucket"),
            cert_s3_key_prefix=pick("cert_s3_key_prefix"),
            owner=pick("owner"),
            tags=_merge_tags(defaults, connector_raw),
            kms_key_arn=pick("kms_key_arn"),
            signing_key_arn=pick("signing_key_arn"),
            signing_key_alias=pick("signing_key_alias"),
            cert_valid_days=_validate_cert_valid_days(
                pick("cert_valid_days", from_microsoft=True)
            ),
            resource_prefix=pick("resource_prefix"),
        )


def _validate_cert_valid_days(raw: Any) -> int | None:
    """Check cert_valid_days is a usable positive integer.

    Checked here so a bad value fails before an Entra app registration exists,
    rather than at the point the certificate is built. `bool` is excluded
    explicitly because it is a subclass of `int`, and `cert_valid_days = true`
    would otherwise silently mean one day.
    """
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        from kb_connector.core.errors import ConfigError
        raise ConfigError(
            f"cert_valid_days must be a positive integer, got {raw!r}."
        )
    if raw < 1:
        from kb_connector.core.errors import ConfigError
        raise ConfigError(
            f"cert_valid_days must be at least 1, got {raw}."
        )
    return raw


def _validate_target(raw: Any) -> str:
    """Normalize and check the `target` value, defaulting to bmkb.

    Checked at config resolution so a typo names the valid options immediately,
    rather than reaching get_target and raising a ValueError partway through a
    setup that has already made source-side changes.
    """
    from kb_connector.targets import DEFAULT_TARGET, TARGET_NAMES, normalize_target

    if raw is None:
        return DEFAULT_TARGET
    if not isinstance(raw, str):
        from kb_connector.core.errors import ConfigError
        raise ConfigError(
            f"target must be a string, not {type(raw).__name__}."
        )
    name = normalize_target(raw)
    if name not in TARGET_NAMES:
        from kb_connector.core.errors import ConfigError
        expected = ", ".join(sorted(TARGET_NAMES))
        raise ConfigError(
            f"Unknown target {raw!r}. Expected one of: {expected}."
        )
    return name


def _validate_derived_name_inputs(
    name: str,
    connector_raw: dict,
    defaults: dict,
    *,
    overrides: dict | None = None,
) -> None:
    """Reject config values that would corrupt a derived AWS resource name.

    Raises ConfigError so the CLI reports it as a configuration problem.
    """
    from kb_connector.core.errors import ConfigError, ConnectorError
    from kb_connector.core.identifiers import (
        validate_arn,
        validate_name_component,
        validate_s3_key_prefix,
    )

    # kms_key_arn is interpolated straight into the Resource of the KB role's
    # KMS statement. Checked as a KMS ARN specifically, so an ARN for some other
    # service cannot pass just because it parses; and rejected outright if it
    # carries an IAM wildcard, since `key/*` would grant the role every key in
    # the account rather than the one the connector needs.
    # Both key ARNs reach a policy Resource: kms_key_arn in the KB role's inline
    # policy, signing_key_arn in the kms:Sign grant for the Quick service role
    # (see core.kms_signing.build_sign_grant_statement). Same two checks apply to
    # each, so they are validated together.
    over = overrides or {}
    for field_name in ("kms_key_arn", "signing_key_arn"):
        key_arn = (
            over.get(field_name)
            or connector_raw.get(field_name)
            or defaults.get(field_name)
        )
        if key_arn is None:
            continue
        try:
            checked = validate_arn(key_arn, field=field_name, service="kms")
        except ConnectorError as exc:
            raise ConfigError(str(exc)) from exc
        if "*" in checked or "?" in checked:
            raise ConfigError(
                f"{field_name} {key_arn!r} contains an IAM wildcard. Give the "
                f"ARN of the single key this connector should use."
            )

    checks: list[tuple[str, object, bool]] = [
        (f"connector name {name!r}", name, False),
        ("resource_prefix", over.get("resource_prefix")
         or connector_raw.get("resource_prefix")
         or defaults.get("resource_prefix"), False),
        ("cert_s3_key_prefix", over.get("cert_s3_key_prefix")
         or connector_raw.get("cert_s3_key_prefix")
         or defaults.get("cert_s3_key_prefix"), True),
        # The signing key's alias is interpolated into `alias/<value>` and used
        # to address a KMS key, so it gets the same treatment as the other
        # derived-name inputs.
        ("signing_key_alias", over.get("signing_key_alias")
         or connector_raw.get("signing_key_alias")
         or defaults.get("signing_key_alias"), False),
    ]
    for label, value, is_prefix in checks:
        if value is None:
            continue
        try:
            if is_prefix:
                validate_s3_key_prefix(value, field=label)
            else:
                validate_name_component(value, field=label)
        except ConnectorError as exc:
            raise ConfigError(str(exc)) from exc


def _merge_tags(defaults: dict, connector_raw: dict) -> dict:
    """Merge operator tag tables, with the connector's entries winning per key.

    Merged rather than picked so an account-wide [defaults.tags] set (CostCenter,
    Owner) doesn't have to be restated in full by a connector that only needs to
    add or override one entry. Values are validated later, at provisioning time,
    so a bad entry surfaces once with a clear message.
    """
    merged: dict = {}
    for source in (defaults.get("tags"), connector_raw.get("tags")):
        if isinstance(source, dict):
            merged.update(source)
    return merged


def load_config(config_path: str | None = None) -> ToolConfig:
    """Load and parse the TOML config file.

    Searches in order: explicit path, project-local, user-global.
    Returns an empty ToolConfig if no file is found (not an error —
    commands can work without a config via CLI flags).
    """
    import tomllib

    path = _find_config_file(config_path)
    if path is None:
        return ToolConfig()

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        from kb_connector.core.errors import ConfigError
        raise ConfigError(f"Failed to read config file {path}: {exc}") from exc

    defaults = raw.get("defaults", {})
    connectors = raw.get("connectors", {})

    return ToolConfig(
        defaults=defaults,
        connectors=connectors,
        config_path=path,
    )


def _find_config_file(explicit_path: str | None) -> str | None:
    """Locate the config file using the git-style search order."""
    if explicit_path:
        if os.path.isfile(explicit_path):
            return explicit_path
        from kb_connector.core.errors import ConfigError
        raise ConfigError(f"Config file not found: {explicit_path}")

    # Project-local
    local = os.path.join(os.getcwd(), _PROJECT_LOCAL)
    if os.path.isfile(local):
        return local

    # User-global
    if _USER_GLOBAL.is_file():
        return str(_USER_GLOBAL)

    return None


def _read_env_vars() -> dict[str, str | None]:
    """Read recognized environment variables."""
    result: dict[str, str | None] = {}
    for env_key, config_key in _ENV_VARS.items():
        value = os.environ.get(env_key)
        if value:
            result[config_key] = value
    return result
