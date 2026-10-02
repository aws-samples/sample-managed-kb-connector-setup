"""Request-level overrides for CreateKnowledgeBase and CreateDataSource.

A connector's `overrides` table deep-merges into the request bodies setup builds:

    [connectors.<name>.overrides.create_data_source]
    [connectors.<name>.overrides.create_knowledge_base]

This reaches every field of those requests, including the ones outside
`connectorParameters` (`mediaExtractionConfiguration`,
`deletionProtectionConfiguration`, `dataDeletionPolicy`,
`vectorIngestionConfiguration`). `connector_params_overrides` is still read; it
applies to `connectorParameters` first, then `overrides.create_data_source`
applies on top.

Fields setup derives itself are refused: `name`, `roleArn`, `knowledgeBaseId`
and `clientToken` have CLI flags or are tracked in state, and tags go through
the same checks as the `[tags]` table so ownership tags cannot be set. Everything
else is checked against the installed botocore model before any AWS call, so a
misspelled field fails at the start of setup. `connectorParameters` is a
free-form document in that model, so its contents are checked only by the
service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kb_connector.core.errors import ConfigError

CREATE_DATA_SOURCE = "create_data_source"
CREATE_KNOWLEDGE_BASE = "create_knowledge_base"
_TABLES = (CREATE_DATA_SOURCE, CREATE_KNOWLEDGE_BASE)

# Top-level request fields setup sets itself, and where to set them instead.
_RESERVED = {
    "name": "pass --kb-name or --ds-name",
    "roleArn": "pass --kb-role-arn",
    "knowledgeBaseId": "it comes from the knowledge base setup creates or --kb",
    "clientToken": "the SDK generates it per request",
}

# Path from the CreateDataSource request root to connectorParameters.
_CONNECTOR_PARAMS_PATH = (
    "dataSourceConfiguration",
    "managedKnowledgeBaseConnectorConfiguration",
    "connectorParameters",
)


@dataclass(frozen=True)
class RequestOverrides:
    """Validated overrides for each request. Empty dicts mean none."""

    create_data_source: dict = field(default_factory=dict)
    create_knowledge_base: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.create_data_source or self.create_knowledge_base)


def deep_merge(base: dict, overrides: dict) -> dict:
    """Recursively merge `overrides` into `base`, returning a new dict.

    Nested dicts merge key by key; any other value replaces what was there.
    Lists replace rather than concatenate, since concatenation rarely matches
    intent for fields like inclusionItemPaths.
    """
    out = dict(base)
    for key, val in overrides.items():
        if key in out and isinstance(out[key], dict) and isinstance(val, dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load(raw: dict) -> RequestOverrides:
    """Read and check the overrides in a connector's raw config.

    Raises ConfigError for a malformed table, an unknown request name, a
    reserved field, or tags that fail the `[tags]` checks.
    """
    cds: dict = {}
    legacy = raw.get("connector_params_overrides")
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise ConfigError("connector_params_overrides must be a table.")
        cds = _nest(_CONNECTOR_PARAMS_PATH, legacy)

    tables = raw.get("overrides")
    if tables is None:
        return RequestOverrides(create_data_source=cds)
    if not isinstance(tables, dict):
        raise ConfigError("overrides must be a table of request tables.")
    unknown = sorted(set(tables) - set(_TABLES))
    if unknown:
        raise ConfigError(
            f"Unknown overrides table(s): {', '.join(unknown)}. "
            f"Expected: {', '.join(_TABLES)}."
        )
    for name in _TABLES:
        body = tables.get(name, {})
        if not isinstance(body, dict):
            raise ConfigError(f"overrides.{name} must be a table.")
        _check_reserved(name, body)

    cds = deep_merge(cds, tables.get(CREATE_DATA_SOURCE, {}))
    return RequestOverrides(
        create_data_source=cds,
        create_knowledge_base=dict(tables.get(CREATE_KNOWLEDGE_BASE, {})),
    )


def check_against_model(overrides: RequestOverrides) -> None:
    """Validate the overridden requests against the installed botocore model.

    Builds each request with placeholder values for what setup fills in at run
    time, merges the overrides, and runs botocore's parameter validation. Makes
    no network call. Raises ConfigError naming every invalid field.
    """
    if not overrides:
        return
    from kb_connector.core.knowledge_base import (
        build_data_source_payload,
        build_knowledge_base_payload,
    )

    placeholder_role = "arn:aws:iam::111122223333:role/placeholder"
    requests = {
        CREATE_KNOWLEDGE_BASE: (
            "CreateKnowledgeBase",
            build_knowledge_base_payload(name="placeholder", role_arn=placeholder_role),
            overrides.create_knowledge_base,
        ),
        CREATE_DATA_SOURCE: (
            "CreateDataSource",
            {
                "knowledgeBaseId": "PLACEHOLDR",
                **build_data_source_payload(name="placeholder", connector_parameters={}),
            },
            overrides.create_data_source,
        ),
    }
    problems: list[str] = []
    for table, (operation, base, extra) in requests.items():
        if not extra:
            continue
        error = _validate(operation, deep_merge(base, extra))
        if error:
            problems.append(f"overrides.{table}: {error}")
    if problems:
        raise ConfigError(
            "Request overrides do not match the installed botocore model for "
            "bedrock-agent:\n  " + "\n  ".join(problems) + "\n"
            "Check the field names against the API reference. A field newer than "
            "the installed botocore also fails here; upgrade boto3 to use it."
        )


def _validate(operation: str, params: dict) -> str | None:
    import botocore.session
    from botocore.exceptions import ParamValidationError
    from botocore.validate import validate_parameters

    model = botocore.session.get_session().get_service_model("bedrock-agent")
    shape = model.operation_model(operation).input_shape
    if shape is None:  # both operations take input; guards a model without it
        return f"{operation} has no input shape in the installed botocore model."
    try:
        validate_parameters(params, shape)
    except ParamValidationError as exc:
        return str(exc).replace("Parameter validation failed:\n", "").replace("\n", "; ")
    return None


def _check_reserved(table: str, body: dict) -> None:
    for key, hint in _RESERVED.items():
        if key in body:
            raise ConfigError(
                f"overrides.{table}.{key} is set by setup and cannot be "
                f"overridden; {hint}."
            )
    if "tags" in body:
        from kb_connector.core.tagging import validate_extra_tags

        try:
            validate_extra_tags(body["tags"])
        except ValueError as exc:
            raise ConfigError(f"overrides.{table}.tags: {exc}") from exc


def _nest(path: tuple[str, ...], leaf: dict) -> dict:
    out: dict[str, Any] = dict(leaf)
    for key in reversed(path):
        out = {key: out}
    return out
