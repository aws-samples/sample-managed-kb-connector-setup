"""init subcommand — interactive config builder.

Walks through creating a kb-connector.toml configuration file:
- Smart defaults from AWS config
- Validates inputs as it goes
- Connector-aware prompts (only asks relevant questions)
- Additive: --add adds a connector without re-prompting defaults
- Batch: --from generates from a fixture JSON (non-interactive)
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from kb_connector.connectors.base import Field
from kb_connector.core.errors import ConfigError, ConnectorError
from kb_connector.core.fileio import atomic_write_bytes


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the init subcommand."""
    parser = subparsers.add_parser(
        "init",
        help="Create or update the configuration file interactively",
        description=(
            "Walk through creating a kb-connector.toml configuration file. "
            "Validates inputs as you go and supports adding multiple connectors."
        ),
    )
    parser.add_argument(
        "--add", action="store_true", help="Add a connector to existing config"
    )
    parser.add_argument(
        "--from", dest="from_file", metavar="FILE",
        help="Generate config from a fixture JSON (non-interactive)",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", default="./kb-connector.toml",
        help="Output file path (default: ./kb-connector.toml)",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    """Execute the init subcommand."""
    try:
        if getattr(args, "from_file", None):
            return _init_from_fixture(args)
        if getattr(args, "non_interactive", False):
            print("Error: init requires interactive mode. Use --from for non-interactive.", file=sys.stderr)
            return 1
        return _init_interactive(args)
    except ConnectorError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n\nCanceled.")
        return 1


def _init_interactive(args: argparse.Namespace) -> int:
    """Interactive config builder."""
    import tomli_w

    output_path = args.output
    existing_config: dict = {}

    # Load existing config if --add mode
    if args.add and os.path.isfile(output_path):
        import tomllib
        with open(output_path, "rb") as f:
            existing_config = tomllib.load(f)

    print("\n  KB Connector Helper — Configuration Setup\n")

    # Defaults section
    if not args.add:
        defaults = _prompt_defaults()
    else:
        defaults = existing_config.get("defaults", {})
        print(f"  Using existing defaults from {output_path}")

    # Connectors section
    connectors = existing_config.get("connectors", {})
    while True:
        connector = _prompt_connector(defaults)
        if connector is None:
            break
        name, config = connector
        connectors[name] = config
        print()
        if not _prompt_yn("  Add another connector?", default=False):
            break

    if not connectors:
        print("\n  No connectors added. Config not written.")
        return 0

    # Build and write TOML. Written 0600 like every other file this tool
    # produces: the config carries the tenant id, AWS account detail, site URLs
    # and operator email addresses, which is the reconnaissance material the
    # owner-only policy exists to cover. See core/fileio.
    doc: dict = {"defaults": defaults, "connectors": connectors}
    atomic_write_bytes(output_path, tomli_w.dumps(doc).encode("utf-8"))

    print(f"\n  ✓ Config written to {output_path} (mode 0600)")
    first_name = next(iter(connectors))
    print(f"\n  Next: run `kb-connector setup {first_name}` to begin.")
    return 0


def _init_from_fixture(args: argparse.Namespace) -> int:
    """Generate config from a JSON fixture file."""
    import json
    import tomli_w

    fixture_path = args.from_file
    if not os.path.isfile(fixture_path):
        raise ConfigError(f"Fixture file not found: {fixture_path}")

    with open(fixture_path, encoding="utf-8") as f:
        fixture = json.load(f)

    # Fixture shape: {"defaults": {...}, "connectors": {"name": {...}}}
    doc = {
        "defaults": fixture.get("defaults", {}),
        "connectors": fixture.get("connectors", {}),
    }

    output_path = args.output
    atomic_write_bytes(output_path, tomli_w.dumps(doc).encode("utf-8"))

    print(f"  ✓ Config generated from {fixture_path} -> {output_path} (mode 0600)")
    return 0


# --- Interactive prompts (plain input + ANSI, no TUI deps) -------------------


def _prompt(label: str, *, default: str = "", validate: str | None = None) -> str:
    """Prompt for a value with optional default and validation."""
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"  ? {label}{suffix}: ").strip()
        if not value and default:
            return default
        if not value:
            print("    (required)")
            continue
        if validate and not re.match(validate, value):
            print("    (invalid format)")
            continue
        return value


def _prompt_optional(label: str, *, default: str = "") -> str:
    """Prompt for an optional value."""
    suffix = f" [{default}]" if default else " (blank to skip)"
    value = input(f"  ? {label}{suffix}: ").strip()
    return value or default


def _prompt_yn(label: str, *, default: bool = True) -> bool:
    """Prompt for a yes/no answer."""
    hint = "(Y/n)" if default else "(y/N)"
    value = input(f"{label} {hint}: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def _prompt_choice(label: str, choices: list[str], *, default: str = "") -> str:
    """Prompt for a choice from a list."""
    print(f"  ? {label}:")
    for i, c in enumerate(choices):
        marker = "❯" if c == default else " "
        print(f"    {marker} {c}")
    while True:
        value = input(f"    choice [{default}]: ").strip().lower()
        if not value and default:
            return default
        if value in choices:
            return value
        print(f"    (choose from: {', '.join(choices)})")


def _prompt_defaults() -> dict:
    """Prompt for the [defaults] section."""
    defaults: dict = {}

    region = _prompt("AWS region", default="us-west-2")
    defaults["region"] = region

    profile = _prompt_optional("AWS profile (blank for default chain)")
    if profile:
        defaults["profile"] = profile

    prefix = _prompt_optional("Prefix for derived resource names")
    if prefix:
        defaults["resource_prefix"] = prefix

    cert_bucket = _prompt_optional("S3 bucket for certificates")
    if cert_bucket:
        defaults["cert_s3_bucket"] = cert_bucket

    # Microsoft defaults
    if _prompt_yn("\n  Configure Microsoft Entra defaults?", default=False):
        ms: dict = {}
        tenant_id = _prompt("Microsoft Entra tenant ID",
                            validate=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        ms["tenant_id"] = tenant_id
        auth_method = _prompt_choice("Auth method", ["az", "device_code"], default="az")
        ms["auth_method"] = auth_method
        defaults["microsoft"] = ms

    return defaults


def _prompt_connector(defaults: dict) -> tuple[str, dict] | None:
    """Prompt for one connector. Returns None to stop.

    The questions come from the connector's spec: every required key, plus the
    keys marked `ask`. Answers equal to a key's default are not written.
    """
    from kb_connector.connectors import all_specs

    if not _prompt_yn("\n  Add a connector?", default=True):
        return None

    name = _prompt("Connector name (short label)")
    specs = all_specs()
    connector_type = _prompt_choice("Connector type", list(specs))
    spec = specs[connector_type]

    config: dict = {"type": connector_type}
    for f in spec.fields:
        if not (f.required or f.ask):
            continue
        if f.key == "tenant_id" and defaults.get("microsoft", {}).get("tenant_id"):
            continue
        if f.key == "sites_selected" and connector_type != "sharepoint":
            continue
        value = _prompt_field(f)
        if value is not None and value != f.default:
            config[f.key] = value
    return name, config


_TENANT_ID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


def _prompt_field(f: Field) -> object:
    """Ask for one field's value, parsed to its kind. None means left blank."""
    label = f"{f.help.rstrip('.')} [{f.key}]"
    kinds = f.kind if isinstance(f.kind, tuple) else (f.kind,)
    if bool in kinds:
        return _prompt_yn(f"  {label}?", default=bool(f.default))
    if f.choices:
        return _prompt_choice(label, list(f.choices), default=f.default or "")
    if list in kinds:
        return _prompt_list(label, required=f.required)
    if int in kinds:
        while True:
            raw = _prompt_optional(label)
            if not raw:
                return None
            if raw.isdigit():
                return int(raw)
            print("    (a whole number)")
    validate = _TENANT_ID_RE if f.key == "tenant_id" else None
    if f.required:
        return _prompt(label, validate=validate)
    return _prompt_optional(label) or None


def _prompt_list(label: str, *, required: bool) -> list[str] | None:
    """Ask for values one at a time until a blank line."""
    values: list[str] = []
    while True:
        prompt = label if not values else "  another (blank to finish)"
        value = _prompt(prompt) if required and not values else _prompt_optional(prompt)
        if not value:
            return values or None
        values.append(value)
