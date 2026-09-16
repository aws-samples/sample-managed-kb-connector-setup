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

    owner = _prompt_optional("Owner name (suffixes resource names)")
    if owner:
        defaults["owner"] = owner

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
    """Prompt for a single connector definition. Returns None to stop."""
    if not _prompt_yn("\n  Add a connector?", default=True):
        return None

    name = _prompt("Connector name (short label)")
    connector_type = _prompt_choice(
        "Connector type",
        ["sharepoint", "onedrive", "s3", "web", "confluence", "googledrive"],
    )

    config: dict = {"type": connector_type}

    if connector_type in ("sharepoint", "onedrive"):
        _prompt_microsoft_connector(config, connector_type, defaults)
    elif connector_type == "s3":
        _prompt_s3_connector(config)
    elif connector_type == "web":
        _prompt_web_connector(config)
    elif connector_type == "confluence":
        _prompt_confluence_connector(config)
    elif connector_type == "googledrive":
        _prompt_googledrive_connector(config)

    return name, config


def _prompt_microsoft_connector(config: dict, connector_type: str, defaults: dict) -> None:
    """Prompt for SharePoint/OneDrive-specific fields."""
    # Tenant ID (may already be in defaults)
    ms_defaults = defaults.get("microsoft", {})
    if not ms_defaults.get("tenant_id"):
        tenant_id = _prompt("Microsoft Entra tenant ID",
                            validate=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        config["tenant_id"] = tenant_id

    # SharePoint only has one usable mode, so there's nothing to choose:
    # 'client_secret' can't supply the certificateS3Path the connector requires,
    # and 'ropc' isn't automated here (see KNOWN-LIMITATIONS.md).
    if connector_type == "sharepoint":
        credential = "cert"
        print("  Credential mode: cert (the only mode SharePoint supports)")
    else:
        credential = _prompt_choice(
            "Credential mode",
            ["cert", "client_secret", "oauth2_refresh"],
            default="cert",
        )
    config["credential"] = credential

    acl = _prompt_yn("  Enable ACL (document-level access control)?", default=True)
    config["acl"] = acl

    if connector_type == "sharepoint":
        urls: list[str] = []
        while True:
            url = _prompt("SharePoint site URL")
            urls.append(url)
            if not _prompt_yn("  Add another site URL?", default=False):
                break
        config["site_urls"] = urls

        host = _prompt_optional("SharePoint host (e.g. contoso.sharepoint.com)")
        if host:
            config["sharepoint_host"] = host

        if _prompt_yn("  Use Sites.Selected (least-privilege)?", default=False):
            config["sites_selected"] = True


def _prompt_s3_connector(config: dict) -> None:
    """Prompt for S3-specific fields."""
    config["bucket_name"] = _prompt("S3 bucket name")
    acl = _prompt_yn("  Enable document-level ACL?", default=False)
    config["acl"] = acl
    if acl:
        config["acl_s3_uri"] = _prompt("S3 URI to global ACL JSON file")


def _prompt_web_connector(config: dict) -> None:
    """Prompt for Web-specific fields."""
    urls: list[str] = []
    while True:
        url = _prompt("Seed URL")
        urls.append(url)
        if not _prompt_yn("  Add another seed URL?", default=False):
            break
    config["seed_urls"] = urls

    auth_mode = _prompt_choice("Auth mode", ["no_auth", "basic_auth"], default="no_auth")
    if auth_mode != "no_auth":
        config["auth_mode"] = auth_mode

    depth = _prompt_optional("Max crawl depth (blank for default)")
    if depth:
        config["crawl_depth"] = int(depth)


def _prompt_confluence_connector(config: dict) -> None:
    """Prompt for Confluence-specific fields."""
    config["host_url"] = _prompt("Confluence host URL (e.g. https://company.atlassian.net/wiki)")
    config["credential"] = _prompt_choice("Credential mode", ["oauth2", "basic_auth"], default="oauth2")


def _prompt_googledrive_connector(config: dict) -> None:
    """Prompt for Google Drive-specific fields."""
    config["credential"] = _prompt_choice("Credential mode", ["oauth2", "service_account"], default="oauth2")
