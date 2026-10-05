"""Write CONFIG-REFERENCE.md from the connector specs.

    python scripts/gen_config_reference.py          # rewrite the file
    python scripts/gen_config_reference.py --check  # exit 1 if it is stale
"""

from __future__ import annotations

import sys
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "CONFIG-REFERENCE.md"


def render() -> str:
    from kb_connector.connectors import all_specs
    from kb_connector.connectors.base import COMMON_FIELDS, MICROSOFT_FIELDS, VALIDATION_KEYS

    generated = (
        "Generated from the connector specs by `scripts/gen_config_reference.py`. "
        "Do not edit by hand."
    )
    intro = (
        "Keys go under `[connectors.<name>]`. A key the tool does not read, or a value "
        "of the wrong type, prints a warning naming the closest valid key. "
        "For request fields not listed here, see "
        "[Request overrides](README.md#request-overrides)."
    )
    lines = ["# Configuration reference", "", generated, "", intro, ""]

    def table(fields) -> None:
        lines.append("| Key | Type | Default | Description |")
        lines.append("|---|---|---|---|")
        for f in fields:
            kinds = f.kind if isinstance(f.kind, tuple) else (f.kind,)
            kind = " or ".join(k.__name__ for k in kinds)
            default = "" if f.default is None else f"`{_toml(f.default)}`"
            desc = f.help
            if f.required:
                desc = "**Required.** " + desc
            if f.choices:
                desc += " One of: " + ", ".join(f"`{c}`" for c in f.choices) + "."
            lines.append(f"| `{f.key}` | {kind} | {default} | {desc} |")
        lines.append("")

    lines += ["## Every connector", ""]
    table(COMMON_FIELDS)
    lines += [
        "`[connectors.<name>.validation]` takes "
        + ", ".join(f"`{k}`" for k in VALIDATION_KEYS) + ".",
        "",
        "## SharePoint and OneDrive", "",
    ]
    table(MICROSOFT_FIELDS)
    common = {f.key for f in COMMON_FIELDS + MICROSOFT_FIELDS}
    for spec in all_specs().values():
        lines += [f"## `type = \"{spec.type}\"`", ""]
        table([f for f in spec.fields if f.key not in common])
    return "\n".join(lines).rstrip("\n") + "\n"


def _toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUTPUT.exists() or OUTPUT.read_text() != text:
            print(f"{OUTPUT.name} is stale. Run: python scripts/gen_config_reference.py")
            return 1
        return 0
    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
