"""Smoke tests for the MCP server.

These tests verify the server constructs cleanly and the expected tools
register with sensible schemas. They don't run the stdio loop — that's
the SDK's responsibility, not ours.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp.server.fastmcp")

from kb_connector.mcp_server.server import _build_server  # noqa: E402


EXPECTED_TOOLS = {
    "kb_connector_list",
    "kb_connector_diagnose",
    "kb_connector_monitor",
    "kb_connector_validate",
    "kb_connector_handoff",
}


def test_server_builds_and_registers_expected_tools():
    server = _build_server()
    assert server.name == "kb-connector"
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS


def test_each_tool_has_a_description():
    server = _build_server()
    tools = asyncio.run(server.list_tools())
    for t in tools:
        assert t.description, f"tool {t.name} has no description"


def test_list_tool_schema_has_optional_paths():
    server = _build_server()
    tools = asyncio.run(server.list_tools())
    list_tool = next(t for t in tools if t.name == "kb_connector_list")
    schema = list_tool.inputSchema
    properties = schema.get("properties", {})
    assert "config_path" in properties
    assert "state_path" in properties


def test_destructive_tools_are_not_exposed():
    """The MCP server is read-only — setup/teardown must not be registered."""
    server = _build_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    forbidden = {"kb_connector_setup", "kb_connector_teardown", "kb_connector_init"}
    assert forbidden.isdisjoint(names), (
        f"unexpected destructive tool registered: {names & forbidden}"
    )


def test_handoff_tool_returns_document(tmp_path: Path):
    """End-to-end: invoke the handoff tool through FastMCP and parse its output."""
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\nregion = \"us-west-2\"\n\n"
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
        "acl = true\n"
    )
    state = tmp_path / "kb-connector.state.json"
    state.write_text(json.dumps({
        "connectors": {
            "eng": {
                "connector_type": "sharepoint",
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "client_app_id": "app-12345",
            }
        }
    }))

    server = _build_server()
    result = asyncio.run(server.call_tool(
        "kb_connector_handoff",
        {
            "connector_name": "eng",
            "direction": "aws",
            "config_path": str(config),
            "state_path": str(state),
        },
    ))
    # call_tool returns either a list of content objects, or a (content, structured)
    # tuple depending on SDK version. Pull the JSON payload out either way.
    content = result[0] if isinstance(result, tuple) else result
    structured = None
    if isinstance(result, tuple) and len(result) > 1 and isinstance(result[1], dict):
        structured = result[1]
    if structured is None:
        for item in content:
            text = getattr(item, "text", None)
            if text:
                structured = json.loads(text)
                break
    assert structured is not None, f"could not extract result from {result!r}"
    assert structured["direction"] == "source-to-aws"
    assert structured["connector"] == "eng"
    assert structured["document"]["source"]["client_id"] == "app-12345"


def test_handoff_direction_map_admits_only_known_values():
    """The mapping is what narrows agent input to the two accepted directions.

    Kept as a direct check because an end-to-end call cannot distinguish this
    from the library's own validation — both surface the same ConfigError.
    """
    from kb_connector.mcp_server.server import _HANDOFF_DIRECTIONS

    assert _HANDOFF_DIRECTIONS == {"aws": "aws", "source": "source"}
    for rejected in ("upload", "AWS", "Source", "", "both"):
        assert _HANDOFF_DIRECTIONS.get(rejected) is None


def test_handoff_tool_reports_a_bad_direction_without_raising(tmp_path: Path):
    """A rejected direction comes back as a structured error, not an exception.

    Agents consume the return value, so an exception escaping the tool is a
    worse failure than a bad argument.
    """
    config = tmp_path / "kb-connector.toml"
    config.write_text(
        "[defaults]\nregion = \"us-west-2\"\n\n"
        "[connectors.eng]\n"
        'type = "sharepoint"\n'
        'tenant_id = "11111111-1111-1111-1111-111111111111"\n'
    )
    state = tmp_path / "kb-connector.state.json"
    state.write_text(json.dumps({"connectors": {"eng": {"connector_type": "sharepoint"}}}))

    server = _build_server()
    result = asyncio.run(server.call_tool(
        "kb_connector_handoff",
        {
            "connector_name": "eng",
            "direction": "upload",
            "config_path": str(config),
            "state_path": str(state),
        },
    ))
    content = result[0] if isinstance(result, tuple) else result
    structured = None
    if isinstance(result, tuple) and len(result) > 1 and isinstance(result[1], dict):
        structured = result[1]
    if structured is None:
        for item in content:
            text = getattr(item, "text", None)
            if text:
                structured = json.loads(text)
                break
    assert structured is not None, f"could not extract result from {result!r}"
    assert structured["error_type"] == "ConfigError"
    assert "upload" in structured["error"]
