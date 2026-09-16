"""MCP server — registers read-only tools over the service layer.

This is the agent-facing surface for kb-connector. Each tool wraps a
function in `kb_connector.service` and returns a JSON-serializable dict
to the caller.

Tools:
    kb_connector_list      List configured connectors and their tracked state.
    kb_connector_diagnose  Run diagnostic checks on a connector.
    kb_connector_monitor   Poll an ingestion job, or start one with start=true.
    kb_connector_validate  Validate credentials + retrieve path.
    kb_connector_handoff   Build a handoff document for split-admin workflows.

All of these are read-only against AWS except `kb_connector_monitor` with
`start=true`, which starts a real ingestion job. That is the one write on
this surface; it defaults to off and is called out in the server
instructions so the model treats it as privileged.

`setup` and `teardown` are deliberately not exposed here — they're
write-heavy / destructive and should land in a follow-up with explicit
confirmation semantics.

Run with:
    kb-connector-mcp                # stdio transport (default)
"""

from __future__ import annotations

import sys
from dataclasses import asdict
from typing import Any, Literal

from kb_connector import __version__, service
from kb_connector.core.errors import ConnectorError

# The handoff directions an agent may ask for. Doubles as the validator: a
# lookup miss is the rejection, so no unvalidated string reaches the library.
_HANDOFF_DIRECTIONS: dict[str, Literal["aws", "source"]] = {
    "aws": "aws",
    "source": "source",
}


def _build_server() -> Any:
    """Construct a FastMCP server with all tools registered.

    The `mcp` import is lazy so the package can be imported without the SDK
    installed (the `mcp` extra is optional).
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised at install time
        raise ImportError(
            "The 'mcp' package is required to run the MCP server. "
            "Install with: pip install 'kb-connector[mcp]'"
        ) from exc

    # The instructions string is what the model reasons about before choosing a
    # tool, so it states the one write this surface can perform. Describing the
    # surface as read-only would be wrong: kb_connector_monitor(start=true)
    # launches a real ingestion job, which re-crawls the source and incurs
    # embedding cost.
    mcp = FastMCP(
        "kb-connector",
        instructions=(
            f"kb-connector {__version__} — monitor, validate, and "
            "diagnose AWS Bedrock Knowledge Base connectors. All tools are "
            "read-only except kb_connector_monitor, which starts a real "
            "ingestion job when called with start=true — that re-crawls the "
            "source and incurs embedding cost, so ask the operator before "
            "setting it. setup and teardown are intentionally not exposed."
        ),
    )

    # --- list ----------------------------------------------------------------

    # nosemgrep: useless-inner-function -- FastMCP @mcp.tool() registers this function.
    @mcp.tool(
        name="kb_connector_list",
        description=(
            "List configured kb-connector connectors and their tracked state. "
            "Returns a summary of each connector with its type, region, KB/DS "
            "IDs (if set up), and ingestion job ID."
        ),
    )
    def kb_connector_list(
        config_path: str | None = None,
        state_path: str | None = None,
    ) -> dict:
        result = service.list_connectors(
            config_path=config_path,
            state_path=state_path,
        )
        return asdict(result)

    # --- diagnose ------------------------------------------------------------

    # nosemgrep: useless-inner-function -- FastMCP @mcp.tool() registers this function.
    @mcp.tool(
        name="kb_connector_diagnose",
        description=(
            "Run diagnostic checks on a connector: secret validation, "
            "certificate expiry, and a CloudTrail scan for AccessDenied "
            "events on the KB role/secret. Set include_logs=true to also "
            "analyze per-document ingestion events from CloudWatch Logs, "
            "which explains a scanned-vs-indexed gap (requires vended log "
            "delivery on the knowledge base). Returns a structured "
            "DiagnoseResult with status (healthy|degraded|failing) and "
            "attribution (source|aws|unknown). Document paths in log analysis "
            "are redacted."
        ),
    )
    def kb_connector_diagnose(
        connector_name: str | None = None,
        region: str | None = None,
        profile: str | None = None,
        kb_id: str | None = None,
        ds_id: str | None = None,
        lookback_minutes: int = 60,
        include_logs: bool = False,
        log_group_name: str | None = None,
        config_path: str | None = None,
        state_path: str | None = None,
    ) -> dict:
        try:
            result = service.diagnose(
                connector_name=connector_name,
                region=region,
                profile=profile,
                kb_id=kb_id,
                ds_id=ds_id,
                lookback_minutes=lookback_minutes,
                include_logs=include_logs,
                log_group_name=log_group_name,
                # Never hand unredacted document paths to an agent: they land
                # in model context and in whatever transcript store sits behind
                # it. The CLI's --no-redact escape hatch is deliberately not
                # exposed here.
                redact_logs=True,
                config_path=config_path,
                state_path=state_path,
            )
        except ConnectorError as exc:
            return {"error": str(exc), "error_type": type(exc).__name__}
        return asdict(result)

    # --- monitor -------------------------------------------------------------

    # nosemgrep: useless-inner-function -- FastMCP @mcp.tool() registers this function.
    @mcp.tool(
        name="kb_connector_monitor",
        description=(
            "Poll an existing ingestion job for a connector and return its "
            "stats (scanned, indexed, failed, skipped, etc.). Poll-only by "
            "default; pass start=true to begin a new ingestion job. The "
            "result includes an ACL-warning flag when the skipped/scanned "
            "ratio suggests a permissions issue."
        ),
    )
    def kb_connector_monitor(
        connector_name: str | None = None,
        region: str | None = None,
        profile: str | None = None,
        kb_id: str | None = None,
        ds_id: str | None = None,
        job_id: str | None = None,
        start: bool = False,
        poll_interval_seconds: int = 10,
        timeout_seconds: int = 1800,
        config_path: str | None = None,
        state_path: str | None = None,
    ) -> dict:
        try:
            result = service.monitor(
                connector_name=connector_name,
                region=region,
                profile=profile,
                kb_id=kb_id,
                ds_id=ds_id,
                job_id=job_id,
                start=start,
                poll_interval_seconds=poll_interval_seconds,
                timeout_seconds=timeout_seconds,
                config_path=config_path,
                state_path=state_path,
            )
        except ConnectorError as exc:
            return {"error": str(exc), "error_type": type(exc).__name__}
        out = asdict(result)
        # Flatten the IngestionStats to surface the derived fields too.
        stats = out.get("stats") or {}
        stats["indexed_total"] = result.stats.indexed_total
        stats["has_acl_warning"] = result.stats.has_acl_warning
        out["stats"] = stats
        return out

    # --- validate ------------------------------------------------------------

    # nosemgrep: useless-inner-function -- FastMCP @mcp.tool() registers this function.
    @mcp.tool(
        name="kb_connector_validate",
        description=(
            "Validate that a connector's credentials and retrieve path are "
            "healthy. Runs a token-mint informational check (Entra "
            "connectors) and a test retrieve against the knowledge base."
        ),
    )
    def kb_connector_validate(
        connector_name: str | None = None,
        region: str | None = None,
        profile: str | None = None,
        kb_id: str | None = None,
        query: str = "test",
        skip_retrieve: bool = False,
        config_path: str | None = None,
        state_path: str | None = None,
    ) -> dict:
        try:
            result = service.validate(
                connector_name=connector_name,
                region=region,
                profile=profile,
                kb_id=kb_id,
                query=query,
                skip_retrieve=skip_retrieve,
                config_path=config_path,
                state_path=state_path,
            )
        except ConnectorError as exc:
            return {"error": str(exc), "error_type": type(exc).__name__}
        return asdict(result)

    # --- handoff -------------------------------------------------------------

    # nosemgrep: useless-inner-function -- FastMCP @mcp.tool() registers this function.
    @mcp.tool(
        name="kb_connector_handoff",
        description=(
            "Build a handoff document for split-admin workflows. "
            "direction='aws' produces source-to-aws (source admin -> AWS "
            "admin); direction='source' produces aws-to-source. Returns "
            "the JSON document; the caller decides whether to write it to "
            "a file."
        ),
    )
    def kb_connector_handoff(
        connector_name: str,
        direction: str = "aws",
        config_path: str | None = None,
        state_path: str | None = None,
    ) -> dict:
        # An agent supplies this as a free-form string, so the mapping is both
        # the validation and the narrowing: anything absent from it is rejected
        # before reaching the library, with no unchecked assertion in between.
        checked = _HANDOFF_DIRECTIONS.get(direction)
        if checked is None:
            return {
                "error": f"Unknown direction {direction!r}; expected 'aws' or 'source'.",
                "error_type": "ConfigError",
            }
        try:
            result = service.handoff(
                connector_name=connector_name,
                direction=checked,
                config_path=config_path,
                state_path=state_path,
            )
        except ConnectorError as exc:
            return {"error": str(exc), "error_type": type(exc).__name__}
        return asdict(result)

    return mcp


def main() -> int:
    """Entry point — starts the MCP server over stdio."""
    try:
        server = _build_server()
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
