"""CloudWatch log fetch + per-document reconciliation for ingestion diagnostics.

Fetches APPLICATION_LOGS from the KB's vended-log delivery (CloudWatch Logs),
parses per-document events, and reconciles them against ingestion job stats
to explain the scanned-vs-indexed gap.

Log structure (per-document events from the managed connector):
  Each log event is a JSON object with fields like:
    - documentId / documentLocation: identifies the file
    - status: "INDEXED", "FAILED", "SKIPPED", "FILTERED"
    - reason: human explanation for non-INDEXED status
    - metadata: additional context (file size, format, etc.)

The reconciliation groups by status + reason and produces a structured summary.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DocumentEvent:
    """A single per-document event from the ingestion logs.

    `details` holds the raw parsed log event and is excluded from repr: the
    service decides what goes in a log line, so it can carry document titles,
    author names, and URL query strings. Analysis only needs status and reason,
    so the raw event stays available for debugging but never renders by
    accident into a traceback or a --json dump.
    """

    document_id: str
    document_location: str
    status: str  # INDEXED, FAILED, SKIPPED, FILTERED
    reason: str | None = None
    details: dict = field(default_factory=dict, repr=False)


@dataclass
class ReasonGroup:
    """A group of documents with the same status + reason."""

    status: str
    reason: str
    count: int
    sample_documents: list[str] = field(default_factory=list)


@dataclass
class LogAnalysisResult:
    """Structured result from log analysis."""

    total_events: int
    groups: list[ReasonGroup]
    indexed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    filtered_count: int = 0
    unknown_count: int = 0
    actionable_issues: list[str] = field(default_factory=list)


def fetch_ingestion_logs(
    *,
    session: Any,
    log_group_name: str,
    start_time_ms: int,
    end_time_ms: int,
    limit: int = 10000,
) -> list[dict]:
    """Fetch log events from CloudWatch Logs for the ingestion window.

    Returns raw log events as dicts. Handles pagination.
    """
    logs_client = session.client("logs")
    events: list[dict] = []
    kwargs: dict = {
        "logGroupName": log_group_name,
        "startTime": start_time_ms,
        "endTime": end_time_ms,
        "limit": min(limit, 10000),
    }

    while True:
        try:
            resp = logs_client.filter_log_events(**kwargs)
        except Exception as exc:
            from kb_connector.core.errors import AwsError
            raise AwsError(f"Failed to fetch logs from {log_group_name}: {exc}") from exc

        for event in resp.get("events", []):
            events.append(event)
            if len(events) >= limit:
                return events

        next_token = resp.get("nextToken")
        if not next_token:
            break
        kwargs["nextToken"] = next_token

    return events


def parse_document_events(raw_events: list[dict]) -> list[DocumentEvent]:
    """Parse raw CloudWatch log events into structured DocumentEvents."""
    parsed: list[DocumentEvent] = []
    for event in raw_events:
        message = event.get("message", "")
        try:
            data = json.loads(message)
        except (json.JSONDecodeError, TypeError):
            continue

        # Various log event shapes depending on service version
        doc_id = (
            data.get("documentId")
            or data.get("document_id")
            or data.get("resourceUri")
            or ""
        )
        doc_location = (
            data.get("documentLocation")
            or data.get("document_location")
            or data.get("s3Uri")
            or doc_id
        )
        status = (
            data.get("status")
            or data.get("documentStatus")
            or ""
        ).upper()
        reason = data.get("reason") or data.get("failureReason") or data.get("statusReason")

        if doc_id or status:
            parsed.append(DocumentEvent(
                document_id=doc_id,
                document_location=doc_location,
                status=status,
                reason=reason,
                details=data,
            ))

    return parsed


def redact_document_location(location: str, *, keep_filename: bool = False) -> str:
    """Reduce a document location to the least identifying useful form.

    Sample document locations are the one part of log analysis that carries
    customer content rather than service metadata: a SharePoint or Drive URL
    names the site, the folder path, and the filename, and those samples get
    printed to a terminal and pasted into tickets when someone asks for help
    with a failing ingestion.

    What actually helps diagnosis is *which* location pattern is failing, not
    the specific file. So the host and a truncated path are kept, the filename
    is dropped by default, and query strings — which can carry tokens on some
    connectors — are always removed.

    Two details that look like over-caution but are not:

    * The prefix is rebuilt from `hostname` (plus port), never from `netloc`.
      `netloc` includes userinfo, so a location of the form
      `https://user:password@host/...` would otherwise have its embedded
      credentials copied verbatim into output destined for a support ticket.
    * Only the *first* path segment is kept. A second would carry the
      SharePoint site name, which is genuinely useful for diagnosis — but the
      same slot on a OneDrive personal site holds the user's email-derived
      identity (`/personal/john_doe_contoso_com/`), so it cannot be emitted
      without disclosing who owns the document. Status, reason and count are
      what actually drive diagnosis; the path is only there to show shape.
    """
    from urllib.parse import urlparse

    raw = (location or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        # Not a URL (an S3 key, a bare document id). Keep only the leading
        # path segment so the shape is visible without the full identifier.
        head, _, tail = raw.partition("/")
        if not tail:
            return _mask_tail(raw)
        return f"{head}/…/{_mask_tail(tail.rsplit('/', 1)[-1])}"

    # hostname, not netloc: netloc carries userinfo. hostname is also
    # already lowercased, and the port is re-appended only if one was given.
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    prefix = f"{parsed.scheme}://{host}"

    segments = [s for s in parsed.path.split("/") if s]
    if not segments:
        return f"{prefix}/"

    filename = segments[-1]
    parents = segments[:-1]
    shown_parents = "/".join(parents[:1])
    elided = "/…" if len(parents) > 1 else ""
    tail = filename if keep_filename else _mask_tail(filename)
    if shown_parents:
        return f"{prefix}/{shown_parents}{elided}/{tail}"
    return f"{prefix}/{tail}"


# Document formats the Bedrock managed connectors ingest. Used to recognize a
# filename inside otherwise free-form service text. Deliberately an explicit
# set rather than a generic `\.\w{1,8}` pattern: a generic one would also match
# version strings ("1.2"), hostnames ("contoso.sharepoint.com") and ARNs,
# producing mangled, harder-to-read diagnostics for no privacy gain.
_DOC_EXTENSIONS = (
    "pdf|docx?|xlsx?|pptx?|txt|md|markdown|html?|csv|tsv|json|xml|rtf|odt|ods|"
    "odp|epub|msg|eml|one|png|jpe?g|gif|bmp|tiff?|webp"
)

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>|]+", re.IGNORECASE)
_FILENAME_IN_TEXT_RE = re.compile(
    r"[^\s\"'<>|/\\]+\.(?:" + _DOC_EXTENSIONS + r")\b", re.IGNORECASE
)


def redact_reason(reason: str | None) -> str | None:
    """Strip document identifiers out of a service-supplied reason string.

    `reason` comes from the managed connector's log event, so its content is
    the service's choice rather than ours — and in practice it frequently
    embeds the very thing `redact_document_location` exists to remove: a full
    document URL ("AccessDenied reading https://.../salaries-2026.xlsx"), or a
    bare filename. Redacting `sample_documents` alone is therefore not enough:
    the filename would still reach the output through the group's `reason`
    field and through the `actionable_issues` strings built from it.

    Two passes, in order:

    1. Any http(s) URL is run through `redact_document_location`, so it gets
       the same host-plus-shape treatment as a sample.
    2. Any remaining token ending in a known document extension is masked.

    What this deliberately does not attempt is scrubbing an extensionless
    identifier (a bare document id, a title with no extension). Recognizing
    those in free text is not reliably possible, so they remain a documented
    residual rather than a false promise — see T-15.
    """
    if not reason:
        return reason
    scrubbed = _URL_IN_TEXT_RE.sub(
        lambda m: redact_document_location(m.group(0)), reason
    )
    return _FILENAME_IN_TEXT_RE.sub(lambda m: _mask_tail(m.group(0)), scrubbed)


def _mask_tail(name: str) -> str:
    """Keep a filename's extension and length signal, drop its identity."""
    if not name:
        return ""
    stem, dot, ext = name.rpartition(".")
    if dot and len(ext) <= 8:
        return f"<redacted>.{ext}"
    return "<redacted>"


def analyze_logs(
    events: list[DocumentEvent], *, redact: bool = True
) -> LogAnalysisResult:
    """Reconcile document events into a structured analysis.

    Groups by (status, reason), counts each category, and identifies
    actionable issues.

    `redact` (default on) trims the sample document locations *and* the
    service-supplied reason strings — see redact_document_location and
    redact_reason. Both matter: the reason routinely embeds the same document
    URL as the sample, and it also flows into `actionable_issues`, so redacting
    only the samples left the filename in the output by another route. Pass
    redact=False only when the full paths are needed and the output is not
    going to be shared.
    """
    # Group by (status, reason)
    groups_map: dict[tuple[str, str], list[str]] = {}
    indexed = 0
    failed = 0
    skipped = 0
    filtered = 0
    unknown = 0

    for event in events:
        key = (event.status, event.reason or "")
        if key not in groups_map:
            groups_map[key] = []
        if len(groups_map[key]) < 5:  # keep up to 5 samples
            location = event.document_location
            groups_map[key].append(
                redact_document_location(location) if redact else location
            )

        if event.status in ("INDEXED", "PROCESSED"):
            indexed += 1
        elif event.status in ("FAILED", "ERROR"):
            failed += 1
        elif event.status == "SKIPPED":
            skipped += 1
        elif event.status in ("FILTERED", "EXCLUDED"):
            filtered += 1
        else:
            unknown += 1

    # Group reason → samples and count occurrences. Sort groups by frequency
    # (most common first); cap each group's sample list at 5.
    counts_map: dict[tuple[str, str], int] = {}
    for event in events:
        key = (event.status, event.reason or "")
        counts_map[key] = counts_map.get(key, 0) + 1

    # Grouping keys stay raw so counts remain exact — two reasons that redact
    # to the same string are still counted separately. Redaction happens at
    # emission, which also means `actionable_issues` below inherits it, since
    # those strings are built from the group's already-redacted reason.
    groups: list[ReasonGroup] = []
    for (status, reason), count in sorted(counts_map.items(), key=lambda x: -x[1]):
        groups.append(ReasonGroup(
            status=status,
            reason=(redact_reason(reason) or "") if redact else reason,
            count=count,
            sample_documents=groups_map.get((status, reason), [])[:5],
        ))

    # Identify actionable issues
    actionable: list[str] = []
    for g in groups:
        if g.status in ("FAILED", "ERROR") and g.count > 0:
            if "access" in (g.reason or "").lower() or "permission" in (g.reason or "").lower():
                actionable.append(
                    f"{g.count} documents failed with permission issue: {g.reason}"
                )
            elif "acl" in (g.reason or "").lower():
                actionable.append(
                    f"{g.count} documents failed with ACL issue: {g.reason}. "
                    "Check that the connector app has ACL permissions."
                )
            else:
                actionable.append(f"{g.count} documents failed: {g.reason or 'unknown reason'}")
        elif g.status == "SKIPPED" and g.count > 10:
            actionable.append(
                f"{g.count} documents skipped: {g.reason or 'no reason given'}. "
                "Common cause: ACL enabled but app lacks permission to read item ACLs."
            )

    return LogAnalysisResult(
        total_events=len(events),
        groups=groups,
        indexed_count=indexed,
        failed_count=failed,
        skipped_count=skipped,
        filtered_count=filtered,
        unknown_count=unknown,
        actionable_issues=actionable,
    )
