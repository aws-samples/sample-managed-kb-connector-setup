"""Start + poll ingestion jobs, produce structured stats summaries.

Terminal states: COMPLETE, COMPLETED, FAILED, STOPPED.
The poll has a timeout so it never hangs forever; on timeout it returns
the last observed status.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from kb_connector.core.errors import AwsError
from kb_connector.targets.base import Target

_TERMINAL = {"COMPLETE", "COMPLETED", "FAILED", "STOPPED"}


@dataclass
class IngestionStats:
    """Structured stats from a completed (or in-progress) ingestion job."""

    status: str
    scanned: int = 0
    new_indexed: int = 0
    modified_indexed: int = 0
    failed: int = 0
    skipped: int = 0
    deleted: int = 0
    metadata_scanned: int = 0
    metadata_modified: int = 0
    failure_reasons: list[str] | None = None

    @property
    def indexed_total(self) -> int:
        return self.new_indexed + self.modified_indexed

    @property
    def has_acl_warning(self) -> bool:
        """True if stats suggest the ACL-enabled-but-no-permissions case.

        When ACL crawling is on but the connector app can't read item-level
        permissions, documents get scanned but skipped instead of indexed.
        That pattern shows up as a large absolute skip count *and* a high
        skip ratio. A handful of skipped docs in a healthy run (rare doc
        types, tombstoned items) is normal and shouldn't trip this flag.
        """
        if not self.scanned or self.skipped < 5:
            return False
        return self.skipped >= 0.25 * self.scanned


@dataclass
class MonitorResult:
    """Structured result from a monitor operation."""

    job_id: str
    stats: IngestionStats
    timed_out: bool = False


def start_and_poll(
    target: Target,
    *,
    kb_id: str,
    ds_id: str,
    poll_interval_seconds: int = 10,
    timeout_seconds: int = 1800,
    on_job_started: Callable[[str], None] | None = None,
) -> MonitorResult:
    """Start an ingestion job and poll to terminal state.

    If `on_job_started` is supplied, it's invoked with the job id the instant
    the job is created — before the first poll — so the caller can persist the
    id to state immediately. This means a dropped poll loop (transient network
    error) never loses the job id: the operator can resume with
    `monitor --no-start` or `monitor --job <id>`.
    """
    started = target.start_ingestion_job(kb_id, ds_id)
    job_id = _extract_job_id(started)
    if on_job_started is not None:
        on_job_started(job_id)
    return poll_job(
        target, kb_id=kb_id, ds_id=ds_id, job_id=job_id,
        poll_interval_seconds=poll_interval_seconds,
        timeout_seconds=timeout_seconds,
    )


def poll_job(
    target: Target,
    *,
    kb_id: str,
    ds_id: str,
    job_id: str,
    poll_interval_seconds: int = 10,
    timeout_seconds: int = 1800,
) -> MonitorResult:
    """Poll an existing ingestion job to terminal state."""
    deadline = time.time() + timeout_seconds
    last_job: dict = {}
    while time.time() < deadline:
        resp = target.get_ingestion_job(kb_id, ds_id, job_id)
        job = resp.get("ingestionJob", resp)
        status = (job.get("status") or "").upper()
        last_job = job
        if status in _TERMINAL:
            return MonitorResult(
                job_id=job_id,
                stats=_parse_stats(job),
                timed_out=False,
            )
        time.sleep(poll_interval_seconds)  # nosemgrep: arbitrary-sleep -- polling backoff
    return MonitorResult(
        job_id=job_id,
        stats=_parse_stats(last_job),
        timed_out=True,
    )


def _parse_stats(job: dict) -> IngestionStats:
    """Parse GetIngestionJob response into structured stats."""
    stats = job.get("statistics", {}) or {}
    status = (job.get("status") or "UNKNOWN").upper()
    return IngestionStats(
        status=status,
        scanned=stats.get("numberOfDocumentsScanned") or 0,
        new_indexed=stats.get("numberOfNewDocumentsIndexed") or 0,
        modified_indexed=stats.get("numberOfModifiedDocumentsIndexed") or 0,
        failed=stats.get("numberOfDocumentsFailed") or 0,
        skipped=stats.get("numberOfDocumentsSkipped") or 0,
        deleted=stats.get("numberOfDocumentsDeleted") or 0,
        metadata_scanned=stats.get("numberOfMetadataDocumentsScanned") or 0,
        metadata_modified=stats.get("numberOfMetadataDocumentsModified") or 0,
        failure_reasons=job.get("failureReasons") or None,
    )


def _extract_job_id(resp: Mapping[str, Any]) -> str:
    """Extract ingestionJobId from a StartIngestionJob response."""
    job = resp.get("ingestionJob", resp)
    jid = job.get("ingestionJobId")
    if not jid:
        raise AwsError(f"Could not find ingestionJobId in response: {resp}")
    return str(jid)
