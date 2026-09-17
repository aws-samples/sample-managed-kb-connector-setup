"""Control-plane adapters for different KB targets.

Use get_target() to construct the right Target for a given backend.
"""

from __future__ import annotations

from typing import Any

from kb_connector.targets.base import Target

DEFAULT_TARGET = "bmkb"

# Every target name get_target accepts. Exported so config can reject an unknown
# `target` value at resolution time, before any AWS call, rather than letting it
# surface much later as a ValueError from deep inside a setup flow. Kept here
# because this module owns the mapping; importing it is cheap, since the concrete
# targets (and boto3 with them) are only imported inside get_target.
TARGET_NAMES = frozenset({"bmkb", "quick"})


def normalize_target(target_name: str | None) -> str:
    """Return a target name lowercased and defaulted, without validating it."""
    return (target_name or DEFAULT_TARGET).strip().lower()


def get_target(
    target_name: str | None, *, session: Any, region: str | None
) -> Target:
    """Construct a Target for the named backend.

    Args:
        target_name: "bmkb" (default) or "quick". None or empty selects the
            default, so callers can pass an unset config or state value through
            without substituting it themselves.
        session: boto3 session.
        region: AWS region, or None to let the SDK resolve it.

    Raises:
        ValueError: for an unknown target name.
    """
    name = normalize_target(target_name)
    if name == "bmkb":
        from kb_connector.targets.bmkb import BmkbTarget
        return BmkbTarget(session=session, region=region)
    if name == "quick":
        from kb_connector.targets.quick import QuickTarget
        return QuickTarget(session=session, region=region)
    expected = ", ".join(sorted(TARGET_NAMES))
    raise ValueError(f"Unknown target {target_name!r}; expected one of: {expected}.")
