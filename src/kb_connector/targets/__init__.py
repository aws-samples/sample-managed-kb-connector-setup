"""Control-plane adapters for different KB targets.

Use get_target() to construct the right Target for a given backend.
"""

from __future__ import annotations

from typing import Any

from kb_connector.targets.base import Target


def get_target(target_name: str, *, session: Any, region: str) -> Target:
    """Construct a Target for the named backend.

    Args:
        target_name: "bmkb" (default) or "quick".
        session: boto3 session.
        region: AWS region.

    Raises:
        ValueError: for an unknown target name.
    """
    name = (target_name or "bmkb").strip().lower()
    if name == "bmkb":
        from kb_connector.targets.bmkb import BmkbTarget
        return BmkbTarget(session=session, region=region)
    if name == "quick":
        from kb_connector.targets.quick import QuickTarget
        return QuickTarget(session=session, region=region)
    raise ValueError(f"Unknown target {target_name!r}; expected 'bmkb' or 'quick'.")
