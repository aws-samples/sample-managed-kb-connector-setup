"""Declarative application-permission sets for managed KB connectors.

Permission selection depends on:
  * source:          "sharepoint" | "onedrive"
  * acl:             whether document-level ACL crawling is enabled
  * sites_selected:  for SharePoint, least-privilege scope
  * credential:      "cert" | "client_secret" | "ropc"

Two stable resource applications are involved (well-known Microsoft constants):
  * Microsoft Graph        00000003-0000-0000-c000-000000000000
  * SharePoint Online      00000003-0000-0ff1-ce00-000000000000

Permission values (e.g. "Sites.Read.All") are resolved to role IDs at runtime
from the resource service principal's appRoles collection — no hardcoded GUIDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Well-known Microsoft resource application ids.
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
SHAREPOINT_APP_ID = "00000003-0000-0ff1-ce00-000000000000"


@dataclass(frozen=True)
class PermissionRequirement:
    """A single application permission to grant + admin-consent."""

    resource_app_id: str
    value: str  # app role value, e.g. "Sites.Read.All"
    why: str    # human explanation for summaries


@dataclass(frozen=True)
class PermissionPlan:
    """Full set of permissions for a given source + options.

    site_role: only meaningful for SharePoint + sites_selected — the role
    granted per-site ("read" or "fullcontrol").

    delegated: delegated permission requirements (OAuth2 scopes) for the
    ROPC path which is a delegated flow.
    """

    requirements: tuple[PermissionRequirement, ...]
    site_role: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)
    delegated: tuple[PermissionRequirement, ...] = field(default_factory=tuple)


# --- SharePoint --------------------------------------------------------------


def _sharepoint_plan(*, acl: bool, sites_selected: bool) -> PermissionPlan:
    reqs: list[PermissionRequirement] = []
    notes: list[str] = []

    if sites_selected:
        reqs.append(PermissionRequirement(
            GRAPH_APP_ID, "Sites.Selected",
            "Access only explicitly granted SharePoint sites (Graph).",
        ))
        reqs.append(PermissionRequirement(
            SHAREPOINT_APP_ID, "Sites.Selected",
            "Access only explicitly granted SharePoint sites (SharePoint REST).",
        ))
        if acl:
            reqs.append(PermissionRequirement(
                GRAPH_APP_ID, "User.Read.All",
                "Resolve users for document-level ACLs.",
            ))
            reqs.append(PermissionRequirement(
                GRAPH_APP_ID, "GroupMember.Read.All",
                "Resolve group membership for document-level ACLs.",
            ))
        site_role = "fullcontrol" if acl else "read"
        notes.append(
            f"Sites.Selected requires per-site grants (role: {site_role}). "
            "New sites added later need their own grant."
        )
        return PermissionPlan(tuple(reqs), site_role=site_role, notes=tuple(notes))

    # All-sites scope.
    reqs.append(PermissionRequirement(
        GRAPH_APP_ID, "Sites.Read.All",
        "Read all SharePoint sites (Graph).",
    ))
    if acl:
        reqs.append(PermissionRequirement(
            GRAPH_APP_ID, "User.Read.All",
            "Resolve users for document-level ACLs.",
        ))
        reqs.append(PermissionRequirement(
            GRAPH_APP_ID, "GroupMember.Read.All",
            "Resolve group membership for document-level ACLs.",
        ))
        reqs.append(PermissionRequirement(
            SHAREPOINT_APP_ID, "Sites.FullControl.All",
            "Read item-level permissions for ACL crawling (SharePoint REST).",
        ))
    else:
        reqs.append(PermissionRequirement(
            SHAREPOINT_APP_ID, "Sites.Read.All",
            "Read all SharePoint site content (SharePoint REST).",
        ))
    return PermissionPlan(tuple(reqs), notes=tuple(notes))


# --- OneDrive ----------------------------------------------------------------


def _onedrive_quick_plan() -> PermissionPlan:
    """OneDrive permissions for Amazon Quick's admin-managed setup.

    Distinct from the Bedrock plan in three ways, all of them load-bearing:

    * `Group.Read.All` is required and the Bedrock connector never asks for it.
      Without it, group-based access control resolves to nothing and documents
      shared with a group are silently missed.
    * There is no SharePoint REST permission at all. The Bedrock plan adds
      `Sites.FullControl.All` for its real-time permission check, which is
      tenant-wide full control, and granting it here would be an over-grant
      Quick has no use for.
    * ACL is unconditional. Admin-managed OneDrive crawls every user's content
      and always enforces document-level access control, so there is no
      content-only variant to select.
    """
    reqs = (
        PermissionRequirement(
            GRAPH_APP_ID, "Files.Read.All",
            "Read files in all users' OneDrive content.",
        ),
        PermissionRequirement(
            GRAPH_APP_ID, "Sites.Read.All",
            "Enumerate per-user OneDrive drives (hosted on SharePoint).",
        ),
        PermissionRequirement(
            GRAPH_APP_ID, "User.Read.All",
            "Resolve user profiles for document-level ACLs.",
        ),
        PermissionRequirement(
            GRAPH_APP_ID, "Group.Read.All",
            "Resolve group objects for group-based access control.",
        ),
        PermissionRequirement(
            GRAPH_APP_ID, "GroupMember.Read.All",
            "Resolve group membership for document-level ACLs.",
        ),
    )
    return PermissionPlan(reqs, notes=(
        "Admin-managed OneDrive always enforces document-level access control, "
        "and crawls every user's OneDrive in the tenant.",
    ))


def _onedrive_plan(*, acl: bool) -> PermissionPlan:
    reqs: list[PermissionRequirement] = [
        PermissionRequirement(
            GRAPH_APP_ID, "Files.Read.All",
            "Read files in all users' OneDrive content.",
        ),
        PermissionRequirement(
            GRAPH_APP_ID, "Sites.Read.All",
            "Enumerate per-user OneDrive drives (hosted on SharePoint).",
        ),
    ]
    if acl:
        reqs.extend([
            PermissionRequirement(
                GRAPH_APP_ID, "User.Read.All",
                "Resolve user profiles for document-level ACLs.",
            ),
            PermissionRequirement(
                GRAPH_APP_ID, "GroupMember.Read.All",
                "Resolve group membership for document-level ACLs.",
            ),
            PermissionRequirement(
                SHAREPOINT_APP_ID, "Sites.FullControl.All",
                "Real-time effective-permission check for ACL-aware retrieval.",
            ),
        ])
    return PermissionPlan(tuple(reqs))


# --- Public API --------------------------------------------------------------


def build_plan(
    *,
    source: str,
    acl: bool,
    sites_selected: bool = False,
    credential: str = "cert",
    target: str = "bmkb",
) -> PermissionPlan:
    """Return the permission plan for the requested source + options.

    `target` selects the consuming service. It only changes the OneDrive plan:
    Amazon Quick's documented SharePoint permission sets are identical to the
    Bedrock connector's in all four combinations (with and without ACL, all-sites
    and Sites.Selected, including the per-site `fullcontrol` role under ACL), so
    that plan is shared rather than duplicated. OneDrive genuinely differs. See
    `_onedrive_quick_plan`.

    Raises ValueError for an unknown source.
    """
    normalized = source.strip().lower()
    if normalized == "sharepoint":
        plan = _sharepoint_plan(acl=acl, sites_selected=sites_selected)
    elif normalized == "onedrive":
        plan = (
            _onedrive_quick_plan()
            if target.strip().lower() == "quick"
            else _onedrive_plan(acl=acl)
        )
    else:
        raise ValueError(
            f"Unknown source {source!r}; expected 'sharepoint' or 'onedrive'."
        )

    delegated = _delegated_requirements(source=normalized, credential=credential)
    if delegated:
        plan = PermissionPlan(
            requirements=plan.requirements,
            site_role=plan.site_role,
            notes=plan.notes + (
                "ROPC is a delegated flow: the app also needs a delegated "
                "SharePoint scope with admin consent.",
            ),
            delegated=delegated,
        )
    return plan


def _delegated_requirements(
    *, source: str, credential: str
) -> tuple[PermissionRequirement, ...]:
    """Delegated permissions for ROPC credential type."""
    if source == "sharepoint" and credential.strip().lower() == "ropc":
        return (
            PermissionRequirement(
                SHAREPOINT_APP_ID, "AllSites.Read",
                "Delegated read for the ROPC SharePoint REST token.",
            ),
        )
    return ()
