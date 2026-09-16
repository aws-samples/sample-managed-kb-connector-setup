"""Unit tests for providers/microsoft modules (no network calls)."""

from kb_connector.providers.microsoft.permissions import (
    build_plan, SHAREPOINT_APP_ID,
)
from kb_connector.providers.microsoft.certs import generate_self_signed, certificate_der_b64


# --- Permissions plans -------------------------------------------------------


def test_sharepoint_content_only():
    """SharePoint without ACL needs Sites.Read.All on both resources."""
    plan = build_plan(source="sharepoint", acl=False, sites_selected=False)
    values = [r.value for r in plan.requirements]
    assert "Sites.Read.All" in values
    assert "Sites.FullControl.All" not in values
    assert plan.site_role is None


def test_sharepoint_with_acl():
    """SharePoint with ACL adds User.Read.All, GroupMember.Read.All, FullControl."""
    plan = build_plan(source="sharepoint", acl=True, sites_selected=False)
    values = [r.value for r in plan.requirements]
    assert "User.Read.All" in values
    assert "GroupMember.Read.All" in values
    assert "Sites.FullControl.All" in values


def test_sharepoint_sites_selected_acl():
    """Sites.Selected + ACL yields fullcontrol site_role."""
    plan = build_plan(source="sharepoint", acl=True, sites_selected=True)
    values = [r.value for r in plan.requirements]
    assert "Sites.Selected" in values
    assert plan.site_role == "fullcontrol"


def test_sharepoint_sites_selected_no_acl():
    """Sites.Selected without ACL yields read site_role."""
    plan = build_plan(source="sharepoint", acl=False, sites_selected=True)
    assert plan.site_role == "read"


def test_onedrive_content_only():
    """OneDrive without ACL needs Files.Read.All + Sites.Read.All."""
    plan = build_plan(source="onedrive", acl=False)
    values = [r.value for r in plan.requirements]
    assert "Files.Read.All" in values
    assert "Sites.Read.All" in values
    assert "Sites.FullControl.All" not in values


def test_onedrive_with_acl():
    """OneDrive ACL adds identity resolution perms + FullControl."""
    plan = build_plan(source="onedrive", acl=True)
    values = [r.value for r in plan.requirements]
    assert "User.Read.All" in values
    assert "GroupMember.Read.All" in values
    assert "Sites.FullControl.All" in values


def test_sharepoint_ropc_adds_delegated():
    """SharePoint ROPC adds a delegated AllSites.Read scope."""
    plan = build_plan(source="sharepoint", acl=False, credential="ropc")
    assert len(plan.delegated) == 1
    assert plan.delegated[0].value == "AllSites.Read"
    assert plan.delegated[0].resource_app_id == SHAREPOINT_APP_ID


def test_unknown_source_raises():
    """Unknown source raises ValueError."""
    import pytest
    with pytest.raises(ValueError, match="Unknown source"):
        build_plan(source="dropbox", acl=False)


# --- Certificate generation --------------------------------------------------


def test_generate_self_signed(fixture_secret):
    """Certificate generation produces expected artifacts."""
    cert = generate_self_signed(
        common_name="test-app",
        pkcs12_password=fixture_secret,
        valid_days=30,
    )
    assert cert.pkcs12_password == fixture_secret
    assert len(cert.pkcs12_bytes) > 100
    assert len(cert.thumbprint_b64url) > 10
    assert len(cert.thumbprint_hex) == 40  # SHA-1 hex
    assert cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(cert.private_key_b64_pkcs8) > 100
    assert cert.not_after  # ISO8601 string


def test_certificate_der_b64():
    """certificate_der_b64 produces valid base64."""
    import base64
    cert = generate_self_signed(common_name="test", pkcs12_password="pw")
    b64 = certificate_der_b64(cert.certificate_der)
    decoded = base64.b64decode(b64)
    assert decoded == cert.certificate_der
