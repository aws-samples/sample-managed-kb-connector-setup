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


# --- Reading the certificates installed on an app -----------------------------


def _graph_returning(key_credentials):
    class _Graph:
        def get(self, path, **params):
            assert params == {"$select": "keyCredentials"}, params
            return {"keyCredentials": key_credentials}

    return _Graph()


def _as_hex(thumbprint_b64url):
    """Uppercase hex, which is what Graph returned from a live tenant."""
    import base64

    padded = thumbprint_b64url + "=" * (-len(thumbprint_b64url) % 4)
    return base64.urlsafe_b64decode(padded).hex().upper()


def _as_base64(thumbprint_b64url):
    """Standard base64, the other form the field is documented to take."""
    import base64

    padded = thumbprint_b64url + "=" * (-len(thumbprint_b64url) % 4)
    return base64.b64encode(base64.urlsafe_b64decode(padded)).decode("ascii")


def test_thumbprints_round_trip_a_hex_identifier():
    """Graph returned uppercase hex from a live tenant, and the value read back
    has to equal what state stores so the two compare directly."""
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    cert = generate_self_signed(common_name="t", pkcs12_password="pw")
    graph = _graph_returning([
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": _as_hex(cert.thumbprint_b64url)}
    ])
    assert list_certificate_thumbprints(graph, "obj") == [cert.thumbprint_b64url]


def test_a_hex_identifier_is_not_read_as_base64():
    """A 40-character hex digest is also valid base64, and decoding it that way
    yields 30 meaningless bytes instead of an error. Reading it as base64 would
    silently produce a thumbprint that matches nothing."""
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    cert = generate_self_signed(common_name="t", pkcs12_password="pw")
    hex_identifier = _as_hex(cert.thumbprint_b64url)
    assert len(hex_identifier) == 40 and len(hex_identifier) % 4 == 0

    graph = _graph_returning([
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": hex_identifier}
    ])
    got = list_certificate_thumbprints(graph, "obj")
    assert got == [cert.thumbprint_b64url], got


def test_thumbprints_round_trip_a_base64_identifier():
    """The field is documented as base64, so both encodings are accepted."""
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    cert = generate_self_signed(common_name="t", pkcs12_password="pw")
    graph = _graph_returning([
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": _as_base64(cert.thumbprint_b64url)}
    ])
    assert list_certificate_thumbprints(graph, "obj") == [cert.thumbprint_b64url]


def test_thumbprints_ignore_entries_that_are_not_certificates():
    """An app may also hold client secrets; the caller asked for certificates."""
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    cert = generate_self_signed(common_name="t", pkcs12_password="pw")
    graph = _graph_returning([
        {"type": "Symmetric", "customKeyIdentifier": _as_hex(cert.thumbprint_b64url)},
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": _as_hex(cert.thumbprint_b64url)},
    ])
    assert list_certificate_thumbprints(graph, "obj") == [cert.thumbprint_b64url]


def test_thumbprints_skip_unusable_entries_instead_of_raising():
    """A missing, malformed, or wrong-length identifier must not take the whole
    read down, and must not contribute a bogus thumbprint."""
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    cert = generate_self_signed(common_name="t", pkcs12_password="pw")
    graph = _graph_returning([
        {"type": "AsymmetricX509Cert"},
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": None},
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": "!!not base64!!"},
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": "   "},
        # Valid base64, but not a 20-byte SHA-1 digest.
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": "aGVsbG8="},
        "not-a-dict",
        {"type": "AsymmetricX509Cert", "customKeyIdentifier": _as_hex(cert.thumbprint_b64url)},
    ])
    assert list_certificate_thumbprints(graph, "obj") == [cert.thumbprint_b64url]


def test_thumbprints_of_an_app_with_no_credentials():
    from kb_connector.providers.microsoft.apps import list_certificate_thumbprints

    assert list_certificate_thumbprints(_graph_returning([]), "obj") == []
