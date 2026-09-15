"""Certificate + key-pair generation for Entra app-only (certificate) auth.

The Bedrock managed connector holds the private key itself: it reads a PKCS#12 (.p12)
bundle from S3 and signs a JWT client assertion to obtain a token.

This module generates a self-signed X.509 certificate over a fresh RSA key
pair and packages it as a PKCS#12 bundle. We produce *only* P12 because:
  * the connector's crawl path accepts P12 or PEM, but
  * the control-plane ACL token path accepts P12 only.
P12 works for both; PEM would silently break ACL crawling.

Artifacts produced:
  * PKCS#12 bundle (cert + private key, password-protected) -> S3
  * headerless base64 PKCS#8 private key -> secret's `privateKey` field
  * certificate DER -> Entra app's keyCredentials
  * SHA-1 thumbprint in base64url (connector config) and hex (Entra portal)
"""

from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


@dataclass
class GeneratedCertificate:
    """Artifacts from certificate generation."""

    certificate_pem: str
    certificate_der: bytes
    # repr=False on every field carrying key material. This object is passed
    # through several call frames during setup, so it appears in any traceback
    # raised along the way — and dataclasses' generated __repr__ would print
    # the unencrypted private key and the PKCS#12 password into the terminal,
    # CI logs, and crash reports.
    private_key_b64_pkcs8: str = field(repr=False)  # base64 PKCS#8, no PEM headers
    pkcs12_bytes: bytes = field(repr=False)
    pkcs12_password: str = field(repr=False)
    thumbprint_b64url: str  # base64url(SHA-1) no padding
    thumbprint_hex: str     # hex SHA-1
    not_after: str          # ISO8601 expiry


def generate_self_signed(
    *,
    common_name: str,
    organization: str = "kb-connector",
    valid_days: int = 365,
    key_size: int = 2048,
    pkcs12_password: str,
    pkcs12_friendly_name: str = "kb-connector",
) -> GeneratedCertificate:
    """Generate an RSA key pair and self-signed certificate.

    Returns a GeneratedCertificate with all artifacts needed for Entra setup.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])

    now = _dt.datetime.now(_dt.timezone.utc)
    not_before = now - _dt.timedelta(minutes=5)  # tolerate clock skew
    not_after = now + _dt.timedelta(days=valid_days)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)

    # Headerless base64 of DER PKCS#8 key: the secret's `privateKey` field format.
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_b64_pkcs8 = base64.b64encode(private_key_der).decode("ascii")

    # PKCS#12 bundle for S3.
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=pkcs12_friendly_name.encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            pkcs12_password.encode("utf-8")
        ),
    )

    # SHA-1 thumbprint (Entra identifies uploaded certs by this).
    # SHA-1 is the algorithm Microsoft requires for the keyCredential
    # `customKeyIdentifier` / `x5t`; it identifies which uploaded certificate is
    # which and is not relied on for any security property. Signatures use
    # SHA-256 (see .sign above).
    #
    # The semgrep suppression sits on its own line rather than trailing the
    # bandit one: bandit reads everything after `nosec` as further test ids, so
    # appending to that comment would silently void the B303 suppression.
    # nosemgrep: insecure-hash-algorithm-sha1
    digest = hashes.Hash(hashes.SHA1())  # noqa: S303  # nosec B303
    digest.update(certificate_der)
    sha1 = digest.finalize()
    thumbprint_b64url = base64.urlsafe_b64encode(sha1).rstrip(b"=").decode("ascii")
    thumbprint_hex = sha1.hex()

    return GeneratedCertificate(
        certificate_pem=certificate_pem,
        certificate_der=certificate_der,
        private_key_b64_pkcs8=private_key_b64_pkcs8,
        pkcs12_bytes=p12_bytes,
        pkcs12_password=pkcs12_password,
        thumbprint_b64url=thumbprint_b64url,
        thumbprint_hex=thumbprint_hex,
        not_after=not_after.replace(microsecond=0).isoformat(),
    )


def certificate_der_b64(cert_der: bytes) -> str:
    """Return standard base64 of DER bytes, as Entra's keyCredentials wants."""
    return base64.b64encode(cert_der).decode("ascii")
