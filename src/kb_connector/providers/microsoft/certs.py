"""Certificate generation for Entra app-only (certificate) auth.

Two flows need a certificate, and they differ in *who holds the private key*.
That single difference drives everything else about them.

`generate_self_signed` covers the Bedrock managed knowledge base. The connector holds the
private key itself: it reads a PKCS#12 (.p12) bundle from S3 and signs a JWT
client assertion to obtain a token. So this produces a key pair here, and the
private half has to be delivered to AWS. We produce *only* P12 because the
connector's crawl path accepts P12 or PEM but the control-plane ACL token path
accepts P12 only; PEM would silently break ACL crawling.

  Artifacts:
    * PKCS#12 bundle (cert + private key, password-protected) -> S3
    * headerless base64 PKCS#8 private key -> secret's `privateKey` field
    * certificate DER -> Entra app's keyCredentials
    * SHA-1 thumbprint in base64url (connector config) and hex (Entra portal)

`generate_kms_backed_cert` covers Amazon Quick admin-managed. The private key is
generated inside AWS KMS and cannot be exported; Quick signs assertions through
`kms:Sign`. So there is no key pair to generate here, no P12, and no secret:
only the KMS public key wrapped in a certificate for the Entra upload, signed by
that same KMS key.

  Artifacts:
    * certificate DER -> Entra app's keyCredentials
    * SHA-1 thumbprint in base64url (Quick console) and hex (Entra portal)

Both share `certificate_thumbprints`. Note the asymmetry in what "self-signed"
costs: the Bedrock path holds the private key, so signing is local and free,
while the Quick path must call out to KMS for the one signature, which is why
`generate_kms_backed_cert` takes a signer callback instead of a key.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import secrets as _secrets
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

# The signature algorithm for the KMS-backed certificate, named twice because
# KMS and asn1crypto spell it differently. RSASSA-PKCS1-v1_5 with SHA-256 is
# RS256, which is what Entra expects on a client assertion and what every
# mainstream CA supports.
_KMS_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"
_ASN1_SIGNATURE_ALGORITHM = "sha256_rsa"


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

    thumbprint_b64url, thumbprint_hex = certificate_thumbprints(certificate_der)

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


def certificate_thumbprints(certificate_der: bytes) -> tuple[str, str]:
    """Return a certificate's SHA-1 thumbprint as (base64url, hex).

    Both forms are needed and they are not interchangeable. Entra identifies an
    uploaded certificate by the hex form, which is what its portal displays;
    the base64url form (unpadded, `+/` mapped to `-_`) is what the connector
    config and the Amazon Quick console ask for. Handing over the wrong one
    fails as a certificate-validation error that names neither.

    SHA-1 is not a choice: it is the algorithm Microsoft specifies for the
    keyCredential `customKeyIdentifier` / `x5t`. It identifies which uploaded
    certificate is which and carries no security property here. Signatures use
    SHA-256.

    Equivalent to the shell pipeline in the Quick setup guide:
        openssl dgst -sha1 -binary cert.cer | base64 | tr '+/' '-_' | tr -d '='

    `usedforsecurity=False` is the declaration that this is an identifier rather
    than a security primitive. bandit reads it and does not flag the call, which
    is why there is no `# nosec` here. semgrep does not read it, so its
    suppression is still required.
    """
    # nosemgrep: insecure-hash-algorithm-sha1
    sha1 = hashlib.sha1(certificate_der, usedforsecurity=False).digest()
    thumbprint_b64url = base64.urlsafe_b64encode(sha1).rstrip(b"=").decode("ascii")
    # Uppercase, because that is how both the Entra portal and Graph's
    # keyCredentials.customKeyIdentifier render it. An operator comparing this
    # value against the portal should not have to notice a case difference.
    return thumbprint_b64url, sha1.hex().upper()


@dataclass
class KmsBackedCertificate:
    """A certificate whose key pair lives entirely in AWS KMS.

    No field carries private key material, so unlike GeneratedCertificate none
    of them need `repr=False`: the private half was created inside KMS and
    cannot be exported. That is the whole point of the admin-managed flow: there
    is no `.p12` to store and no private key to put in Secrets Manager.
    """

    certificate_pem: str
    certificate_der: bytes
    thumbprint_b64url: str  # base64url(SHA-1), no padding, for the Quick console
    thumbprint_hex: str     # uppercase hex SHA-1, for the Entra portal
    not_after: str          # ISO8601 expiry
    signing_key_arn: str    # the KMS key that both signs and is embedded


def generate_kms_backed_cert(
    *,
    public_key_der: bytes,
    signing_key_arn: str,
    sign: Callable[[bytes], bytes],
    common_name: str = "QuickSharePointServiceAuth",
    organization: str = "kb-connector",
    valid_days: int = 730,
) -> KmsBackedCertificate:
    """Build a self-signed X.509 certificate whose key pair is held in KMS.

    Entra needs an X.509 certificate to validate the assertions Quick signs, and
    the KMS private key cannot leave KMS to sign one. There are two ways around
    that, and this takes the better one.

    The AWS setup guide splices the KMS public key into a certificate signed by a
    throwaway local key (`openssl x509 -req -force_pubkey`), producing an
    artifact whose signature does not verify against its own embedded public key
    (OpenSSL says so while creating it). Entra accepts it, because Entra only
    reads the public key. Other things in the chain do not: strict X.509
    validators, compliance scanners, HSM importers, and security review all
    treat it as malformed, and it can never be turned into a CSR for a corporate
    CA because it fails Proof-of-Possession by construction.

    Instead, this signs the certificate with the KMS key itself. The
    TBSCertificate is assembled with asn1crypto, handed to `sign`, and the
    signature wrapped back into the DER structure. The result is RFC-compliant:
    the signature verifies against the embedded public key, because they are the
    same key pair. Entra behaves identically either way.

    Both properties are then checked before returning, so a certificate that
    would fail at runtime cannot reach the Entra upload. Verifying the
    self-signature is exactly the check Entra performs on a client assertion. KMS
    produced the signature and the embedded public key verifies it, so a pass
    here means the runtime flow works.

    Args:
        public_key_der: DER SubjectPublicKeyInfo, from
            core.kms_signing.get_public_key_der.
        signing_key_arn: recorded on the result so a certificate can be traced
            back to the key it was built from.
        sign: signs the TBSCertificate bytes with that same KMS key and returns
            a PKCS#1 v1.5 SHA-256 signature. See
            core.kms_signing.make_signer. Injected rather than calling KMS here,
            to keep this package free of any AWS dependency.
        valid_days: certificate lifetime. The KMS key outlives it, so rotation
            reissues a certificate from the same key: the Entra upload changes
            and the key ARN does not.

    Raises:
        ValueError: if the exported key is not RSA, or if the finished
            certificate fails either verification.
    """
    from asn1crypto import keys as asn1_keys
    from asn1crypto import x509 as asn1_x509

    public_key = serialization.load_der_public_key(public_key_der)
    if not isinstance(public_key, rsa.RSAPublicKey):
        # Guarded rather than cast: load_der_public_key returns a union of every
        # public key type, and a non-RSA key would otherwise fail deeper in with
        # an error that does not mention the key spec.
        raise ValueError(
            f"Expected an RSA public key from KMS, got "
            f"{type(public_key).__name__}. The signing key must be "
            f"RSA_2048 with SIGN_VERIFY usage."
        )

    name = asn1_x509.Name.build({
        "organization_name": organization,
        "common_name": common_name,
    })
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    not_before = now - _dt.timedelta(minutes=5)  # tolerate clock skew
    not_after = now + _dt.timedelta(days=valid_days)

    tbs = asn1_x509.TbsCertificate({
        "version": "v3",
        # Positive and within RFC 5280's 20-octet limit. `| 1` keeps it odd,
        # which cannot be zero and cannot be read as negative.
        "serial_number": _secrets.randbits(159) | 1,
        "signature": {"algorithm": _ASN1_SIGNATURE_ALGORITHM},
        "issuer": name,  # self-signed: issuer and subject are the same name
        "validity": {
            "not_before": {"utc_time": not_before},
            "not_after": {"utc_time": not_after},
        },
        "subject": name,
        "subject_public_key_info": asn1_keys.PublicKeyInfo.load(public_key_der),
        "extensions": [
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": {"ca": False},
            },
            {
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": {"digital_signature", "key_encipherment"},
            },
        ],
    })

    certificate_der = asn1_x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": {"algorithm": _ASN1_SIGNATURE_ALGORITHM},
        "signature_value": sign(tbs.dump()),
    }).dump()

    _verify_kms_backed_cert(certificate_der, public_key)

    certificate = x509.load_der_x509_certificate(certificate_der)
    thumbprint_b64url, thumbprint_hex = certificate_thumbprints(certificate_der)

    return KmsBackedCertificate(
        certificate_pem=certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii"),
        certificate_der=certificate_der,
        thumbprint_b64url=thumbprint_b64url,
        thumbprint_hex=thumbprint_hex,
        not_after=not_after.isoformat(),
        signing_key_arn=signing_key_arn,
    )


def _verify_kms_backed_cert(
    certificate_der: bytes, expected_public_key: rsa.RSAPublicKey
) -> None:
    """Check the finished certificate before it is uploaded to Entra.

    Two properties, both cheap and both worth failing loudly on, because the
    alternative is a certificate that Entra accepts at upload time and then
    rejects on every sync with an error that does not name the cause:

      * the embedded public key really is the KMS key's, so Entra will verify
        assertions against the key that signs them;
      * the self-signature verifies, which confirms the signer callback used
        that same key and the expected algorithm.
    """
    certificate = x509.load_der_x509_certificate(certificate_der)

    embedded = certificate.public_key()
    if (
        not isinstance(embedded, rsa.RSAPublicKey)
        or embedded.public_numbers() != expected_public_key.public_numbers()
    ):
        raise ValueError(
            "The generated certificate does not carry the KMS public key. "
            "Entra would verify assertions against the wrong key."
        )

    try:
        embedded.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "The generated certificate's signature does not verify against the "
            "KMS public key. The signer did not use the same key, or did not "
            f"use {_KMS_SIGNING_ALGORITHM}."
        ) from exc


def certificate_der_b64(cert_der: bytes) -> str:
    """Return standard base64 of DER bytes, as Entra's keyCredentials wants."""
    return base64.b64encode(cert_der).decode("ascii")
