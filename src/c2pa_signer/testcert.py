"""Erzeugt eine Test-PKI (Root-CA + Claim-Signing-Zertifikat) für die Entwicklung.

Das Endzertifikat folgt dem Zertifikatsprofil der C2PA-Spezifikation
(Kapitel "Certificate Profile"): kein CA-Zertifikat, KeyUsage
digitalSignature, ExtendedKeyUsage mit C2PA-Claim-Signing und emailProtection,
Subject/Authority Key Identifier. Die Root-CA steht natürlich NICHT auf der
C2PA-Trust-List; Validatoren zeigen solche Signaturen als "nicht
vertrauenswürdig" an, solange die Root nicht als Trust Anchor konfiguriert ist.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# id-kp-c2pa-claimSigning aus der C2PA-Spezifikation
C2PA_CLAIM_SIGNING_OID = x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")


@dataclass
class TestPki:
    root_cert: Path
    chain: Path
    key: ec.EllipticCurvePrivateKey  # wird vom Aufrufer im Schlüsselspeicher abgelegt


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "c2pa-signer TEST"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def create_test_pki(out_dir: Path, days: int = 365) -> TestPki:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name("c2pa-signer TEST Root CA")
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False,
            decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("c2pa-signer TEST Claim Signer"))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False,
            decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            C2PA_CLAIM_SIGNING_OID, ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    pem = serialization.Encoding.PEM
    pki = TestPki(out_dir / "test-root-ca.pem", out_dir / "signer-chain.pem", leaf_key)
    pki.root_cert.write_bytes(root.public_bytes(pem))
    # Kette ohne Root: Endzertifikat zuerst, Trust Anchor wird nicht mitgeliefert.
    pki.chain.write_bytes(leaf.public_bytes(pem))
    return pki
