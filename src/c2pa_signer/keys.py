"""Schlüssel-Backends für die Claim-Signatur.

Die Signatur läuft immer über eine Callback-Funktion. Dadurch muss der
private Schlüssel nie als Klartext an die C2PA-Bibliothek übergeben werden,
und weitere Backends (Betriebssystem-Schlüsselspeicher, PKCS#11/HSM, Cloud-KMS)
lassen sich ergänzen, ohne den Rest des Tools zu ändern. Das ist die
Grundlage für die Sicherheitsanforderungen des C2PA-Conformance-Programms
(siehe docs/conformance.md).
"""

from __future__ import annotations

import getpass
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import c2pa

PASSWORD_ENV = "C2PA_SIGNER_KEY_PASSWORD"

_EC_ALGS = {
    "ES256": (c2pa.C2paSigningAlg.ES256, hashes.SHA256, 32),
    "ES384": (c2pa.C2paSigningAlg.ES384, hashes.SHA384, 48),
    "ES512": (c2pa.C2paSigningAlg.ES512, hashes.SHA512, 66),
}
_PS_ALGS = {
    "PS256": (c2pa.C2paSigningAlg.PS256, hashes.SHA256),
    "PS384": (c2pa.C2paSigningAlg.PS384, hashes.SHA384),
    "PS512": (c2pa.C2paSigningAlg.PS512, hashes.SHA512),
}


class KeyBackend(ABC):
    """Abstraktion über den Ort, an dem der private Schlüssel liegt."""

    alg_name: str

    @property
    def alg(self) -> c2pa.C2paSigningAlg:
        if self.alg_name in _EC_ALGS:
            return _EC_ALGS[self.alg_name][0]
        if self.alg_name in _PS_ALGS:
            return _PS_ALGS[self.alg_name][0]
        return c2pa.C2paSigningAlg.ED25519

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Signiert die vom C2PA-SDK gelieferten Daten (COSE Sig_structure)."""


class FileKeyBackend(KeyBackend):
    """Privater Schlüssel als (verschlüsselte) PKCS#8-PEM-Datei.

    Das Passwort kommt aus der Umgebungsvariable C2PA_SIGNER_KEY_PASSWORD
    oder wird interaktiv abgefragt. Unverschlüsselte Schlüssel werden nur
    mit allow_unencrypted=True akzeptiert (Entwicklung/Tests).
    """

    def __init__(self, key_path: Path, password: bytes | None = None,
                 allow_unencrypted: bool = False) -> None:
        pem = Path(key_path).read_bytes()
        encrypted = b"ENCRYPTED" in pem.split(b"\n", 1)[0]
        if not encrypted and not allow_unencrypted:
            raise ValueError(
                f"{key_path}: Schlüssel ist nicht verschlüsselt. "
                "Mit --allow-unencrypted-key nur für Tests zulassen."
            )
        if encrypted and password is None:
            env = os.environ.get(PASSWORD_ENV)
            password = env.encode() if env else getpass.getpass(
                f"Passwort für {key_path}: ").encode()
        self._key = serialization.load_pem_private_key(
            pem, password=password if encrypted else None)
        self.alg_name = _alg_for_key(self._key)

    def sign(self, data: bytes) -> bytes:
        key = self._key
        if isinstance(key, ec.EllipticCurvePrivateKey):
            _, hash_cls, size = _EC_ALGS[self.alg_name]
            der = key.sign(data, ec.ECDSA(hash_cls()))
            r, s = decode_dss_signature(der)
            # COSE erwartet r||s mit fester Länge (IEEE P1363), nicht DER.
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        if isinstance(key, rsa.RSAPrivateKey):
            hash_cls = _PS_ALGS[self.alg_name][1]
            return key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hash_cls()),
                            salt_length=hash_cls().digest_size),
                hash_cls(),
            )
        return key.sign(data)


def _alg_for_key(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"secp256r1": "ES256", "secp384r1": "ES384",
                "secp521r1": "ES512"}[key.curve.name]
    if isinstance(key, rsa.RSAPrivateKey):
        return "PS256"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ED25519"
    raise ValueError(f"Nicht unterstützter Schlüsseltyp: {type(key).__name__}")
