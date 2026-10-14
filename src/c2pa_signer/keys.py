"""Claim-Signatur mit dem Schlüssel aus dem Schlüsselspeicher des Betriebssystems.

Die Signatur läuft über eine Callback-Funktion. Dadurch wird der private
Schlüssel nie an die C2PA-Bibliothek übergeben. Abgelegt wird er mit
``c2pa-keystore import`` oder ``c2pa-signer testcert`` (siehe keystore.py).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import c2pa

from .keystore import load_key

_EC_ALGS = {
    "ES256": (c2pa.C2paSigningAlg.ES256, hashes.SHA256, 32),
    "ES384": (c2pa.C2paSigningAlg.ES384, hashes.SHA384, 48),
    "ES512": (c2pa.C2paSigningAlg.ES512, hashes.SHA512, 66),
}
_PS_ALGS = {
    "PS256": (c2pa.C2paSigningAlg.PS256, hashes.SHA256),
}


class KeystoreKeyBackend:
    """Signiert mit dem Schlüssel ``name`` aus dem Schlüsselspeicher."""

    def __init__(self, name: str) -> None:
        self._key = load_key(name)
        self.alg_name = alg_for_key(self._key)

    @property
    def alg(self) -> c2pa.C2paSigningAlg:
        if self.alg_name in _EC_ALGS:
            return _EC_ALGS[self.alg_name][0]
        if self.alg_name in _PS_ALGS:
            return _PS_ALGS[self.alg_name][0]
        return c2pa.C2paSigningAlg.ED25519

    def sign(self, data: bytes) -> bytes:
        """Signiert die vom C2PA-SDK gelieferten Daten (COSE Sig_structure)."""
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


def alg_for_key(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"secp256r1": "ES256", "secp384r1": "ES384",
                "secp521r1": "ES512"}[key.curve.name]
    if isinstance(key, rsa.RSAPrivateKey):
        return "PS256"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ED25519"
    raise ValueError(f"Nicht unterstützter Schlüsseltyp: {type(key).__name__}")
