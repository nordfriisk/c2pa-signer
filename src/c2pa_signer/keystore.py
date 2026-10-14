"""Ablage des Claim-Signing-Schlüssels im Schlüsselspeicher des Betriebssystems.

Verwendet die Bibliothek ``keyring``:

* Windows: Anmeldeinformationsverwaltung (Credential Manager, DPAPI-geschützt)
* macOS: Schlüsselbund (Keychain)
* Linux: Secret Service (GNOME Keyring, KWallet) oder Kernel-Keyring-Backends

Der Schlüssel liegt dort als PKCS#8 (DER, Base64) unter dem Dienstnamen
``c2pa-signer``. Der Schutz im Ruhezustand übernimmt der Schlüsselspeicher;
das entspricht der "dedicated key management component" aus Assurance Level 1
der C2PA Generator Product Security Requirements.
"""

from __future__ import annotations

import base64
import sys

import keyring
from keyring.errors import NoKeyringError, PasswordDeleteError
from cryptography.hazmat.primitives import serialization

SERVICE = "c2pa-signer"
DEFAULT_NAME = "default"
_PREFIX = "c2pa-signer:pkcs8-der-b64:v1:"
# Windows speichert Geheimnisse als UTF-16 mit max. 2560 Byte -> 1280 Zeichen.
_WINDOWS_MAX_CHARS = 1280


class KeystoreError(Exception):
    pass


def backend_name() -> str:
    kr = keyring.get_keyring()
    return f"{type(kr).__module__}.{type(kr).__name__}"


def _encode(private_key) -> str:
    der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return _PREFIX + base64.b64encode(der).decode("ascii")


def store_key(private_key, name: str = DEFAULT_NAME, overwrite: bool = False) -> None:
    """Legt einen privaten Schlüssel (cryptography-Objekt) im Schlüsselspeicher ab."""
    if not overwrite and _get_raw(name) is not None:
        raise KeystoreError(
            f"Unter dem Namen '{name}' liegt bereits ein Schlüssel "
            "(--overwrite zum Ersetzen).")
    secret = _encode(private_key)
    if sys.platform == "win32" and len(secret) > _WINDOWS_MAX_CHARS:
        raise KeystoreError(
            "Schlüssel ist zu groß für die Windows-Anmeldeinformationsverwaltung. "
            "Bitte einen EC-Schlüssel (P-256/P-384) verwenden.")
    try:
        keyring.set_password(SERVICE, name, secret)
    except NoKeyringError as exc:
        raise KeystoreError(_no_keyring_hint()) from exc


def load_key(name: str = DEFAULT_NAME):
    """Liest den privaten Schlüssel aus dem Schlüsselspeicher."""
    raw = _get_raw(name)
    if raw is None:
        raise KeystoreError(
            f"Kein Schlüssel '{name}' im Schlüsselspeicher ({backend_name()}). "
            "Mit 'c2pa-keystore import' ablegen.")
    if not raw.startswith(_PREFIX):
        raise KeystoreError(f"Eintrag '{name}' hat ein unbekanntes Format.")
    der = base64.b64decode(raw[len(_PREFIX):])
    return serialization.load_der_private_key(der, password=None)


def delete_key(name: str = DEFAULT_NAME) -> None:
    try:
        keyring.delete_password(SERVICE, name)
    except PasswordDeleteError as exc:
        raise KeystoreError(f"Kein Schlüssel '{name}' vorhanden.") from exc
    except NoKeyringError as exc:
        raise KeystoreError(_no_keyring_hint()) from exc


def _get_raw(name: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, name)
    except NoKeyringError as exc:
        raise KeystoreError(_no_keyring_hint()) from exc


def _no_keyring_hint() -> str:
    return ("Kein Schlüsselspeicher verfügbar. Unter Linux wird ein Secret-Service-"
            "Dienst benötigt (z. B. GNOME Keyring oder KWallet).")
