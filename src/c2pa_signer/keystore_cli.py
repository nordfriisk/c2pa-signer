"""Kommandozeile: c2pa-keystore {import,show,delete,backend}.

Legt den Claim-Signing-Schlüssel im Schlüsselspeicher des Betriebssystems ab,
damit er nicht als Datei auf der Platte liegen muss.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import __version__
from .keys import alg_for_key
from .keystore import (DEFAULT_NAME, SERVICE, KeystoreError, backend_name,
                       delete_key, load_key, store_key)


def _fingerprint(private_key) -> str:
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def cmd_import(args: argparse.Namespace) -> int:
    pem = args.keyfile.read_bytes()
    password = None
    if b"ENCRYPTED" in pem.split(b"\n", 1)[0]:
        password = getpass.getpass(f"Passwort für {args.keyfile}: ").encode()
    key = serialization.load_pem_private_key(pem, password=password)
    store_key(key, args.name, overwrite=args.overwrite)
    print(f"Schlüssel '{args.name}' abgelegt in {backend_name()} "
          f"(Dienst '{SERVICE}').")
    print(f"Algorithmus: {alg_for_key(key)}  SHA-256 (Public Key): {_fingerprint(key)}")
    print(f"Signieren mit: c2pa-signer sign ... --keystore {args.name}")
    print(f"Die Datei {args.keyfile} wird nicht mehr benötigt; "
          "bitte sicher löschen oder offline verwahren.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    key = load_key(args.name)
    print(f"Name:        {args.name}")
    print(f"Speicher:    {backend_name()}")
    print(f"Algorithmus: {alg_for_key(key)}")
    print(f"SHA-256 (Public Key): {_fingerprint(key)}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    delete_key(args.name)
    print(f"Schlüssel '{args.name}' gelöscht.")
    return 0


def cmd_backend(args: argparse.Namespace) -> int:
    print(backend_name())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c2pa-keystore",
        description="Signierschlüssel im Schlüsselspeicher des Betriebssystems verwalten.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("import", help="Schlüssel aus einer PEM-Datei übernehmen")
    i.add_argument("keyfile", type=Path, help="Privater Schlüssel (PEM, gern verschlüsselt)")
    i.add_argument("--name", default=DEFAULT_NAME, help="Name des Eintrags")
    i.add_argument("--overwrite", action="store_true", help="Vorhandenen Eintrag ersetzen")
    i.set_defaults(func=cmd_import)

    s = sub.add_parser("show", help="Algorithmus und Fingerabdruck anzeigen")
    s.add_argument("--name", default=DEFAULT_NAME)
    s.set_defaults(func=cmd_show)

    d = sub.add_parser("delete", help="Schlüssel aus dem Speicher löschen")
    d.add_argument("--name", default=DEFAULT_NAME)
    d.set_defaults(func=cmd_delete)

    b = sub.add_parser("backend", help="Verwendeten Schlüsselspeicher anzeigen")
    b.set_defaults(func=cmd_backend)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (KeystoreError, ValueError, OSError) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
