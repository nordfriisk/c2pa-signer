"""Kommandozeile: c2pa-signer {sign,verify,testcert}."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__
from .keys import PASSWORD_ENV, FileKeyBackend, KeystoreKeyBackend
from .keystore import KeystoreError
from .signing import (JPEG_SUFFIXES, SignOptions, iter_jpegs, make_signer,
                      read_manifest, sign_many)
from .testcert import create_test_pki


def _plan_targets(inputs: list[Path], output: Path | None, in_place: bool,
                  recursive: bool) -> list[tuple[Path, Path]]:
    pairs: list[tuple[Path, Path]] = []
    single_file_out = (output is not None and len(inputs) == 1
                       and inputs[0].is_file()
                       and output.suffix.lower() in JPEG_SUFFIXES)
    for inp in inputs:
        if not inp.exists():
            raise SystemExit(f"Nicht gefunden: {inp}")
        for src in iter_jpegs(inp, recursive):
            if in_place:
                dst = src
            elif single_file_out:
                dst = output
            else:
                rel = src.relative_to(inp) if inp.is_dir() else Path(src.name)
                dst = output / rel
            if not in_place and dst.resolve() == src.resolve():
                raise SystemExit(f"Ziel wäre das Original: {src} (--in-place verwenden)")
            pairs.append((src, dst))
    return pairs


def cmd_sign(args: argparse.Namespace) -> int:
    if not args.in_place and args.output is None:
        raise SystemExit("Bitte --output angeben oder --in-place verwenden.")
    pairs = _plan_targets(args.inputs, args.output, args.in_place, args.recursive)
    if not pairs:
        print("Keine JPG-Dateien gefunden.", file=sys.stderr)
        return 1
    if args.keystore:
        backend = KeystoreKeyBackend(args.keystore)
    else:
        backend = FileKeyBackend(args.key, allow_unencrypted=args.allow_unencrypted_key)
    chain = args.cert.read_text()
    signer = make_signer(backend, chain, args.tsa_url)
    opts = SignOptions(author=args.author, title=args.title, tsa_url=args.tsa_url)
    failed = 0
    try:
        for res in sign_many(pairs, signer, opts):
            if res.ok:
                if not args.quiet:
                    print(f"OK      {res.source} -> {res.target}")
            else:
                failed += 1
                print(f"FEHLER  {res.source}: {res.message}", file=sys.stderr)
    finally:
        signer.close()
    print(f"{len(pairs) - failed} signiert, {failed} fehlgeschlagen.", file=sys.stderr)
    return 1 if failed else 0


def cmd_verify(args: argparse.Namespace) -> int:
    bad = 0
    for inp in args.inputs:
        for path in iter_jpegs(inp, args.recursive):
            try:
                info = read_manifest(path, args.trust_anchors)
            except Exception as exc:
                bad += 1
                print(f"KEIN MANIFEST  {path}: {exc}")
                continue
            state = info["validation_state"]
            if args.json:
                print(json.dumps({"file": str(path), **info}, indent=2, default=str))
            else:
                m = info["active_manifest"] or {}
                sig = m.get("signature_info", {})
                print(f"{state:<14} {path}  ({sig.get('issuer', '?')}, "
                      f"{sig.get('common_name', '?')})")
            ok_states = {"Trusted"} if args.trust_anchors else {"Trusted", "Valid"}
            if state not in ok_states:
                bad += 1
    return 1 if bad else 0


def cmd_testcert(args: argparse.Namespace) -> int:
    password = None
    if not args.no_password:
        env = os.environ.get(PASSWORD_ENV)
        password = (env or getpass.getpass("Passwort für den Testschlüssel: ")).encode()
    pki = create_test_pki(args.out, password, args.days)
    print(f"Root-CA (Trust Anchor zum Prüfen): {pki.root_cert}")
    print(f"Zertifikatskette:                  {pki.chain}")
    print(f"Privater Schlüssel:                {pki.key}")
    print("Achtung: nur für Entwicklung, nicht auf der C2PA-Trust-List.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="c2pa-signer",
                                description="JPG-Bilder nach C2PA signieren und prüfen.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sign", help="Dateien oder Verzeichnisse signieren")
    s.add_argument("inputs", nargs="+", type=Path, help="JPG-Dateien oder Verzeichnisse")
    s.add_argument("--cert", required=True, type=Path,
                   help="Zertifikatskette (PEM, Endzertifikat zuerst)")
    key = s.add_mutually_exclusive_group(required=True)
    key.add_argument("--key", type=Path, help="Privater Schlüssel (PEM-Datei)")
    key.add_argument("--keystore", metavar="NAME",
                     help="Schlüssel aus dem Schlüsselspeicher des Betriebssystems "
                          "(abgelegt mit c2pa-keystore import)")
    out = s.add_mutually_exclusive_group()
    out.add_argument("-o", "--output", type=Path,
                     help="Zielverzeichnis (oder Zieldatei bei genau einer Eingabedatei)")
    out.add_argument("--in-place", action="store_true", help="Originale überschreiben")
    s.add_argument("-r", "--recursive", action="store_true",
                   help="Unterverzeichnisse einbeziehen")
    s.add_argument("--tsa-url", help="RFC-3161-Zeitstempeldienst")
    s.add_argument("--author", help="Name des Urhebers")
    s.add_argument("--title", help="Titel (Standard: Dateiname)")
    s.add_argument("--allow-unencrypted-key", action="store_true",
                   help="Unverschlüsselten Schlüssel zulassen (nur Tests)")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Manifest lesen und Signatur prüfen")
    v.add_argument("inputs", nargs="+", type=Path)
    v.add_argument("-r", "--recursive", action="store_true")
    v.add_argument("--trust-anchors", type=Path,
                   help="PEM mit vertrauenswürdigen Root-Zertifikaten")
    v.add_argument("--json", action="store_true", help="Vollständige Ausgabe als JSON")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("testcert", help="Test-PKI für die Entwicklung erzeugen")
    t.add_argument("--out", type=Path, default=Path("certs"))
    t.add_argument("--days", type=int, default=365)
    t.add_argument("--no-password", action="store_true",
                   help="Schlüssel unverschlüsselt speichern")
    t.set_defaults(func=cmd_testcert)
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
