"""Signieren und Prüfen von JPG-Dateien mit dem C2PA-SDK."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

import c2pa

from . import CLAIM_GENERATOR_NAME, __version__
from .keys import KeyBackend

JPEG_SUFFIXES = {".jpg", ".jpeg"}


@dataclass
class SignOptions:
    author: str | None = None
    title: str | None = None
    tsa_url: str | None = None


@dataclass
class Result:
    source: Path
    target: Path | None
    ok: bool
    message: str = ""


def iter_jpegs(path: Path, recursive: bool) -> Iterator[Path]:
    if path.is_file():
        yield path
        return
    pattern = "**/*" if recursive else "*"
    for p in sorted(path.glob(pattern)):
        if p.is_file() and p.suffix.lower() in JPEG_SUFFIXES:
            yield p


def build_manifest(source: Path, opts: SignOptions) -> dict:
    assertions = []
    if opts.author:
        # CAWG/Schema.org-Autorenangabe als einfache Metadaten-Assertion
        assertions.append({
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org",
                "@type": "CreativeWork",
                "author": [{"@type": "Person", "name": opts.author}],
            },
        })
    return {
        "claim_generator_info": [{"name": CLAIM_GENERATOR_NAME,
                                  "version": __version__}],
        "title": opts.title or source.name,
        "format": "image/jpeg",
        "assertions": assertions,
    }


def make_signer(backend: KeyBackend, chain_pem: str,
                tsa_url: str | None) -> c2pa.Signer:
    return c2pa.Signer.from_callback(backend.sign, backend.alg, chain_pem, tsa_url)


def sign_file(source: Path, target: Path, signer: c2pa.Signer,
              opts: SignOptions) -> None:
    """Signiert eine JPG-Datei.

    Intent EDIT: das Ausgangsbild wird als Parent-Ingredient mit der Aktion
    c2pa.opened eingetragen. Ein bereits vorhandenes Manifest bleibt so als
    Provenienzkette erhalten.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    builder = c2pa.Builder(json.dumps(build_manifest(source, opts)))
    try:
        builder.set_intent(c2pa.C2paBuilderIntent.EDIT)
        # In eine temporäre Datei schreiben und dann atomar ersetzen, damit
        # bei --in-place nie ein halb geschriebenes Original übrig bleibt.
        fd, tmp_name = tempfile.mkstemp(suffix=".jpg", dir=target.parent)
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            with open(source, "rb") as src, open(tmp, "w+b") as dst:
                builder.sign(signer, "image/jpeg", src, dst)
            os.replace(tmp, target)
        finally:
            tmp.unlink(missing_ok=True)
    finally:
        builder.close()


def sign_many(sources: Iterable[tuple[Path, Path]], signer: c2pa.Signer,
              opts: SignOptions) -> Iterator[Result]:
    for source, target in sources:
        try:
            sign_file(source, target, signer, opts)
            yield Result(source, target, True)
        except Exception as exc:  # pro Datei weitermachen
            yield Result(source, target, False, str(exc))


def read_manifest(path: Path, trust_anchors: Path | None = None) -> dict:
    """Liest das Manifest und gibt Validierungsstatus plus aktives Manifest zurück."""
    settings: dict = {"verify": {"verify_trust": trust_anchors is not None}}
    if trust_anchors is not None:
        settings["trust"] = {"trust_anchors": trust_anchors.read_text()}
    context = c2pa.Context.from_dict(settings)
    reader = c2pa.Reader(str(path), context=context)
    try:
        return {
            "validation_state": reader.get_validation_state(),
            "validation_results": reader.get_validation_results(),
            "active_manifest": reader.get_active_manifest(),
        }
    finally:
        reader.close()
        context.close()
