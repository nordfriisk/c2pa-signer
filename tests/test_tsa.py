"""Signieren mit Zeitstempel eines TSA von der C2PA-TSA-Trust-List.

Braucht Netzzugang zum Zeitstempeldienst und läuft deshalb nur, wenn
C2PA_TSA_TEST gesetzt ist (in der CI unter Linux).
"""

import json
import os
import urllib.request

import pytest
from PIL import Image

from c2pa_signer.cli import main
from c2pa_signer.signing import DEFAULT_TSA_URL, read_manifest

TSA_TRUST_LIST = ("https://raw.githubusercontent.com/c2pa-org/conformance-public/"
                  "main/trust-list/C2PA-TSA-TRUST-LIST.pem")

pytestmark = pytest.mark.skipif(not os.environ.get("C2PA_TSA_TEST"),
                                reason="braucht Netzzugang zum TSA (C2PA_TSA_TEST=1)")


def _status_codes(results: dict, kind: str) -> list[str]:
    active = (results or {}).get("activeManifest", {})
    return [entry["code"] for entry in active.get(kind, [])]


def test_sign_with_trust_listed_tsa(pki, tmp_path):
    src = tmp_path / "a.jpg"
    Image.new("RGB", (32, 24), (5, 6, 7)).save(src)
    out = tmp_path / "a-signiert.jpg"
    rc = main(["sign", str(src), "-o", str(out), "-q",
               "--cert", str(pki / "signer-chain.pem"), "--tsa-url", DEFAULT_TSA_URL])
    assert rc == 0

    # Trust Anchors: Test-Root (Signierzertifikat) + offizielle C2PA-TSA-Trust-List
    with urllib.request.urlopen(TSA_TRUST_LIST, timeout=30) as resp:
        tsa_roots = resp.read().decode()
    anchors = tmp_path / "anchors.pem"
    anchors.write_text((pki / "test-root-ca.pem").read_text() + "\n" + tsa_roots)

    info = read_manifest(out, anchors)
    results = info["validation_results"]
    print(json.dumps(results, indent=2))
    success = _status_codes(results, "success")
    failure = _status_codes(results, "failure")
    informational = _status_codes(results, "informational")

    assert "timeStamp.validated" in success
    assert "timeStamp.trusted" in success
    assert "timeStamp.untrusted" not in informational
    assert not failure
    assert info["validation_state"] == "Trusted"
    # Mit Zeitstempel trägt die Signatur die Zeit des TSA.
    assert info["active_manifest"]["signature_info"].get("time")
