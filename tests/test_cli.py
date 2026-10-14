
import pytest
from PIL import Image

from c2pa_signer.cli import main
from c2pa_signer.signing import read_manifest

@pytest.fixture()
def images(tmp_path):
    d = tmp_path / "in"
    (d / "sub").mkdir(parents=True)
    for name in ["a.jpg", "b.JPEG", "sub/c.jpg"]:
        Image.new("RGB", (32, 24), (10, 120, 200)).save(d / name)
    (d / "notes.txt").write_text("kein Bild")
    return d


def _sign(pki, *args):
    return main(["sign", *args, "--cert", str(pki / "signer-chain.pem"), "-q"])


def test_sign_directory_recursive(pki, images, tmp_path):
    out = tmp_path / "out"
    assert _sign(pki, str(images), "-r", "-o", str(out), "--author", "Stefan") == 0
    signed = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert signed == ["a.jpg", "b.JPEG", "sub/c.jpg"]
    info = read_manifest(out / "a.jpg", pki / "test-root-ca.pem")
    assert info["validation_state"] == "Trusted"
    labels = [a["label"] for a in info["active_manifest"]["assertions"]]
    assert "stds.schema-org.CreativeWork" in labels


def test_sign_directory_non_recursive(pki, images, tmp_path):
    out = tmp_path / "out"
    assert _sign(pki, str(images), "-o", str(out)) == 0
    assert not (out / "sub").exists()


def test_sign_single_file_to_file(pki, images, tmp_path):
    target = tmp_path / "x" / "signiert.jpg"
    assert _sign(pki, str(images / "a.jpg"), "-o", str(target)) == 0
    assert read_manifest(target)["validation_state"] == "Valid"


def test_in_place_and_resign_keeps_history(pki, images):
    src = images / "a.jpg"
    assert _sign(pki, str(src), "--in-place") == 0
    assert _sign(pki, str(src), "--in-place") == 0
    manifest = read_manifest(src)["active_manifest"]
    assert manifest["ingredients"][0].get("active_manifest")


def test_tampered_file_fails_verify(pki, images, tmp_path):
    out = tmp_path / "out"
    _sign(pki, str(images / "a.jpg"), "-o", str(out))
    data = bytearray((out / "a.jpg").read_bytes())
    data[-20] ^= 0xFF
    (out / "a.jpg").write_bytes(data)
    assert main(["verify", str(out / "a.jpg")]) == 1


def test_untrusted_root_fails_with_trust_anchors(pki, images, tmp_path):
    other = tmp_path / "other"
    main(["testcert", "--out", str(other), "--name", "anderer"])
    out = tmp_path / "out"
    _sign(pki, str(images / "a.jpg"), "-o", str(out))
    assert main(["verify", str(out), "--trust-anchors",
                 str(other / "test-root-ca.pem")]) == 1


def test_testcert_refuses_to_overwrite_key(pki, tmp_path):
    assert main(["testcert", "--out", str(tmp_path / "neu")]) == 2
    assert main(["testcert", "--out", str(tmp_path / "neu"), "--overwrite"]) == 0
    assert not list((tmp_path / "neu").glob("*key*"))


def test_output_required(pki, images):
    with pytest.raises(SystemExit):
        _sign(pki, str(images))
