import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from PIL import Image

from c2pa_signer.cli import main as signer_main
from c2pa_signer.keystore import SERVICE
from c2pa_signer.keystore_cli import main as keystore_main
from c2pa_signer.signing import read_manifest


@pytest.fixture()
def keyfile(tmp_path):
    """Verschlüsselte PEM-Datei, wie sie z. B. bei einer CA entsteht."""
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "key.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"geheim")))
    return path


@pytest.fixture(autouse=True)
def password_prompt(monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "geheim")


def test_import_show_delete(memory_keyring, keyfile, capsys):
    assert keystore_main(["import", str(keyfile), "--name", "test"]) == 0
    stored = memory_keyring.store[(SERVICE, "test")]
    assert "PRIVATE KEY" not in stored  # DER/Base64, keine PEM-Datei
    assert keystore_main(["show", "--name", "test"]) == 0
    assert "ES256" in capsys.readouterr().out
    assert keystore_main(["delete", "--name", "test"]) == 0
    assert (SERVICE, "test") not in memory_keyring.store
    assert keystore_main(["show", "--name", "test"]) == 2


def test_import_refuses_overwrite(keyfile):
    key = str(keyfile)
    assert keystore_main(["import", key]) == 0
    assert keystore_main(["import", key]) == 2
    assert keystore_main(["import", key, "--overwrite"]) == 0


def test_sign_with_keystore(pki, tmp_path):
    src = tmp_path / "a.jpg"
    Image.new("RGB", (32, 24), (1, 2, 3)).save(src)
    out = tmp_path / "out"
    rc = signer_main(["sign", str(src), "-o", str(out), "-q",
                      "--cert", str(pki / "signer-chain.pem"), "--keystore", "default"])
    assert rc == 0
    info = read_manifest(out / "a.jpg", pki / "test-root-ca.pem")
    assert info["validation_state"] == "Trusted"


def test_sign_with_missing_keystore_entry(pki, tmp_path):
    src = tmp_path / "a.jpg"
    Image.new("RGB", (8, 8)).save(src)
    rc = signer_main(["sign", str(src), "-o", str(tmp_path / "o"),
                      "--cert", str(pki / "signer-chain.pem"), "--keystore", "fehlt"])
    assert rc == 2


@pytest.mark.skipif(not __import__("os").environ.get("C2PA_REAL_KEYRING"),
                    reason="nur mit echtem Schlüsselspeicher (CI unter Windows/macOS)")
def test_real_os_keyring_roundtrip(memory_keyring):
    import uuid

    import keyring
    from keyring.backend import get_all_keyring

    from conftest import MemoryKeyring

    from c2pa_signer.keystore import delete_key, load_key, store_key

    # Echten Speicher des Betriebssystems verwenden, nicht den Testspeicher.
    real = max((kr for kr in get_all_keyring() if not isinstance(kr, MemoryKeyring)),
               key=lambda kr: kr.priority)
    assert real.priority > 0, f"kein Schlüsselspeicher verfügbar: {real}"
    keyring.set_keyring(real)
    name = f"ci-{uuid.uuid4().hex[:8]}"
    key = ec.generate_private_key(ec.SECP256R1())
    store_key(key, name)
    try:
        assert load_key(name).private_numbers() == key.private_numbers()
    finally:
        delete_key(name)
