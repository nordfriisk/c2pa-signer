import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from PIL import Image

from c2pa_signer.cli import main as signer_main
from c2pa_signer.keystore import SERVICE
from c2pa_signer.keystore_cli import main as keystore_main
from c2pa_signer.signing import read_manifest


class MemoryKeyring(KeyringBackend):
    """Schlüsselspeicher im Arbeitsspeicher, damit die Tests ohne OS-Dienst laufen."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if self.store.pop((service, username), None) is None:
            raise PasswordDeleteError(username)


@pytest.fixture()
def memory_keyring():
    previous = keyring.get_keyring()
    kr = MemoryKeyring()
    keyring.set_keyring(kr)
    yield kr
    keyring.set_keyring(previous)


@pytest.fixture()
def pki(tmp_path, monkeypatch):
    monkeypatch.setenv("C2PA_SIGNER_KEY_PASSWORD", "test-passwort")
    certs = tmp_path / "certs"
    assert signer_main(["testcert", "--out", str(certs)]) == 0
    return certs


def test_import_show_delete(memory_keyring, pki, capsys):
    assert keystore_main(["import", str(pki / "signer-key.pem"), "--name", "test"]) == 0
    stored = memory_keyring.store[(SERVICE, "test")]
    assert "PRIVATE KEY" not in stored  # DER/Base64, keine PEM-Datei
    assert keystore_main(["show", "--name", "test"]) == 0
    assert "ES256" in capsys.readouterr().out
    assert keystore_main(["delete", "--name", "test"]) == 0
    assert (SERVICE, "test") not in memory_keyring.store
    assert keystore_main(["show", "--name", "test"]) == 2


def test_import_refuses_overwrite(memory_keyring, pki):
    key = str(pki / "signer-key.pem")
    assert keystore_main(["import", key]) == 0
    assert keystore_main(["import", key]) == 2
    assert keystore_main(["import", key, "--overwrite"]) == 0


def test_sign_with_keystore(memory_keyring, pki, tmp_path):
    keystore_main(["import", str(pki / "signer-key.pem")])
    src = tmp_path / "a.jpg"
    Image.new("RGB", (32, 24), (1, 2, 3)).save(src)
    out = tmp_path / "out"
    rc = signer_main(["sign", str(src), "-o", str(out), "-q",
                      "--cert", str(pki / "signer-chain.pem"), "--keystore", "default"])
    assert rc == 0
    info = read_manifest(out / "a.jpg", pki / "test-root-ca.pem")
    assert info["validation_state"] == "Trusted"


def test_sign_with_missing_keystore_entry(memory_keyring, pki, tmp_path):
    src = tmp_path / "a.jpg"
    Image.new("RGB", (8, 8)).save(src)
    rc = signer_main(["sign", str(src), "-o", str(tmp_path / "o"),
                      "--cert", str(pki / "signer-chain.pem"), "--keystore", "fehlt"])
    assert rc == 2


def test_key_and_keystore_are_exclusive(pki, tmp_path):
    with pytest.raises(SystemExit):
        signer_main(["sign", str(tmp_path), "-o", str(tmp_path / "o"),
                     "--cert", str(pki / "signer-chain.pem"),
                     "--key", str(pki / "signer-key.pem"), "--keystore", "x"])


@pytest.mark.skipif(not __import__("os").environ.get("C2PA_REAL_KEYRING"),
                    reason="nur mit echtem Schlüsselspeicher (CI unter Windows/macOS)")
def test_real_os_keyring_roundtrip(pki):
    import uuid

    from c2pa_signer.keys import load_key_file
    from c2pa_signer.keystore import delete_key, load_key, store_key

    name = f"ci-{uuid.uuid4().hex[:8]}"
    key = load_key_file(pki / "signer-key.pem", password=b"test-passwort")
    store_key(key, name)
    try:
        assert load_key(name).private_numbers() == key.private_numbers()
    finally:
        delete_key(name)
