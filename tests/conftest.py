import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from c2pa_signer.cli import main


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


@pytest.fixture(autouse=True)
def memory_keyring():
    previous = keyring.get_keyring()
    kr = MemoryKeyring()
    keyring.set_keyring(kr)
    yield kr
    keyring.set_keyring(previous)


@pytest.fixture()
def pki(tmp_path):
    """Test-PKI; der Schlüssel liegt im Speicher unter dem Namen 'default'."""
    certs = tmp_path / "certs"
    assert main(["testcert", "--out", str(certs)]) == 0
    return certs
