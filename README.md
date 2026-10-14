# c2pa-signer

Kommandozeilentool, das JPG-Bilder nach dem [C2PA-Standard](https://c2pa.org)
(Content Credentials, [Content Authenticity Initiative](https://contentauthenticity.org))
signiert und prüft. Läuft unter Linux, Windows und macOS (Python ≥ 3.10).
Basis ist die offizielle Bibliothek [`c2pa-python`](https://github.com/contentauth/c2pa-python).

## Installation

```bash
python -m pip install -e ".[dev]"
```

## Schnellstart mit Testzertifikat

```bash
# Test-PKI erzeugen (Root-CA + Signierzertifikat, Schlüssel passwortgeschützt)
c2pa-signer testcert --out certs

# Passwort für den Schlüssel (sonst wird interaktiv gefragt)
export C2PA_SIGNER_KEY_PASSWORD=...        # Windows: set C2PA_SIGNER_KEY_PASSWORD=...

# Eine Datei signieren
c2pa-signer sign foto.jpg --cert certs/signer-chain.pem --key certs/signer-key.pem -o foto-signiert.jpg

# Alle JPGs eines Verzeichnisses (mit -r auch Unterverzeichnisse) signieren
c2pa-signer sign ./bilder -r --cert certs/signer-chain.pem --key certs/signer-key.pem -o ./signiert --author "Stefan"

# Prüfen (ohne Trust Anchor: "Valid", mit Test-Root: "Trusted")
c2pa-signer verify ./signiert -r --trust-anchors certs/test-root-ca.pem
```

## Schlüssel im Schlüsselspeicher des Betriebssystems

Statt einer Schlüsseldatei kann der private Schlüssel im Schlüsselspeicher des
Betriebssystems liegen: Windows-Anmeldeinformationsverwaltung, macOS-Schlüsselbund
oder unter Linux Secret Service (GNOME Keyring, KWallet).

```bash
c2pa-keystore import certs/signer-key.pem          # einmalig ablegen (Name: default)
c2pa-keystore show                                  # Algorithmus und Fingerabdruck
c2pa-signer sign ./bilder -r --cert certs/signer-chain.pem --keystore default -o ./signiert
c2pa-keystore delete                                # Eintrag entfernen
```

Mit `--name` lassen sich mehrere Schlüssel verwalten, z. B. für die Rotation.
Danach wird die Schlüsseldatei nicht mehr gebraucht und sollte sicher gelöscht
oder offline verwahrt werden. Unter Windows passen nur EC-Schlüssel (P-256/P-384)
in die Anmeldeinformationsverwaltung.

## Befehle

| Befehl | Zweck |
|---|---|
| `sign` | Dateien/Verzeichnisse signieren. `-o` Ziel (Verzeichnis oder bei einer Datei auch Dateiname), alternativ `--in-place`. `-r` rekursiv, `--tsa-url` Zeitstempeldienst, `--author`, `--title`. |
| `verify` | Manifest lesen und Signatur prüfen, `--trust-anchors` für eigene Roots, `--json` für die volle Ausgabe. Exit-Code 1 bei ungültigen oder fehlenden Manifesten. |
| `c2pa-keystore` | Schlüssel im Schlüsselspeicher ablegen (`import`), anzeigen (`show`), löschen (`delete`), Speicher anzeigen (`backend`). |
| `testcert` | Test-PKI nach dem C2PA-Zertifikatsprofil erzeugen. **Nur für Entwicklung.** |

Bereits signierte Bilder behalten ihre Historie: das alte Manifest wird als
Parent-Ingredient (Aktion `c2pa.opened`) in das neue übernommen.

## Sicherheit

* Private Schlüssel müssen verschlüsselt sein; unverschlüsselte nur mit `--allow-unencrypted-key`.
* Alternativ liegt der Schlüssel im Schlüsselspeicher des Betriebssystems (`--keystore`).
* Signiert wird über einen Callback (`keys.py`); weitere Schlüssel-Backends
  (PKCS#11/HSM, Cloud-KMS) lassen sich dort ergänzen.
* Schlüssel und Zertifikate niemals einchecken (`.gitignore` schließt `certs/` und `*.pem` aus).

## Conformance

Ziel ist die Aufnahme in die offizielle Liste konformer C2PA-Produkte.
Was dafür nötig ist und wie das Design darauf ausgerichtet ist: [docs/conformance.md](docs/conformance.md).

## Tests

```bash
python -m pytest
```
