# c2pa-signer

Kommandozeilentool, das JPG-Bilder nach dem [C2PA-Standard](https://c2pa.org)
(Content Credentials, [Content Authenticity Initiative](https://contentauthenticity.org))
signiert und prüft. Läuft unter Linux, Windows und macOS (Python ≥ 3.10).
Basis ist die offizielle Bibliothek [`c2pa-python`](https://github.com/contentauth/c2pa-python).

## Installation

```bash
python -m pip install -e ".[dev]"
```

## Schlüssel

Der private Signierschlüssel liegt ausschließlich im Schlüsselspeicher des
Betriebssystems: Windows-Anmeldeinformationsverwaltung, macOS-Schlüsselbund oder
unter Linux Secret Service (GNOME Keyring, KWallet). Es gibt keine Schlüsseldatei
und kein Passwort beim Signieren; geschützt wird der Schlüssel durch die Anmeldung
am Betriebssystem.

## Schnellstart mit Testzertifikat

```bash
# Test-PKI erzeugen: Zertifikate nach certs/, Schlüssel direkt in den Schlüsselspeicher
c2pa-signer testcert --out certs

# Eine Datei signieren
c2pa-signer sign foto.jpg --cert certs/signer-chain.pem -o foto-signiert.jpg

# Alle JPGs eines Verzeichnisses (mit -r auch Unterverzeichnisse) signieren
c2pa-signer sign ./bilder -r --cert certs/signer-chain.pem -o ./signiert --author "Stefan"

# Prüfen (ohne Trust Anchor: "Valid", mit Test-Root: "Trusted")
c2pa-signer verify ./signiert -r --trust-anchors certs/test-root-ca.pem
```

## Schlüssel verwalten

```bash
c2pa-keystore import schluessel.pem   # vorhandenen Schlüssel übernehmen (z. B. für ein CA-Zertifikat)
c2pa-keystore show                    # Algorithmus und Fingerabdruck
c2pa-keystore delete                  # Eintrag entfernen
```

Ohne Angabe heißt der Eintrag `default`. Mit `--name` (bei `testcert` und
`c2pa-keystore`) bzw. `--keystore NAME` (bei `sign`) lassen sich mehrere Schlüssel
verwalten, z. B. für die Rotation. Nach einem Import wird die PEM-Datei nicht mehr
gebraucht. Unter Windows passen nur EC-Schlüssel (P-256/P-384) in die
Anmeldeinformationsverwaltung.

## Befehle

| Befehl | Zweck |
|---|---|
| `sign` | Dateien/Verzeichnisse signieren. `--cert` Zertifikatskette, `--keystore` Schlüsselname (Standard `default`), `-o` Ziel (Verzeichnis oder bei einer Datei auch Dateiname), alternativ `--in-place`. `-r` rekursiv, `--tsa-url` Zeitstempeldienst, `--author`, `--title`. |
| `verify` | Manifest lesen und Signatur prüfen, `--trust-anchors` für eigene Roots, `--json` für die volle Ausgabe. Exit-Code 1 bei ungültigen oder fehlenden Manifesten. |
| `c2pa-keystore` | Schlüssel im Schlüsselspeicher ablegen (`import`), anzeigen (`show`), löschen (`delete`), Speicher anzeigen (`backend`). |
| `testcert` | Test-PKI nach dem C2PA-Zertifikatsprofil erzeugen, Schlüssel landet im Schlüsselspeicher. **Nur für Entwicklung.** |

Bereits signierte Bilder behalten ihre Historie: das alte Manifest wird als
Parent-Ingredient (Aktion `c2pa.opened`) in das neue übernommen.

## Sicherheit

* Der Schlüssel liegt nur im Schlüsselspeicher des Betriebssystems, nie als Datei.
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
