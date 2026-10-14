# Weg zur C2PA-Conformance

Stand der Recherche: 14.10.2026. Quellen am Ende.

## Wie der Prozess abläuft

c2pa-signer ist im Sinne des C2PA-Conformance-Programms ein **Generator Product**
(erzeugt Content Credentials), Implementierungsklasse **Edge** (läuft lokal auf
dem Rechner des Nutzers, kein Backend).

1. **Expression of Interest** beim C2PA-Conformance-Programm einreichen (Formular auf der Programmseite).
2. **Antrag**: rechtliche Vereinbarung mit C2PA unterschreiben, Nachweise einreichen
   (Architekturdiagramme, Dokumentation), Rückfragen der Programmverantwortlichen klären.
3. **Funktionale Konformität** (Abschnitt 6.1.1 des Programmdokuments): Manifeste müssen
   spezifikationskonform sein, Assertions im aktiven Manifest stehen, und der Claim muss mit
   einem X.509-Zertifikat signiert sein, das auf die **C2PA Trust List** zurückführt.
4. **Sicherheitsanforderungen**: Security-Architecture-Dokument nach Vorlage (Anhang C der
   *Generator Product Security Requirements*) ausfüllen: Organisation, Produkt, Schlüsselerzeugung
   und -speicherung, Schutz gegen Fehlkonfiguration und Missbrauch.
5. **Assurance Level**: C2PA legt ein maximales Level (1 oder 2) fest. Das Level steht später als
   eigene X.509-Erweiterung im Signierzertifikat.
6. **Zertifikat** bei einer CA beziehen, die auf der C2PA Trust List steht und nach der
   C2PA Certificate Policy ausstellt.
7. **Listung**: bei Annahme Eintrag in die Conforming-Products-Liste (JSON im öffentlichen
   GitHub-Repo `c2pa-org/conformance-public`), sichtbar im Conformance Explorer.

Gebühren und Bearbeitungsdauer nennen die öffentlichen Seiten nicht; das klärt sich erst im Antrag.
Die alte Interim Trust List ist seit 1.1.2026 eingefroren, neue Produkte brauchen ein Zertifikat
unter der offiziellen C2PA Trust List.

## Was das für uns bedeutet

### Zertifikate

* **Entwicklung**: selbst erzeugte Test-PKI (`c2pa-signer testcert`). Signaturen sind gültig,
  aber "nicht vertrauenswürdig", solange die Test-Root nicht als Trust Anchor angegeben ist.
* **Produktion**: Signierzertifikat einer CA von der C2PA Trust List. Der Zertifikatsantrag
  setzt voraus, dass das Produkt im Conformance-Programm ist (Assurance Level im Zertifikat).
* Das Testzertifikat folgt bereits dem C2PA-Zertifikatsprofil (EKU `c2pa-kp-claimSigning`,
  `digitalSignature`, kein CA-Zertifikat), damit der spätere Wechsel nur Dateien tauscht.

### Assurance Level 1 (realistisches erstes Ziel für ein Desktop-CLI)

| Anforderung | Umsetzung |
|---|---|
| Schlüssel verschlüsselt gespeichert | erledigt: Schlüssel liegt nur im Schlüsselspeicher des Betriebssystems |
| Schlüssel im Speicher nur zum Signieren entschlüsselt, oder Key-Management-Komponente (Linux Keyring, macOS Keychain) | umgesetzt: `c2pa-keystore` + `--keystore` (Windows Credential Manager, macOS Keychain, Linux Secret Service) |
| Least Privilege, zeitlich begrenzter Zugriff auf den Schlüssel | offen: im Security-Dokument beschreiben, ggf. über OS-Keystore lösen |
| Schlüsselrotation unterstützen | möglich: Schlüssel/Zertifikat sind Parameter; Prozess dokumentieren |
| SCA/SBOM-Scan gegen NVD, CRITICAL/HIGH in 90 Tagen beheben, Release-Pipeline blockiert | teilweise: `pip-audit` in CI; SBOM-Erzeugung und Release-Gate fehlen noch |
| Keine Zugangsdaten im Binary (bei automatischer Zertifikatsanforderung) | erfüllt, es gibt keine eingebauten Geheimnisse |

### Assurance Level 2

Verlangt Schlüssel in einer höher privilegierten Umgebung mit hardwaregestützter Attestierung
(Secure Enclave, TPM/Microsoft Platform Crypto Provider, KMS/HSM) sowie Nachweise zur
Binary-Integrität. Für ein plattformübergreifendes Python-CLI ist das deutlich aufwendiger;
Empfehlung: zuerst Level 1, Level 2 später über ein KMS/HSM-Backend (PKCS#11) prüfen.

### Weitere Punkte fürs Design

* **Zeitstempel**: nicht vorgeschrieben, aber empfohlen, damit Signaturen nach Ablauf des
  Zertifikats gültig bleiben. `--tsa-url` ist vorhanden; produktiv einen TSA von der C2PA TSA
  Trust List nutzen.
* **Eintrag in der Liste**: Jeder Eintrag der Conforming Products List nennt Produkt, Rolle
  (Generator), Assurance Level, die geprüfte Spezifikationsversion und die abgedeckten
  Medientypen. Für uns also: Generator, Level 1, Medientyp `image/jpeg`. Die Spezifikations-
  version ergibt sich aus dem gepinnten SDK; vor dem Antrag festhalten, welche Version es
  umsetzt (aktuell gelistete Produkte nennen z. B. C2PA 2.2).
* **Widerruf**: Validatoren prüfen per OCSP bzw. Sperrlisten, ob das Signierzertifikat
  widerrufen ist. Ein widerrufenes oder zum Signierzeitpunkt abgelaufenes Zertifikat lässt die
  Prüfung scheitern. Der Rotationsprozess im Security-Dokument muss das abdecken.
* **Spezifikationskonformität** sichert die offizielle Bibliothek `c2pa-python`/`c2pa-rs`
  ab; Version ist gepinnt, Updates bewusst einspielen.
* **Verteilung**: für Level 2 und vertrauenswürdige Releases sind signierte Binärpakete
  (z. B. PyInstaller + Code-Signing je Plattform) sinnvoll.

## Nächste Schritte

1. Expression of Interest einreichen, um Fristen, Kosten und aktuelle Programmversion zu erfahren.
2. ~~Backend für OS-Schlüsselspeicher ergänzen~~ (erledigt). Prüfen, ob für Level 2 ein nicht exportierbarer Schlüssel (Secure Enclave, TPM über Microsoft Platform Crypto Provider) nötig ist.
3. SBOM (CycloneDX) und Release-Gate in der CI.
4. Security-Architecture-Dokument nach Anhang C entwerfen.
5. CA von der C2PA Trust List auswählen und Zertifikat beantragen.

## Quellen

* [C2PA conformance program](https://opensource.contentauthenticity.org/docs/conformance/)
* [Trust lists](https://opensource.contentauthenticity.org/docs/conformance/trust-lists/)
* [C2PA Generator Product Security Requirements v0.2](https://github.com/c2pa-org/conformance-public/blob/main/docs/v0.2/C2PA%20Generator%20Product%20Security%20Requirements.md)
* [C2PA FAQ](https://c2pa.org/faqs/)
* [Encypher-Glossar: Conformance Program](https://encypher.com/glossary#conformance-program) (Hinweis von Stefan)
* [Encypher Conformance Explorer](https://encypher.com/c2pa-standard/conformance)
