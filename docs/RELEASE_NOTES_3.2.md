# EntropyForge 3.2

Verze 3.2 zachovává všechny funkce předchozího generátoru a přidává
oddělený přísný profil Windows CNG, bezpečný lokální bridge pro HTML a
rozšířené auditní podklady.

## Hlavní změny

- přímá cesta přes `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)`,
- kontrola systémového FIPS režimu před použitím přísného profilu,
- fail-closed chování bez tichého fallbacku,
- stejný backend pro Python a HTML přes same-origin loopback bridge,
- zachované systémové, diverzifikované a vícezdrojové režimy,
- až osm externích souborů nebo `.efb` balíčků,
- samostatný sběrač drand, NIST Beacon a RANDOM.ORG Signed API,
- rozšířené testy backendu, bridge, CSP a certifikačních tvrzení,
- dokumentovaný threat model, stavový model a laboratorní checklist,
- přehlednější stav časování událostí a opravené rozložení režimových
  karet.

## Ověření

- 44 Python unit a integračních testů,
- HTML/Node integrační testy,
- společný známý HMAC-SHA-512 testovací vektor,
- kontrola CSP hashe,
- statistická diagnostická kampaň,
- kontrola čistě rozbaleného distribučního archivu.

## Bezpečnostní stav

EntropyForge je kryptograficky bezpečně navržený lokální nástroj, nikoli
samostatně certifikovaný FIPS, NIST, EUCC nebo Common Criteria produkt.
Certifikace podkladového modulu Windows se nesmí vydávat za certifikaci
této aplikace.

Podrobnosti jsou v `SECURITY_MODEL.txt`, `TEST_REPORT.txt` a adresáři
`certification/`.
