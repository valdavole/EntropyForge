# EntropyForge 3.3

Verze 3.3 zachovává kryptografickou konstrukci a všechny funkce verze
3.2 a přidává kompletní české a anglické rozhraní v Pythonu i HTML.

## Hlavní změny

- okamžitý přepínač `Čeština / English` v obou rozhraních,
- překlad všech karet, formulářů, nápověd, dynamických stavů, dialogů,
  validačních chyb, diagnostiky a technických reportů,
- zachování formulářů, externích zdrojů, výstupů a aktivního režimu při
  změně jazyka,
- lokální zapamatování jazyka bez telemetrie nebo síťové komunikace,
- překlad výchozích ukázkových možností pouze do chvíle, než je uživatel
  sám upraví,
- rozšířené automatické testy přepínání oběma směry a zachování výstupu,
- aktualizovaný CSP hash samostatné HTML verze.

## Kryptografická kompatibilita

Jazyková vrstva nevstupuje do seedování, HMAC směšování, externích
zdrojů ani generovaného výstupu. Doménový prefix konstrukce zůstává
`EntropyForge-3.2|`, takže známý HMAC-SHA-512 testovací vektor i
bezpečnostní model výstupní cesty zůstávají beze změny.

## Ověření

- 47 Python unit a integračních testů,
- HTML/Node integrační testy včetně přepnutí jazyků,
- společný známý HMAC-SHA-512 testovací vektor,
- kontrola CSP hashe,
- test fail-closed Windows CNG backendu a loopback bridge,
- kontrola certifikačních tvrzení a externích formátů.

## Bezpečnostní stav

EntropyForge je kryptograficky bezpečně navržený lokální nástroj, nikoli
samostatně certifikovaný FIPS, NIST, EUCC nebo Common Criteria produkt.
Certifikace podkladového modulu Windows se nesmí vydávat za certifikaci
této aplikace.

Podrobnosti jsou v `SECURITY_MODEL.txt`, `TEST_REPORT.txt` a adresáři
`certification/`.
