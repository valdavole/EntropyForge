# Threat model – EntropyForge 3.3

## Rozsah

Model pokrývá generování náhodných bajtů, jejich mapování na uživatelský
výstup a lokální HTML bridge. Neprohlašuje operační systém, prohlížeč ani
podkladový kryptografický modul za bezchybné.

## Aktiva

- nepředvídatelnost výstupních bajtů;
- rovnoměrnost mapování na čísla, možnosti a znaky;
- tajnost hesel a tokenů po vygenerování;
- integrita volby aktivního režimu;
- pravdivost zobrazeného FIPS a certifikačního stavu;
- integrita zdrojového kódu a distribučního balíčku.

## Hranice důvěry

1. podkladový modul Windows CNG;
2. Python proces nebo prohlížeč;
3. loopback HTTP hranice mezi HTML a bridge;
4. uživatelská relace, schránka a souborový systém;
5. volitelný síťový sběrač mimo generátor.

## Hrozby a opatření

| Hrozba | Dopad | Opatření 3.3 | Zbytkové riziko |
|---|---|---|---|
| Tiché selhání Windows RNG | Předvídatelný výstup | Kontrola návratových kódů, 64B repetition check, trvalý error state | Sofistikovaná chyba bez opakování nemusí být zjištěna |
| Tichý fallback | Uživatel věří jinému zdroji | Přísný profil nikdy nepřechází na `os.urandom` ani Web Crypto | Chybná budoucí úprava; kryto regresním testem |
| Vypnutá FIPS zásada | Neodpovídající režim | Povinné `BCryptGetFipsAlgorithmMode` před generováním | Zásada sama nedokazuje úplnou shodu s certifikátem |
| Neodpovídající verze Windows | Neplatné tvrzení | Úzký manifest a stav `unmatched` | Manifest je offline a neověřuje hardware ani aktuální webový stav |
| Cross-origin zneužití bridge | Cizí web odebírá bajty | Loopback bind, Host/Origin, SameSite cookie, bez CORS, same-origin CSP | Kompromitovaný lokální proces nebo rozšíření prohlížeče |
| DNS rebinding | Přístup k lokálnímu API | Povolen pouze Host `127.0.0.1`/`localhost` s aktuálním portem | Útok v kompromitovaném prohlížeči |
| Malformovaný JSON/DoS | Pád nebo paměťové vyčerpání | Přesná pole, typy, limity a Content-Length | Lokální oprávněný uživatel může stále zatěžovat proces |
| Modulo bias | Nerovnoměrný výběr | Rejection sampling | Implementační regrese; jednotkové testy |
| Zkreslený unikátní výběr | Nerovnoměrné losování | Částečný Fisherův–Yates | Chybná budoucí změna |
| Vyzrazení hesla/tokenů | Ztráta tajemství | Žádná telemetrie, žádný access log, lokální zpracování | Schránka, RAM, swap, malware, screenshot a uložený TXT |
| Podvržený externí zdroj | Falešná „entropie“ | Externí zdroj nikdy nenahrazuje OS CSPRNG; v přísném profilu je vyřazen | Metadata .efb nejsou nezávisle podepsaná autoritou |
| Veřejný beacon považovaný za tajný | Falešná bezpečnostní představa | UI a dokumentace nepřidělují tajnou entropii | Uživatel může varování ignorovat |
| Změněný balíček | Spuštění podvrženého kódu | SHA256SUMS, CSP hash, testy | Kontrolní součet ze stejného archivu není autentický podpis |
| Falešné certifikační tvrzení | Právní a bezpečnostní riziko | Výslovné claim limits, report, manifest a dokumentace | Distributor může text úmyslně změnit |

## Záměrně neřešené scénáře

- plně kompromitovaný kernel nebo administrátor;
- hardwarový trojan;
- útoky postranními kanály na obecný Python/prohlížeč;
- bezpečné nulování immutable řetězců;
- fyzické zabezpečení počítače;
- ochrana uživatelem exportovaných souborů;
- dostupnost vzdálených beaconů.

## Bezpečnostní invarianty

1. Každý přísný výstup pochází pouze z jednoho úspěšného CNG požadavku.
2. Přísná cesta neobsahuje custom mixer ani externí data.
3. Chyba přísné cesty vrací chybu, nikoli náhradní náhodná data.
4. Generování omezených hodnot nepoužívá modulo.
5. Bridge nepřijímá cross-origin výstupní požadavky.
6. Certifikační evidence nikdy nemění samotné bajty ani nezvyšuje
   deklarovaný počet bitů entropie.
