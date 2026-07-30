# EntropyForge 3.3

[Čeština](README.md) | [English](README.en.md)

Lokální generátor kryptograficky bezpečných čísel, losování, hesel,
tokenů a UUID s funkčně shodným rozhraním v Pythonu a HTML.

Obě rozhraní lze za běhu kompletně přepnout mezi češtinou a angličtinou.
Volba jazyka se ukládá pouze lokálně a nemění kryptografickou konstrukci
ani právě zadaná či vygenerovaná data.

EntropyForge staví běžné režimy na CSPRNG operačního systému nebo
prohlížeče. Volitelně přidává doménově oddělenou diverzifikaci, externí
zdroje a samostatný přísný profil Windows CNG.

> [!IMPORTANT]
> EntropyForge není certifikovaný FIPS, NIST, EUCC ani Common Criteria
> produkt. Přísný profil používá kryptografický modul Windows, ale
> certifikace podkladového modulu není certifikací této aplikace.

## Hlavní vlastnosti

- Python 3.10+ bez knihoven třetích stran.
- Samostatná HTML verze využívající Web Crypto.
- Kompletní české a anglické rozhraní včetně chyb, diagnostiky a reportů.
- Přímý přísný profil `BCryptGenRandom` ve Windows.
- Fail-closed chování bez tichého přechodu na náhradní zdroj.
- Rovnoměrné mapování čísel pomocí rejection samplingu.
- Unikátní výběry pomocí částečného Fisherova–Yatesova algoritmu.
- Hesla, Hex/Base64 URL tokeny a UUID v4.
- Až osm lokálních souborů nebo balíčků `.efb`.
- Samostatný sběrač pro drand, NIST Beacon a volitelný RANDOM.ORG
  Signed API.
- Shodné známé testovací vektory Pythonu a HTML.
- Automatické testy pro Linux a Windows a bezpečnostní analýza CodeQL.

## Rychlé spuštění

### Python ve Windows

1. Nainstaluj Python 3.10 nebo novější.
2. Stáhni a rozbal poslední balíček z GitHub Releases.
3. Spusť `run_windows.bat`.

Alternativně:

```powershell
py -3 entropy_forge.py
```

### Samostatné HTML

Otevři `EntropyForge.html` v moderním prohlížeči. Samostatná varianta je
offline a používá `crypto.getRandomValues()`. Přísný Windows CNG profil
v ní není dostupný.

### HTML s přísným Windows CNG profilem

```text
run_validated_html.bat
```

Skript spustí loopback server na náhodném portu `127.0.0.1`. Bridge
kontroluje Host, Origin a relační cookie, neposkytuje CORS a neloguje
generované hodnoty.

Připravenost profilu lze ověřit bez generování:

```text
check_validated_profile.bat
```

Živý test skutečného Windows CNG:

```text
run_windows_cng_live_test.bat
```

## Režimy

| Režim | Výstupní základ | Doplňkové vstupy |
| --- | --- | --- |
| Přísný Windows CNG | `BCryptGenRandom` | žádné; vlastní směšovač je vyřazen |
| Systémový CSPRNG | `os.urandom()` / Web Crypto | žádné |
| Diverzifikovaný software | systémový CSPRNG | HMAC-SHA-512 a časování událostí |
| Vícezdrojový | systémový CSPRNG | HMAC, časování a až osm externích zdrojů |

Časování myši a klávesnice je v diverzifikovaných režimech aktivně
použito jako bonusová diverzifikace. Není mu přidělen konkrétní počet
bitů min-entropie a bezpečnost na něm nezávisí.

## Požadavky

- Python 3.10 nebo novější.
- Tkinter pro Python GUI.
- Moderní prohlížeč s Web Crypto pro HTML.
- Node.js 24 pouze pro vývojové HTML testy.
- Windows pro přímý CNG profil.

Projekt při běžném spuštění nepotřebuje žádné balíčky z PyPI ani npm.

## Testy

Ve Windows:

```text
run_tests.bat
```

Na libovolné podporované platformě:

```bash
python tests/run_all.py
```

Sada obsahuje unit, integrační, známé odpovědi, simulaci HTML rozhraní,
kontrolu CSP, strict backend, loopback bridge, externí formáty a
vzdálené balíčky.

Rozšířená statistická kampaň:

```bash
python tests/statistical_campaign.py
```

Statistické testy jsou diagnostika implementace, nikoli důkaz
nepředvídatelnosti nebo certifikace entropického zdroje.

## Úpravy HTML

Vložený JavaScript je uzamčen SHA-256 hodnotou v Content Security
Policy. Po každé změně obsahu `<script>` spusť:

```bash
python tools/update_html_csp.py
python tools/update_html_csp.py --check
```

Bez aktualizace hashe prohlížeč z bezpečnostních důvodů zablokuje celý
skript.

## Struktura repozitáře

| Cesta | Účel |
| --- | --- |
| `entropy_forge.py` | Python GUI a generátor |
| `EntropyForge.html` | samostatná HTML varianta |
| `validated_backend.py` | přímé Windows CNG API a FIPS kontrola |
| `validated_bridge.py` | zabezpečený loopback bridge pro HTML |
| `entropy_bundle.py` | parser a validace formátu `.efb` |
| `remote_entropy_collector.py` | oddělený síťový sběrač |
| `tests/` | automatické a statistické testy |
| `certification/` | pracovní podklady pro audit a laboratoř |
| `tools/` | vývojové a údržbové nástroje |
| `.github/` | CI, CodeQL, Dependabot a šablony |

Podrobný uživatelský návod je v `README.txt`, bezpečnostní konstrukce v
`SECURITY_MODEL.txt` a zaznamenaná validační kampaň v
`TEST_REPORT.txt`.

## Co do repozitáře nepatří

- API klíče, `.env` soubory a přihlašovací údaje.
- Vygenerované `.efb`, `.bin`, reporty a náhodné výstupy.
- `__pycache__`, virtuální prostředí a editorové soubory.
- Distribuční ZIPy; ty patří mezi aktiva GitHub Release.

## Publikace

Kompletní návod pro první nahrání, doporučená nastavení repozitáře a
vytvoření verze `v3.3.0` je v
[`docs/GITHUB_PUBLISHING.md`](docs/GITHUB_PUBLISHING.md).

GitHub sám nabízí zdrojový archiv každého tagu. Uživatelský distribuční
ZIP lze připojit zvlášť k Release.

## Bezpečnost

Zranitelnosti neposílej do veřejného issue. Postup je uveden v
[`SECURITY.md`](SECURITY.md). Přesný threat model a omezení jsou v
`SECURITY_MODEL.txt`.

## Přispívání

Pull requesty jsou vítané. Před odesláním si přečti
[`CONTRIBUTING.md`](CONTRIBUTING.md) a spusť kompletní testovací sadu.
Změny kryptografické konstrukce musí být doprovázeny testy, vysvětlením
bezpečnostního dopadu a aktualizací dokumentace.

## Citace

GitHub umí nabídnout citaci z přiloženého souboru `CITATION.cff`.

## Licence

Copyright © 2026 Filip Novák.

Projekt je zveřejněn pod licencí [MIT](LICENSE). Licence umožňuje
použití, úpravy a další šíření při zachování licenčního a autorského
upozornění.
