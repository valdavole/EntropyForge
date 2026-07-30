ENTROPYFORGE 3.3
================

EntropyForge je lokální generátor čísel, losování, hesel, tokenů a UUID.
Balíček obsahuje funkčně shodnou Python a HTML verzi. Verze 3.3 zachovává
všechny režimy a přidává kompletní přepínání češtiny a angličtiny bez
změny kryptografické konstrukce nebo rozpracovaných výstupů.

DŮLEŽITÝ VERDIKT
----------------

- Běžné režimy jsou kryptograficky bezpečně navržené a stojí na CSPRNG
  operačního systému nebo prohlížeče.
- Přísný profil volá přímo Windows BCryptGenRandom a odmítne pracovat,
  pokud Windows nehlásí zapnutou systémovou FIPS zásadu.
- EntropyForge NENÍ FIPS, NIST, EUCC ani Common Criteria certifikovaný
  produkt. Certifikace podkladového modulu Windows není certifikací
  této aplikace.
- Přísný profil je technický krok k auditovatelnější integraci. Formální
  tvrzení stále vyžaduje přesnou podporovanou konfiguraci, Security
  Policy a posouzení nezávislou laboratoří.


1. NEJRYCHLEJŠÍ SPUŠTĚNÍ
------------------------

Python:

1. Nainstaluj Python 3.10 nebo novější.
2. Rozbal celý balíček.
3. Ve Windows spusť run_windows.bat.
4. Jazyk lze kdykoli změnit v pravé části záhlaví.

Samostatné HTML:

1. Otevři EntropyForge.html v moderním prohlížeči.
2. Tato varianta je zcela samostatná a nepovoluje vzdálená spojení.
3. Přísný Windows profil v ní není dostupný, protože prohlížeč nemůže
   přímo volat BCryptGenRandom ani ověřit FIPS stav Windows.
4. Jazyk lze kdykoli změnit v pravé části záhlaví.


2. PŘÍSNÝ WINDOWS CNG PROFIL
----------------------------

Profil přidává přímou cestu:

    EntropyForge -> BCryptGenRandom
                 -> BCRYPT_USE_SYSTEM_PREFERRED_RNG
                 -> kryptografický modul Windows CNG

Nevstupuje do ní vlastní HMAC směšovač, časování událostí, Web Crypto,
os.urandom ani externí .efb data. Pokud zdroj selže, není použit žádný
náhradní režim.

Kontrola připravenosti:

    check_validated_profile.bat

Živý test skutečného Windows CNG na cílovém počítači:

    run_windows_cng_live_test.bat

Použití v Python GUI:

1. Spusť run_windows.bat.
2. Otevři Zdroje a diagnostika.
3. Vyber Přísný Windows CNG profil.
4. Pokud podmínky nejsou splněny, volba zůstane nedostupná a aplikace
   zobrazí přesný důvod.

Použití v HTML:

1. Spusť run_validated_html.bat.
2. Skript otevře náhodný lokální port na 127.0.0.1 a prohlížeč.
3. HTML komunikuje pouze se stejným loopback originem.
4. Terminál s bridge ponech otevřený; ukončíš jej Ctrl+C.

Bezpečnost lokálního bridge:

- naslouchá výhradně na 127.0.0.1 a náhodném portu,
- kontroluje Host a u generování také Origin,
- používá HttpOnly SameSite=Strict relační cookie,
- neposkytuje CORS,
- přijímá pouze přesný JSON formát a omezené velikosti,
- neukládá požadavky ani výstupy do access logu,
- při chybě podkladového zdroje nevrací náhodná data.


3. ZAPNUTÍ SYSTÉMOVÉ FIPS ZÁSADY
--------------------------------

EntropyForge nastavení systému nikdy samo nemění. Zapnutí může ovlivnit
jiné aplikace, BitLocker, RDP nebo starší protokoly, proto rozhodnutí
patří správci zařízení.

Ve Windows Pro/Enterprise:

1. Otevři jako správce Místní zásady zabezpečení (secpol.msc).
2. Místní zásady -> Možnosti zabezpečení.
3. Zapni:
   System cryptography: Use FIPS compliant algorithms for encryption,
   hashing, and signing.
4. Znovu spusť kontrolu check_validated_profile.bat.

Microsoft uvádí, že nastavení platí pro Windows 10 i Windows 11 a změna
lokální zásady nevyžaduje restart. Doménová Group Policy může mít
přednost:

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing


4. REŽIMY GENERÁTORU
--------------------

Přísný Windows CNG profil
    Přímý BCryptGenRandom. Jedna výstupní vrstva, nejmenší vlastní
    kryptografická logika a fail-closed chování. Vyšší auditovatelnost
    neznamená „více náhodnosti“.

Systémový CSPRNG
    Python používá os.urandom(), HTML crypto.getRandomValues(). Je to
    nejjednodušší běžný režim bez vlastního post-processingu.

Diverzifikovaný software
    Zachovává čerstvý systémový CSPRNG a XORuje jej s doménově odděleným
    HMAC-SHA-512 proudem. Časování pouze diverzifikuje stav a nedostává
    odhad min-entropie.

Vícezdrojový režim
    Přidává až osm lokálních souborů nebo .efb balíčků. Systémový CSPRNG
    zůstává základem. Veřejné beacony nejsou tajná entropie.

Ukazatel 1/3, 2/3 a 3/3 vyjadřuje počet konstrukčních vrstev diverzity.
Není to známka, počet bitů entropie ani pořadí kryptografické bezpečnosti.
Přísný profil má 1/3, protože záměrně minimalizuje vlastní výstupní cestu.


5. EXTERNÍ ZDROJE A VZDÁLENÝ SBĚRAČ
------------------------------------

Do běžného vícezdrojového režimu lze importovat:

- surová binární data,
- hexadecimální text,
- Base64 nebo Base64 URL,
- desítkové bajty,
- textové bity,
- EntropyForge Remote Bundle (.efb).

remote_entropy_collector.py je samostatný síťový nástroj. Podporuje:

- drand quicknet se shodou nejméně dvou ze tří relayů,
- NIST Randomness Beacon 2.0 s opakovaným načtením přesného pulzu,
- volitelně RANDOM.ORG Signed API s vlastním API klíčem.

Ve Windows jej spustíš run_remote_collector.bat. Vygenerovaný .efb
potom ručně přidáš do Python nebo HTML generátoru. API klíč RANDOM.ORG
se do balíčku neukládá.


6. ROVNOMĚRNOST VÝSTUPŮ
-----------------------

- Omezená čísla používají rejection sampling, nikoli modulo.
- Unikátní čísla a možnosti používají částečný Fisherův-Yatesův výběr.
- Hesla se vybírají rovnoměrně z celé abecedy; nevyhovující kandidát se
  celý zahodí.
- UUID v4 mají správně nastavené bity verze a varianty.
- Python i HTML sdílejí limity a known-answer testy.


7. CERTIFIKAČNÍ STAV
--------------------

validated_backend.py má k datu 2026-07-30 úzký offline záznam veřejných
podkladů pro Microsoft Windows Cryptographic Primitives Library,
CMVP #4825. Záznam slouží pouze jako předběžná kontrola verze:

https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4825

Nedokazuje:

- že EntropyForge je certifikovaný,
- že libovolný počítač se stejným číslem sestavení je validovaná
  konfigurace,
- že je certifikát stále aktivní,
- že jsou dodržena všechna pravidla Security Policy,
- že současná verze Windows odpovídá testovanému prostředí.

Windows 11 23H2/24H2 FIPS 140-3 moduly byly při přípravě verze 3.3 v
procesu CMVP. Manifest se nesmí rozšířit, dokud nebude vydán dokončený
certifikát a zkontrolována jeho Security Policy.

Kompletní plán a podklady jsou v adresáři certification.


8. TESTY
--------

Ve Windows:

    run_tests.bat

Nebo:

    python tests/run_all.py

Sada kontroluje Python, HTML, strict backend, fail-closed chování,
same-origin bridge, CSP hash, formáty externích dat, vzdálené balíčky,
rovnoměrné mapování a regresi všech dosavadních funkcí.

Úspěšné statistické testy nejsou důkazem nepředvídatelnosti ani
certifikací. Jejich úkolem je odhalit hrubou chybu implementace.


9. SOUBORY
----------

entropy_forge.py
    Python GUI a generátor.

EntropyForge.html
    Samostatná HTML verze; přes lokální bridge zpřístupní i přísný
    Windows profil.

validated_backend.py
    Přímé fail-closed volání Windows CNG a kontrola FIPS zásady.

validated_bridge.py
    Loopback-only same-origin most pro HTML.

run_validated_html.bat
    Spuštění HTML přes lokální bridge.

check_validated_profile.bat
    Kontrola podmínek přísného profilu bez generování.

run_windows_cng_live_test.bat
    On-target 1MiB funkční a statistický smoke test skutečného CNG.

remote_entropy_collector.py
    Volitelný samostatný síťový sběrač .efb.

entropy_bundle.py
    Kanonický formát a validace .efb.

SECURITY_MODEL.txt
    Přesný bezpečnostní model a omezení.

certification/
    Návrh hranice, Security Policy draft, threat model, trasovatelnost a
    checklist pro nezávislou laboratoř.

TEST_REPORT.txt
    Konkrétní výsledky validační kampaně verze 3.3.

SHA256SUMS.txt
    SHA-256 kontrolní součty souborů; vytvářejí se pro distribuční ZIP
    a nejsou udržovány jako součást průběžné větve repozitáře.

tools/update_html_csp.py
    Bezpečně přepočítá CSP hash po změně vloženého JavaScriptu v HTML.

README.md, LICENSE, SECURITY.md, CONTRIBUTING.md a CITATION.cff
    Metadata, licence a pravidla potřebná pro veřejný GitHub repozitář.
