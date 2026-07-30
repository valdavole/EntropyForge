# EntropyForge Strict Integration Profile 3.3

## Pracovní návrh Security Policy

Tento dokument je návrh podkladů pro předběžnou konzultaci s laboratoří.
Nebyl schválen CMVP a není validačním certifikátem.

## 1. Obecné údaje

| Položka | Hodnota |
|---|---|
| Produkt | EntropyForge |
| Verze | 3.3 |
| Profil | `entropyforge.windows-cng.strict.v1` |
| Zamýšlená úroveň | FIPS 140-3 Level 1 |
| Typ | Softwarová aplikace integrující externí kryptografický modul |
| Stav | Nevalidováno |
| Vendor | Musí být právně určen před podáním |

## 2. Kryptografická hranice

Současná přísná cesta **nedefinuje EntropyForge jako nový kryptografický
modul**. Validovanou hranicí má být podkladový modul Microsoft Windows
Cryptographic Primitives Library, pokud přesná konfigurace odpovídá jeho
aktuálnímu CMVP certifikátu a Security Policy.

Mimo tuto hranici jsou:

- `entropy_forge.py` a jeho Tk GUI;
- `EntropyForge.html`;
- `validated_bridge.py`;
- mapování náhodných bajtů na čísla, možnosti, hesla, tokeny a UUID;
- schránka, souborový systém a uživatelské výstupy;
- vícezdrojový HMAC režim a vzdálený sběrač.

Pokud laboratoř rozhodne, že je požadován vlastní certifikát
EntropyForge, musí být vytvořen samostatný nativní modul s pevnou
binární hranicí. Python interpreter a obecný prohlížeč nemohou být bez
dalšího návrhu vydávány za tuto hranici.

## 3. Režimy

### Přísný integrační režim

Jediný kryptografický zdroj výstupních bajtů:

```text
BCryptGenRandom(
    hAlgorithm = NULL,
    pbBuffer = output,
    cbBuffer = requested_bytes,
    dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG
)
```

Před použitím musí `BCryptGetFipsAlgorithmMode` vrátit úspěch a
nenulovou hodnotu. Selhání je konečný stav aktuální instance profilu.

### Běžné režimy

Systémový, diverzifikovaný a vícezdrojový režim jsou mimo zamýšlený
schválený profil. Rozhraní je musí jasně odlišit a nesmí je automaticky
použít po selhání přísného profilu.

## 4. Rozhraní

| Logické rozhraní | Implementace |
|---|---|
| Data input | Požadovaný počet bajtů |
| Data output | Náhodné bajty vrácené Windows CNG |
| Control input | Volba přísného profilu; konfigurace FIPS zásady mimo aplikaci |
| Status output | Dostupnost API, FIPS stav, chyba, evidence manifestu |
| Power input | Poskytuje obecné výpočetní prostředí |

Bridge přijímá pouze:

- `GET /` – lokální HTML;
- `GET /api/v1/status` – stav po ověření relace;
- `POST /api/v1/random` – přesný JSON `{"bytes": n}`.

## 5. Role, služby a autentizace

### Role

- **User** – žádá náhodný výstup.
- **Crypto Officer / správce systému** – nastavuje podporované operační
  prostředí a systémovou FIPS zásadu.

Level 1 nevyužívá autentizaci rolí uvnitř aplikace. Loopback relační
cookie je ochrana webového rozhraní, nikoli FIPS autentizace role.

### Služby

| Služba | Režim | Výsledek |
|---|---|---|
| Query status | Přísný | Stav bez náhodného výstupu |
| Generate random bytes | Přísný | Bajty z Windows CNG |
| Generate number/choice/password/token | Aplikační | Deterministické mapování CNG bajtů |
| Diagnostics | Přísný | Smoke test, nikoli validace |
| Import external source | Běžný | Není povoleno v přísné výstupní cestě |

## 6. Softwarová bezpečnost

- Integritu podkladového modulu a jeho startup self-testy řeší Windows
  podle příslušné Security Policy.
- Distribuce EntropyForge obsahuje `SHA256SUMS.txt`; tyto neklíčované
  otisky detekují náhodné změny, ale nenahrazují podepsaný release.
- Produkční kandidát musí být podepsán Authenticode, reproducibilně
  sestaven a uložen v řízeném repozitáři.
- Přísná cesta nesmí umožnit dynamicky vložit jiného poskytovatele.

## 7. Operační prostředí

Současný kód kontroluje:

- platformu Windows;
- dostupnost `bcrypt.dll`;
- přítomnost obou požadovaných API;
- výsledek `BCryptGetFipsAlgorithmMode`;
- verzi Windows proti úzkému offline manifestu.

Laboratoř musí určit:

- přesnou edici a build Windows;
- podporované aktualizace;
- architekturu a procesorové třídy;
- požadovanou Group Policy;
- podmínky single-user/multi-user prostředí;
- podkladové moduly, certifikáty a jejich závislosti.

## 8. Fyzická a neinvazivní bezpečnost

Pro software Level 1 se očekává `N/A`, ale konečné určení provede
laboratoř podle aktuální Implementation Guidance.

## 9. Citlivé bezpečnostní parametry

Přísný profil:

- nepřijímá seed, klíč ani personalizační řetězec;
- neudržuje vlastní stav DRBG;
- neukládá náhodný výstup;
- vrací výstup volající aplikaci v plaintextu.

Aplikace nedokáže garantovat nulování výsledných Python řetězců,
JavaScript řetězců, schránky, swapu nebo uživatelem uložených souborů.
Výstup použitý jako heslo či klíč je po opuštění podkladového modulu
mimo jeho kryptografickou hranici.

## 10. Self-testy a chybové stavy

Podkladový modul odpovídá za FIPS startup a podmíněné self-testy.
EntropyForge navíc:

- kontroluje návratový stav každého CNG volání;
- před požadavkem generuje 64bajtový kontrolní blok;
- odmítne identický po sobě jdoucí kontrolní blok;
- po chybě nastaví instanci do trvalého chybového stavu;
- nevrátí částečný výstup;
- nepoužije náhradní RNG.

Kontrola opakování není náhradou za self-testy podkladového modulu ani
SP 800-90B health test.

## 11. Životní cyklus

Před podáním je nutné zavést:

- unikátní verzování zdrojů a binárních artefaktů;
- chráněnou hlavní větev a povinnou kontrolu změn;
- sledování požadavku až k testu;
- evidenci kompilátoru, SDK, závislostí a příkazů sestavení;
- podepisování release;
- SBOM;
- proces hlášení a oprav zranitelností;
- pravidla, které změny vyžadují opakovanou validaci.

## 12. Mitigace dalších útoků

Projekt si nyní nenárokuje specifické mitigace mimo standardní vlastnosti
operačního prostředí. Loopback bridge zmírňuje cross-origin zneužití,
ale nechrání proti kompromitovanému lokálnímu účtu, prohlížeči,
malwaru, debuggeru ani administrátorovi.

## 13. Povinné omezení tvrzení

Ani pozitivní stav v UI neopravňuje k formulaci „EntropyForge je
certifikovaný“. Maximální zamýšlené tvrzení po odborném potvrzení je:

> Přísný profil EntropyForge používá podkladový modul [název a
> certifikát] v konfiguraci určené jeho Security Policy.
