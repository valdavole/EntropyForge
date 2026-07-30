# EntropyForge 3.3 – certifikační připravenost

Stav k 30. červenci 2026: **připraveno pro předběžný odborný audit, nikoli certifikováno**.

## Zvolená cesta

Nejpravděpodobnější dosažitelná varianta v podmínkách samostatného
studentského projektu je:

1. zachovat všechny dosavadní experimentální a vícezdrojové režimy;
2. pro regulované použití aktivovat pouze oddělený přísný profil;
3. v něm přímo volat systémově preferovaný RNG Windows CNG;
4. nevkládat do této cesty vlastní DRBG, HMAC směšování, časování ani
   vzdálené zdroje;
5. vztahovat každé případné tvrzení pouze k přesně podporované verzi
   podkladového kryptografického modulu;
6. nechat výslednou konfiguraci a dokumentaci posoudit akreditovanou
   laboratoří.

Tato cesta je levnější, kratší a auditovatelnější než pokus certifikovat
celou Python nebo HTML aplikaci jako nový kryptografický modul.

## Co verze 3.3 už technicky řeší

- přímé `BCryptGenRandom(NULL, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)`;
- ověření systémového FIPS režimu přes `BCryptGetFipsAlgorithmMode`;
- fail-closed chování bez tichého návratu na jiný RNG;
- průběžnou kontrolu opakování 64bajtového bloku;
- oddělenou výstupní cestu bez vlastního post-processingu;
- shodný backend pro Python a HTML přes loopback-only same-origin bridge;
- omezené API, přesnou validaci JSON, Host/Origin kontrolu, HttpOnly
  SameSite relaci, zákaz CORS a zákaz logování výstupů;
- technický report se stavem FIPS zásady a certifikačních podkladů;
- strojově čitelný manifest, model hrozeb, návrh Security Policy,
  trasovatelnost a laboratorní checklist;
- regresní test, že selhání přísného zdroje nikdy nepoužije Web Crypto
  ani `os.urandom`.

## Co nelze dokončit pouze zdrojovým kódem

- vydání certifikátu CMVP, EUCC nebo Common Criteria;
- potvrzení konkrétního hardwaru a operačního prostředí;
- právní identitu vendora a odpovědnou osobu;
- smlouvu, rozpočet a testování akreditovanou laboratoří;
- produkční ACVP/ESV/CMVP podání;
- schválení Security Policy;
- oprávnění používat validační logo nebo slovo „certifikovaný“.

## Aktuální překážka cíle FIPS 140-3

Přiložený offline záznam dokáže předběžně spárovat Windows 11 build
`10.0.22000` s Microsoft Cryptographic Primitives Library, CMVP
certifikát `#4825`. Jde však o **FIPS 140-2** certifikát se sunset datem
21. září 2026.

Microsoft moduly pro Windows 11 23H2/24H2 byly 30. července 2026 v
procesu validace FIPS 140-3, nikoli v seznamu dokončených certifikátů.
EntropyForge proto jejich stav nesmí vydávat za hotovou validaci.

Nejrozumnější pokračování je:

- používat přísný profil jako technicky bezpečnou, fail-closed integraci;
- před jakýmkoli formálním nasazením aktualizovat manifest podle nového
  dokončeného certifikátu a jeho Security Policy;
- nechat konfiguraci potvrdit laboratoří.

## Povolené a zakázané formulace

Povolené nyní:

> EntropyForge 3.3 je kryptograficky bezpečně navržený generátor.

> Přísný profil volá přímo Windows CNG a bez splněných podmínek selže.

Povolené až po ověření přesné konfigurace:

> Přísný profil používá podkladový kryptografický modul validovaný pod
> certifikátem [číslo] v konfiguraci definované jeho Security Policy.

Zakázané bez samostatně vydaného certifikátu:

> EntropyForge je FIPS/NIST certifikovaný.

> EntropyForge je schválený podle SP 800-90B/90C.

> EntropyForge je certifikovaný hardwarový nebo fyzický RNG.

## Obsah adresáře

- `SECURITY_POLICY_DRAFT.md` – pracovní návrh bezpečnostní politiky;
- `THREAT_MODEL.md` – aktiva, hranice důvěry a zbytková rizika;
- `FINITE_STATE_MODEL.md` – stavy, přechody a fail-closed invarianty;
- `TRACEABILITY_MATRIX.md` – stav požadavků FIPS 140-3 Level 1;
- `LAB_SUBMISSION_CHECKLIST.md` – konkrétní externí kroky;
- `validation_manifest.json` – strojově čitelný stav podkladů;
- `SOURCES.md` – primární veřejné zdroje.
