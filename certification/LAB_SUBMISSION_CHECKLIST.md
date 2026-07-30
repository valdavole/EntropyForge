# Checklist pro skutečné laboratorní podání

## A. Rozhodnutí o rozsahu

- [ ] Určit právní subjekt vendora a kontaktní osobu.
- [ ] Rozhodnout, zda cílem je:
  - [ ] pouze doložené používání existujícího validovaného modulu; nebo
  - [ ] vlastní certifikát kryptografického modulu EntropyForge.
- [ ] Nechat laboratoř písemně potvrdit vhodnost integrační architektury.
- [ ] Zmrazit přesnou edici, build a aktualizační kanál Windows.
- [ ] Zmrazit podporovanou architekturu a procesorové třídy.
- [ ] Vybrat pouze aktivní FIPS 140-3 certifikát podkladového modulu.
- [ ] Prostudovat jeho kompletní Security Policy a závislé certifikáty.

## B. Produktový freeze

- [ ] Přidělit neměnnou verzi kandidáta.
- [ ] Vytvořit čistý, reprodukovatelný build.
- [ ] Zaznamenat kompilátor/interpreter, SDK a všechny závislosti.
- [ ] Vytvořit SBOM.
- [ ] Podepsat binární distribuci Authenticode.
- [ ] Archivovat zdroj, build logy, test logy a výsledné hashe.
- [ ] Zakázat automatické aktualizace uvnitř validační hranice.
- [ ] Definovat proces oprav, CVE a revalidace.

## C. Důkazy a dokumentace

- [ ] Dokončit Security Policy podle aktuálního SP 800-140B.
- [ ] Dokončit block diagram a kryptografickou hranici.
- [ ] Popsat všechny porty a logická rozhraní.
- [ ] Dokončit role, služby a indikátory schváleného režimu.
- [ ] Popsat SSP vstup, výstup, uložení a nulování.
- [ ] Doložit startup, conditional a on-demand self-testy.
- [ ] Doložit error states a inhibici výstupu.
- [ ] Popsat instalaci a všechny bezpečnostní konfigurace.
- [ ] Přiložit finite-state model.
- [ ] Přiložit trasovatelnost požadavek -> implementace -> test.
- [ ] Přiložit threat model a seznam zbytkových rizik.
- [ ] Přiložit uživatelský a administrátorský návod.

## D. Kryptografické a entropické podklady

- [ ] Potvrdit, že požadované RNG/DRBG je v rozsahu aktivního
  certifikátu podkladového modulu.
- [ ] Potvrdit odpovídající CAVP/ACVP certifikáty.
- [ ] Potvrdit ENT(P), SP 800-90B nebo SP 800-90C podklady podle
  aktuálního rozhodnutí laboratoře.
- [ ] Zakázat vlastní HMAC/external režimy v deklarovaném approved mode.
- [ ] Ověřit, že všechny výstupní požadavky kontrolují návratový stav.
- [ ] Ověřit, že žádný error path nevrací částečný nebo náhradní výstup.

## E. Testování

- [ ] Spustit automatické testy na každé deklarované konfiguraci.
- [ ] Přidat Windows-native integrační test na reálném cílovém buildu.
- [ ] Ověřit zapnutý i vypnutý FIPS stav.
- [ ] Ověřit chybové stavy pomocí řízeného test double nebo fault injection.
- [ ] Ověřit Host, Origin, cookie a CORS vlastnosti bridge.
- [ ] Spustit static analysis a dependency scan.
- [ ] Provést nezávislý code review.
- [ ] Provést penetrační test lokálního bridge.
- [ ] Uchovat protokoly bez citlivých náhodných výstupů.

## F. Externí proces

- [ ] Vybrat NVLAP akreditovanou Cryptographic and Security Testing Lab.
- [ ] Uzavřít smlouvu, NDA, rozpočet a harmonogram.
- [ ] Dodat vendor evidence.
- [ ] Vyřešit všechny komentáře laboratoře.
- [ ] Umožnit laboratoři provést produkční ACVP/ESV/CMVP podání.
- [ ] Uhradit laboratorní a NIST poplatky.
- [ ] Počkat na dokončené CMVP review a vydaný certifikát.
- [ ] Před zveřejněním zkontrolovat přesné povolené validační tvrzení.
- [ ] Nepoužít logo ani slovo „certifikovaný“ před vydáním certifikátu.

## G. Po vydání

- [ ] Publikovat přesné číslo certifikátu a podporované konfigurace.
- [ ] Přiložit schválenou Security Policy bez úprav.
- [ ] Oddělit approved a non-approved režimy v UI a dokumentaci.
- [ ] Sledovat sunset, revocation, CVE a změny Implementation Guidance.
- [ ] Každou změnu posoudit podle pravidel maintenance/revalidation.
- [ ] Po ztrátě platnosti okamžitě odstranit nebo upravit validační claim.
