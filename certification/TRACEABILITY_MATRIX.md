# Předběžná trasovatelnost k FIPS 140-3 Level 1

Tato matice je interní pracovní pomůcka. Konečné požadavky a důkazy určí
NVLAP akreditovaná laboratoř podle aktuální Implementation Guidance.

| Oblast | Stav 3.3 | Existující důkaz | Chybějící krok |
|---|---|---|---|
| 1. General | Částečně | Název, verze, cílová úroveň a omezení tvrzení | Právní vendor, schválený submission scope |
| 2. Cryptographic module specification | Částečně | Přímá CNG cesta a předběžná hranice | Laboratorní rozhodnutí, zda jde o integraci nebo vlastní modul |
| 3. Cryptographic module interfaces | Připraveno k revizi | Parametry API, status a loopback endpointy | Formální mapování portů a rozhraní |
| 4. Roles, services, authentication | Částečně | User/Crypto Officer a tabulka služeb | Laboratorní potvrzení role modelu |
| 5. Software/firmware security | Částečně | CSP hash, SHA256SUMS, kontrola návratů | Authenticode, reproducibilní build, integrity evidence |
| 6. Operational environment | Blokováno externě | Kontrola OS, architektury, FIPS zásady a manifestu | Zmrazit přesný OS/build/hardware a potvrdit Security Policy |
| 7. Physical security | Očekáváno N/A | Softwarový profil | Potvrzení laboratoří |
| 8. Non-invasive security | Očekáváno N/A | Bez deklarované mitigace | Potvrzení laboratoří |
| 9. SSP management | Částečně | Žádný vlastní seed/DRBG state, žádné ukládání | Posouzení výstupu mimo hranici a nulování |
| 10. Self-tests | Částečně | Delegace modulu, return codes, repetition check, error state | Důkaz self-testů podkladového modulu a jejich indikace |
| 11. Life-cycle assurance | Nedokončeno | Verzovaný zdroj, testy, dokumentace | Řízený repozitář, SBOM, build records, signing, vuln process |
| 12. Mitigation of other attacks | Částečně | Loopback web controls, žádné zvláštní claimy | Laboratorní vyhodnocení |
| Approved algorithms / CAVP | Externí závislost | CNG volání, veřejné podklady #4825 | Aktuální FIPS 140-3 certifikát a přesné CAVP algoritmy |
| Entropy / SP 800-90B | Externí závislost | Entropii poskytuje podkladový modul | Potvrdit ENT(P)/ESV rozsah přesné verze modulu |
| RBG / SP 800-90C | Externí závislost | Žádný vlastní RBG claim | Rozhodnutí laboratoře, zda a jak se 90C vztahuje |
| ACVP testování | Není v rozsahu aplikace | Aplikace neimplementuje vlastní DRBG | Pokud vznikne vlastní modul, vytvořit ACVP rozhraní |
| Nezávislá laboratoř | Nezahájeno | Seznam zdrojů a checklist | Vybrat laboratoř, smlouva, testování a podání |
| Certifikát | Neexistuje | Výslovně uvedeno ve všech materiálech | Vydání CMVP po úspěšném podání |

## Mapování invariantů na automatické testy

| Invariant | Test |
|---|---|
| Přísná cesta nepoužije `os.urandom` | `test_validated_mode_uses_only_strict_backend` |
| Nedostupný profil se nevrátí na jiný režim | `test_unavailable_validated_mode_never_falls_back` |
| Vypnutá FIPS zásada negeneruje | `test_fips_policy_off_fails_without_generating` |
| Selhání CNG je trvalý error state | `test_provider_failure_is_sticky_and_fail_closed` |
| HTML bridge failure nepoužije Web Crypto | HTML `simulated strict failure` regression |
| Cross-origin request je odmítnut před generováním | `test_cross_origin_request_is_rejected_before_generation` |
| Bridge vrací přesnou délku | `test_random_endpoint_is_same_origin_and_exact_length` |
| Omezená čísla nepoužívají modulo | `randbelow` coverage/range tests + source inspection |
| Python/HTML mají shodný custom HMAC profil | sdílený known-answer test |
| CSP odpovídá inline skriptu | `test_html_csp_hash_matches_inline_script` |
