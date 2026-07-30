# Bezpečnostní zásady

## Podporované verze

| Verze | Bezpečnostní aktualizace |
| --- | --- |
| 3.3.x | ano |
| 3.2.x | ano |
| starší | ne |

## Hlášení zranitelnosti

Bezpečnostní problém nezveřejňuj v běžném GitHub issue.

Preferovaný postup:

1. otevři záložku **Security** repozitáře,
2. zvol **Advisories**,
3. vytvoř **New draft security advisory**.

Pokud soukromé hlášení není zapnuté, kontaktuj správce neveřejným
kanálem uvedeným na jeho GitHub profilu. Neposílej funkční exploity,
API klíče ani citlivé výstupy do veřejného komentáře.

Uveď:

- postiženou verzi a soubor,
- operační systém a rozhraní Python/HTML,
- přesný postup reprodukce,
- očekávaný a skutečný výsledek,
- možný dopad,
- návrh opravy, pokud jej máš.

## Rozsah

Za bezpečnostní problém se považuje například:

- předvídatelný nebo zkreslený výstup,
- tichý fallback přísného profilu,
- obejití same-origin ochrany bridge,
- únik API klíče nebo generovaných dat,
- parser přijímající nekanonický či poškozený `.efb`,
- rozpor mezi deklarovaným a skutečným zdrojem náhodnosti,
- zavádějící certifikační tvrzení.

Úspěšný statistický test sám o sobě nedokazuje bezpečnost a nezvyklá
jednotlivá náhodná hodnota sama o sobě není zranitelnost.

Projekt neposkytuje placený bug bounty program. Hlášení budou řešena
podle závažnosti a dostupnosti správce.

## Omezení tvrzení

EntropyForge není samostatně certifikovaný FIPS, NIST, EUCC ani Common
Criteria produkt. Podrobnosti jsou v `SECURITY_MODEL.txt` a v adresáři
`certification/`.
