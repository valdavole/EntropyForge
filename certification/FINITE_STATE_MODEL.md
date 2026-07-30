# Finite-state model přísného profilu

## Stavy

| Stav | Výstup povolen | Popis |
|---|---:|---|
| `INITIALIZING` | Ne | Načítá se `bcrypt.dll` a vážou se požadovaná API |
| `UNAVAILABLE` | Ne | Nejde o Windows nebo požadované API není dostupné |
| `FIPS_DISABLED` | Ne | Windows vrací vypnutý FIPS režim |
| `READY` | Ano | API je dostupné a FIPS režim je potvrzen |
| `GENERATING` | Ne průběžně | Probíhá health probe a CNG požadavek |
| `ERROR` | Ne | CNG/health kontrola selhala; stav je pro instanci konečný |

## Přechody

| Z | Událost | Do | Akce |
|---|---|---|---|
| `INITIALIZING` | platforma/API chybí | `UNAVAILABLE` | Vrátit status bez výstupu |
| `INITIALIZING` | FIPS zásada vypnutá | `FIPS_DISABLED` | Vrátit status bez výstupu |
| `INITIALIZING` | API a FIPS v pořádku | `READY` | Povolit volbu profilu |
| `FIPS_DISABLED` | správce zapne zásadu a stav je znovu ověřen | `READY` | Povolit volbu profilu |
| `READY` | požadavek `n > 0` | `GENERATING` | Znovu ověřit FIPS, spustit probe |
| `GENERATING` | probe/CNG úspěch | `READY` | Vrátit přesně `n` bajtů |
| `GENERATING` | libovolná chyba | `ERROR` | Zahodit částečný výstup |
| `READY` | FIPS zásada vypnutá | `FIPS_DISABLED` | Odmítnout požadavek |
| `ERROR` | libovolný požadavek | `ERROR` | Odmítnout bez fallbacku |

## Invarianty

- Výstup vzniká pouze při úspěšném přechodu `GENERATING -> READY`.
- `ERROR`, `UNAVAILABLE` ani `FIPS_DISABLED` nemají cestu k výstupu.
- Z `ERROR` není v jedné instanci návrat; je nutné proces ukončit.
- Běžný režim může uživatel zvolit ručně jako samostatný režim, ale
  není automatickým přechodem z přísného profilu.
- Stav `evidence_state` pouze informuje o podkladech. Nemění CNG výstup
  ani sám nepovoluje certifikační tvrzení.
