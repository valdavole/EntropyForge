# Přispívání do EntropyForge

Děkujeme za zájem o projekt. U kryptografického softwaru je důležitější
správnost, auditovatelnost a poctivě omezená tvrzení než množství funkcí.

## Než začneš

- Pro bezpečnostní problém použij soukromý postup v `SECURITY.md`.
- Pro běžnou chybu nebo návrh založ odpovídající GitHub issue.
- Velkou změnu kryptografické konstrukce nejdřív popiš v issue.
- Do issue, commitu ani testu nevkládej API klíče nebo skutečná citlivá
  náhodná data.

## Vývojové prostředí

Projekt potřebuje Python 3.10+ a pro HTML testy Node.js 24. Nemá
runtime závislosti třetích stran.

```bash
python tests/run_all.py
```

Volitelná statistická kampaň:

```bash
python tests/statistical_campaign.py
```

## Změny HTML

JavaScript v `EntropyForge.html` je uzamčen CSP hashem. Po každé změně
obsahu `<script>` spusť:

```bash
python tools/update_html_csp.py
python tools/update_html_csp.py --check
```

Pouhé odstranění CSP nebo přidání `unsafe-inline` není přijatelné.

## Bezpečnostní pravidla změn

- Systémový CSPRNG musí zůstat základem všech běžných režimů.
- Přísný profil nesmí přejít na náhradní generátor.
- Omezené intervaly nesmí používat modulo.
- Uživatelská či vzdálená data se nesmí vydávat za ověřenou entropii
  bez odpovídajícího modelu a validace.
- Python a HTML mají zůstat funkčně shodné.
- Nové kryptografické domény nebo změny formátu musí dostat známý
  testovací vektor a regresní test.
- Certifikace podkladového modulu nesmí být popsána jako certifikace
  EntropyForge.

## Pull request

Pull request by měl:

1. popsat problém a řešení,
2. uvést bezpečnostní dopad,
3. přidat nebo aktualizovat testy,
4. aktualizovat dokumentaci,
5. projít workflow `Tests` a `CodeQL`,
6. neobsahovat generované soubory, cache ani tajné údaje.

Odesláním příspěvku souhlasíš s jeho zveřejněním pod licencí MIT
tohoto repozitáře.
