# První publikace EntropyForge na GitHubu

Repozitář obsahuje zdrojové soubory rozbalené. Distribuční ZIP se
necommituje; patří jako volitelná příloha ke GitHub Release.

## 1. Založení repozitáře

Na GitHubu zvol:

1. **New repository**
2. název `EntropyForge`
3. viditelnost **Public**
4. nepřidávej README, `.gitignore` ani licenci – všechny jsou již
   připravené
5. potvrď **Create repository**

Doporučený popis:

> Cross-platform cryptographically secure RNG with bilingual Python and HTML interfaces, multi-source entropy mixing, diagnostics, and strict Windows CNG mode.

Doporučená témata:

```text
random-number-generator
cryptography
csprng
python
html
web-crypto
windows-cng
security
```

## 2. Nahrání přes Git

Rozbal `EntropyForge_3.3_GitHub_Repo.zip`. V terminálu otevřeném v
rozbalené složce spusť:

```bash
git init
git branch -M main
git add .
git commit -m "Release EntropyForge 3.3"
git remote add origin https://github.com/TVUJ_UCET/EntropyForge.git
git push -u origin main
```

`TVUJ_UCET` nahraď svým GitHub uživatelským jménem.

Před `git commit` lze příkazem `git status` zkontrolovat, že se
nenahrává `.env`, `.efb`, cache nebo ZIP.

## 3. GitHub Desktop

Alternativně lze rozbalenou složku přidat do GitHub Desktop:

1. **File → Add local repository**
2. vyber rozbalenou složku
3. pokud ještě není repozitář, zvol vytvoření repozitáře v této složce
4. vytvoř první commit
5. zvol **Publish repository**
6. zkontroluj, že název je `EntropyForge` a viditelnost odpovídá záměru

## 4. Kontrola po nahrání

V záložce **Actions** musí proběhnout:

- `Tests` na Windows a Linuxu,
- `CodeQL` pro Python a JavaScript.

První běh může trvat několik minut. Červený stav neignoruj před
vytvořením Release.

V **Settings → Security** doporučujeme zapnout:

- Private vulnerability reporting,
- Dependabot alerts,
- Secret scanning, pokud je pro účet dostupný.

Pro větev `main` lze později zapnout pravidlo vyžadující úspěšné
workflow `Tests` před sloučením pull requestu.

## 5. Vytvoření verze

Po zelených testech:

1. otevři **Releases**
2. zvol **Draft a new release**
3. vytvoř tag `v3.3.0` z větve `main`
4. název nastav na `EntropyForge 3.3`
5. vlož obsah `docs/RELEASE_NOTES_3.3.md`
6. přilož `EntropyForge_3.3_Release.zip`
7. přilož také odpovídající `.sha256` soubor
8. zvol **Publish release**

GitHub automaticky nabídne také `Source code (zip)` a
`Source code (tar.gz)`. Vlastní Release ZIP je vhodný pro běžné
uživatele, protože neobsahuje vývojové šablony a workflow.

## 6. Další úpravy

Před každým commitem změny HTML skriptu:

```bash
python tools/update_html_csp.py
python tests/run_all.py
```

Nová verze by měla aktualizovat:

- `APP_VERSION` v Pythonu a HTML,
- doménový prefix, pokud se mění kryptografická konstrukce,
- známé testovací vektory,
- `CHANGELOG.txt`,
- uživatelskou a bezpečnostní dokumentaci,
- release tag a poznámky.

## Licence

Připravená MIT licence umožňuje použití, úpravy a distribuci při
zachování autorského a licenčního upozornění. Pokud chceš místo toho
zakázat další šíření nebo vyžadovat zveřejnění odvozených úprav, změň
licenci ještě před prvním veřejným zveřejněním.
