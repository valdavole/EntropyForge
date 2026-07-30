## Co se mění

Stručný popis změny a důvodu.

## Bezpečnostní dopad

- [ ] Nemění kryptografickou konstrukci ani zdroje důvěry.
- [ ] Pokud je mění, změna je vysvětlená a otestovaná.
- [ ] Přísný profil zůstává fail-closed.
- [ ] Python a HTML zůstávají funkčně shodné.
- [ ] Nejsou přidané API klíče, citlivá data ani generované výstupy.

## Ověření

- [ ] `python tools/update_html_csp.py --check`
- [ ] `python tests/run_all.py`
- [ ] Dokumentace a changelog jsou aktuální.
