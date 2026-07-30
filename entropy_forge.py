#!/usr/bin/env python3
"""
EntropyForge 3.3
Offline random number, choice, password and token generator.

Security model
--------------
- Primary source: operating-system CSPRNG via os.urandom().
- Optional supplementary sources: local event timing, imported RNG files and
  validated EntropyForge remote bundles.
- Supplementary mixing: domain-separated HMAC-SHA-512.
- Uniform bounded integers: rejection sampling, never modulo reduction.
- Optional strict Windows profile: direct BCryptGenRandom through the
  system-preferred CNG provider, with fail-closed FIPS-policy verification.

The operating-system CSPRNG is always the security foundation. Supplementary
sources never replace it. The strict profile bypasses EntropyForge's custom
mixing rather than claiming that it is FIPS validated. EntropyForge itself is
not a certified cryptographic module and has not undergone an independent
cryptographic audit.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import platform
import re
import struct
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Iterable, Protocol, Sequence, TypeVar

from entropy_bundle import BundleError, looks_like_bundle, parse_bundle
from validated_backend import StrictProfileError, WindowsCNGBackend

T = TypeVar("T")

APP_NAME = "EntropyForge"
# Version 3.3 adds a bilingual UI.  The cryptographic construction identifier
# intentionally remains at 3.2 because localization does not change the random
# construction or its known-answer vectors.
APP_VERSION = "3.3"
DOMAIN = b"EntropyForge-3.2|"

MIN_EXTERNAL_BYTES = 4_096
MAX_EXTERNAL_FILE_BYTES = 32 * 1024 * 1024
MAX_EXTERNAL_SOURCES = 8
MAX_OUTPUT_CHARACTERS = 8_000_000
MAX_INTEGER_DIGITS = 2_000
DIVERSITY_LEVELS = {"validated": 1, "system": 1, "hybrid": 2, "external": 3}

# Palette shared conceptually with the HTML edition.
BG = "#080d14"
PANEL = "#101925"
PANEL_2 = "#162233"
PANEL_DARK = "#07101a"
OUTPUT_BG = "#050a10"
TEXT = "#edf5ff"
MUTED = "#9db0c8"
LINE = "#293a50"
ACCENT = "#68d3ff"
ACCENT_2 = "#97f0c1"
WARN = "#ffd37a"
BAD = "#ff8d9a"

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"

LANGUAGE_NAMES = {"cs": "Čeština", "en": "English"}

# Czech is the canonical source language.  Exact matches are preferred; the
# same table is also used for composed status/error strings by replacing the
# longest matching fragments first.
EN_TRANSLATIONS = {
    "Připraveno": "Ready",
    "Hotovo": "Done",
    "Chyba": "Error",
    "Jazyk": "Language",
    "Čeština": "Czech",
    "Offline generátor s kryptografickým zdrojem systému, bezpečným vícezdrojovým vrstvením a odděleným přísným profilem Windows CNG. Žádná telemetrie, žádná síť v generátoru.": (
        "Offline generator with the operating system's cryptographic source, "
        "safe multi-source layering, and a separate strict Windows CNG profile. "
        "No telemetry and no network access in the generator."
    ),
    "bez modulo zkreslení": "no modulo bias",
    "offline generátor": "offline generator",
    "více externích zdrojů": "multiple external sources",
    "Bezpečnostní stav": "Security status",
    "Kryptograficky bezpečný • diverzifikovaný": "Cryptographically secure • diversified",
    "Kryptograficky bezpečný • přísný Windows profil": "Cryptographically secure • strict Windows profile",
    "Kryptograficky bezpečný • vícezdrojový": "Cryptographically secure • multi-source",
    "Kryptograficky bezpečný": "Cryptographically secure",
    "DIVERZIFIKOVANÝ": "DIVERSIFIED",
    "SYSTÉMOVÝ\nCSPRNG": "SYSTEM\nCSPRNG",
    "WINDOWS CNG\nPŘÍMÝ": "WINDOWS CNG\nDIRECT",
    "Dvě ze tří vrstev diverzifikace. Čerstvý systémový CSPRNG zůstává garantovaným základem.": (
        "Two of three diversification layers. A fresh system CSPRNG remains the guaranteed foundation."
    ),
    "Aktivní zdroj": "Active source",
    "Nemusíš nic nastavovat. Automatický režim vždy zachová čerstvý systémový CSPRNG a bezpečně přimíchá dostupné doplňkové zdroje. Přísný Windows profil je samostatný, nepoužívá vlastní směšovač a nikdy se nezaměňuje za certifikát celé aplikace.": (
        "No configuration is required. Automatic mode always retains a fresh "
        "system CSPRNG and safely mixes in available supplementary sources. "
        "The strict Windows profile is separate, does not use the custom mixer, "
        "and is never presented as a certificate for the application."
    ),
    "Čísla": "Numbers",
    "Losování": "Choices",
    "Hesla": "Passwords",
    "Zdroje a diagnostika": "Sources and diagnostics",
    "Jak to funguje": "How it works",
    "Kopírovat": "Copy",
    "Uložit TXT": "Save TXT",
    "Vymazat": "Clear",
    "Náhodná čísla": "Random numbers",
    "Minimum včetně": "Minimum, inclusive",
    "Maximum včetně": "Maximum, inclusive",
    "Počet čísel": "Number of values",
    "Počet": "Count",
    "Délka": "Length",
    "Bez opakování": "Without replacement",
    "Generovat": "Generate",
    "Podporuje celá čísla až do 2000 číslic; celkový výstup je bezpečně omezen.": (
        "Supports integers up to 2000 digits; total output is safely limited."
    ),
    "Losování možností": "Random choice",
    "Jedna možnost na řádek": "One option per line",
    "Kámen\nNůžky\nPapír": "Rock\nPaper\nScissors",
    "Počet výběrů": "Number of selections",
    "Losovat": "Draw",
    "V režimu bez opakování se shodné řádky sloučí. S opakováním mohou duplicity sloužit jako váhy.": (
        "In without-replacement mode, identical lines are merged. With "
        "replacement, duplicates can act as weights."
    ),
    "Silná hesla": "Strong passwords",
    "Délka hesla": "Password length",
    "Počet hesel": "Number of passwords",
    "malá písmena": "lowercase letters",
    "VELKÁ písmena": "UPPERCASE letters",
    "číslice": "digits",
    "symboly": "symbols",
    "Celé heslo se vybírá rovnoměrně. Nevyhovující kandidát se zahodí a vygeneruje znovu.": (
        "The complete password is sampled uniformly. A candidate that does not "
        "meet the selected constraints is discarded and generated again."
    ),
    "Tokeny a identifikátory": "Tokens and identifiers",
    "Počet bajtů": "Number of bytes",
    "Platí pro Hex a Base64 URL.": "Applies to Hex and Base64 URL.",
    "Počet výstupů": "Number of outputs",
    "Formát": "Format",
    "Zdroje a funkční diagnostika": "Sources and functional diagnostics",
    "Přísný Windows CNG profil": "Strict Windows CNG profile",
    "Přímé BCryptGenRandom bez vlastního HMAC mixéru. Aktivuje se jen ve Windows se zapnutou systémovou FIPS zásadou.": (
        "Direct BCryptGenRandom without the custom HMAC mixer. It activates only "
        "on Windows when the system FIPS policy is enabled."
    ),
    "PŘÍMÉ CNG • NE CERTIFIKÁT APLIKACE": "DIRECT CNG • NOT AN APPLICATION CERTIFICATE",
    "Systémový CSPRNG": "System CSPRNG",
    "Nejjednodušší auditovatelná varianta. Přímo používá kryptografický generátor operačního systému.": (
        "The simplest auditable option. It directly uses the operating system's cryptographic generator."
    ),
    "KRYPTOGRAFICKY BEZPEČNÝ": "CRYPTOGRAPHICALLY SECURE",
    "Diverzifikovaný software": "Diversified software",
    "Stejný systémový základ plus HMAC proud a časování událostí bez připsané entropické garance.": (
        "The same system foundation plus an HMAC stream and event timing without "
        "claiming a guaranteed amount of entropy."
    ),
    "STEJNÁ GARANCE + DIVERZITA": "SAME GUARANTEE + DIVERSITY",
    "Vícezdrojový režim": "Multi-source mode",
    "Navíc vrství až osm souborů či vzdálených .efb balíčků. Žádný z nich nenahrazuje systémový základ.": (
        "Additionally layers up to eight files or remote .efb bundles. None of them replaces the system foundation."
    ),
    "VYŽADUJE EXTERNÍ DATA": "REQUIRES EXTERNAL DATA",
    "Přidat další externí zdroj": "Add another external source",
    "Lze postupně navrstvit až osm souborů z lokálního hardwaru i .efb balíčků vytvořených vzdáleným sběračem. Duplicitní zdroj se odmítne a původní bajty se po jednosměrném zpracování nedrží jako výstupní proud.": (
        "Up to eight files from local hardware or .efb bundles created by the "
        "remote collector can be layered. Duplicate sources are rejected, and "
        "the original bytes are not retained as an output stream after one-way processing."
    ),
    "Formát souboru": "File format",
    "Automaticky rozpoznat": "Detect automatically",
    "Surová binární data": "Raw binary data",
    "Hexadecimální text": "Hexadecimal text",
    "Desítkové bajty": "Decimal bytes",
    "Textové bity": "Text bits",
    "Přidat soubor": "Add file",
    "Odebrat poslední": "Remove last",
    "Odebrat vše": "Remove all",
    "Externí zdroj není připojen.": "No external source is connected.",
    "Vzdálený balíček vytvoří samostatný nástroj remote_entropy_collector.py (ve Windows run_remote_collector.bat). Samotný generátor tak zůstává offline.": (
        "A remote bundle is created by the separate remote_entropy_collector.py "
        "tool (run_remote_collector.bat on Windows). The generator itself therefore remains offline."
    ),
    "Pokročilé nastavení zdroje": "Advanced source settings",
    "Režim": "Mode",
    "Automaticky, doporučeno": "Automatic, recommended",
    "Pouze systémový CSPRNG": "System CSPRNG only",
    "Vícezdrojový s externími daty": "Multi-source with external data",
    "Spustit funkční diagnostiku": "Run functional diagnostics",
    "Uložit technický report": "Save technical report",
    "Automatický režim použije dostupné doplňkové zdroje. Přísný profil je záměrně oddělený: čte přímo Windows CNG, nepřimíchává časování ani externí data a při nesplnění podmínek selže bez náhradního režimu.": (
        "Automatic mode uses available supplementary sources. The strict profile "
        "is deliberately separate: it reads Windows CNG directly, does not mix "
        "timing or external data, and fails without a fallback when its conditions are not met."
    ),
    "Funkční diagnostika zatím nebyla spuštěna.": "Functional diagnostics have not been run yet.",
    "Co je uvnitř": "What is inside",
    "Bezpečný základ": "Secure foundation",
    "Běžné režimy stojí na os.urandom(); přísný Windows profil volá přímo BCryptGenRandom se systémově preferovaným poskytovatelem.": (
        "Standard modes use os.urandom(); the strict Windows profile directly "
        "calls BCryptGenRandom with the system-preferred provider."
    ),
    "Bez zkreslení": "Unbiased mapping",
    "Čísla v intervalu používají rejection sampling, nikoli jednoduché modulo.": (
        "Numbers in a range use rejection sampling rather than simple modulo reduction."
    ),
    "Soukromí kláves": "Keyboard privacy",
    "Zpracovává se pouze časování události. Znak, keycode ani napsaný text se nesbírá.": (
        "Only event timing is processed. The character, keycode, and typed text are not collected."
    ),
    "Standardní promíchání": "Standard mixing",
    "Doplňkový proud používá doménově oddělený HMAC-SHA-512 a je XORován s čerstvým systémovým proudem.": (
        "The supplementary stream uses domain-separated HMAC-SHA-512 and is XORed with a fresh system stream."
    ),
    "Poctivé omezení": "Honest limitations",
    "Certifikace podkladového modulu Windows není certifikací EntropyForge. Časování ani statistika souboru nedostávají automatický odhad entropie.": (
        "Certification of the underlying Windows module is not certification of "
        "EntropyForge. Timing and file statistics are not automatically assigned an entropy estimate."
    ),
    "Fail-closed profil": "Fail-closed profile",
    "Přísný režim se bez Windows CNG a zapnuté FIPS zásady neaktivuje a nikdy tiše nepřejde na jiný zdroj.": (
        "Strict mode does not activate without Windows CNG and an enabled FIPS "
        "policy, and it never silently falls back to another source."
    ),
    "Oddělená síťová vrstva": "Separate network layer",
    "Generátor zůstává offline. Samostatný sběrač může vytvořit kontrolovaný .efb balíček z drand, NIST a volitelně RANDOM.ORG.": (
        "The generator remains offline. A separate collector can create a "
        "controlled .efb bundle from drand, NIST, and optionally RANDOM.ORG."
    ),
    "Doplňkové časování: 0 událostí • aktivně použito jako bonusová diverzifikace": (
        "Supplementary timing: 0 events • actively used as bonus diversification"
    ),
    "Doplňkové časování: nepoužívá se (": "Supplementary timing: not used (",
    " zaznamenaných událostí)": " recorded events)",
    "Doplňkové časování: ": "Supplementary timing: ",
    " událostí • aktivně použito jako bonusová diverzifikace": (
        " events • actively used as bonus diversification"
    ),
    "Systémový zdroj: v pořádku": "System source: healthy",
    "Windows CNG profil: v pořádku": "Windows CNG profile: healthy",
    "VRSTVY: ": "LAYERS: ",
    "DIVERZITA: 1/3 • PŘÍMÝ PROFIL": "DIVERSITY: 1/3 • DIRECT PROFILE",
    "Jedna přímá vrstva: BCryptGenRandom se systémově preferovaným poskytovatelem. Vlastní HMAC, časování i externí data jsou z výstupní cesty vyřazeny.": (
        "One direct layer: BCryptGenRandom with the system-preferred provider. "
        "The custom HMAC, timing, and external data are excluded from the output path."
    ),
    " Offline podklad odpovídá ": " The offline evidence matches ",
    " Přesnou certifikační shodu prostředí musí potvrdit laboratoř.": (
        " Exact validation matching of the environment must be confirmed by a laboratory."
    ),
    "Jedna vrstva: přímý kryptografický generátor operačního systému. Nejmenší vlastní kód a nejsnazší audit.": (
        "One layer: the operating system's direct cryptographic generator. "
        "The smallest amount of custom code and the easiest audit."
    ),
    "Dvě vrstvy: čerstvý systémový proud a doménově oddělená HMAC diverzifikace s časováním. Formální garance zůstává stejná jako u systémového CSPRNG.": (
        "Two layers: a fresh system stream and domain-separated HMAC diversification "
        "with timing. The formal guarantee remains the same as for the system CSPRNG."
    ),
    "Tři konstrukční vrstvy; aktivní soubory/balíčky: ": (
        "Three construction layers; active files/bundles: "
    ),
    ", samostatné externí komponenty: ": ", independent external components: ",
    ". Systémový proud zůstává základem.": ". The system stream remains the foundation.",
    " Součástí je vzdálený fyzický zdroj známý poskytovateli.": (
        " Includes a remote physical source whose bytes are known to the provider."
    ),
    " Veřejné beacony zvyšují auditovatelnou diverzitu, ale nejsou tajnou entropií.": (
        " Public beacons increase auditable diversity but are not secret entropy."
    ),
    "externí komponenta": "external component",
    "externí komponenty": "external components",
    "externích komponent": "external components",
    "ZDROJ": "SOURCE",
    "ZDROJE": "SOURCES",
    "ZDROJŮ": "SOURCES",
    " EXTERNÍ\n": " EXTERNAL\n",
    "Přísný Windows profil není připraven": "Strict Windows profile is not ready",
    "Přísný profil není dostupný.": "The strict profile is unavailable.",
    "Aplikace nepřepnula na náhradní zdroj.": "The application did not switch to a fallback source.",
    "Nejdřív přidej externí zdroj": "Add an external source first",
    "Externí zdroj zatím není přidaný. Aktivní režim se nezměnil.": (
        "No external source has been added yet. The active mode was not changed."
    ),
    "Přísný Windows profil není připraven. Aktivní režim se nezměnil a nebyl použit žádný náhradní zdroj.": (
        "The strict Windows profile is not ready. The active mode was not changed "
        "and no fallback source was used."
    ),
    "Externí zdroj zatím není přidaný. Aktivní zůstává diverzifikovaný režim.": (
        "No external source has been added yet. Diversified mode remains active."
    ),
    "Aktivní režim: ": "Active mode: ",
    "UUID v4 má vždy pevně 16 bajtů.": "UUID v4 always has a fixed size of 16 bytes.",
    "Generuji čísla…": "Generating numbers…",
    "Losuji…": "Drawing…",
    "Generuji hesla…": "Generating passwords…",
    "Generuji tokeny…": "Generating tokens…",
    "Dekóduji a zpracovávám externí zdroj…": "Decoding and processing external source…",
    "Spouštím funkční diagnostiku…": "Running functional diagnostics…",
    "Vybrat data z externího RNG": "Select data from an external RNG",
    "Všechny soubory": "All files",
    "Binární soubory": "Binary files",
    "Textové soubory": "Text files",
    "Textový soubor": "Text file",
    "Aktivní soubory/balíčky: ": "Active files/bundles: ",
    " • poslední: ": " • last: ",
    " B zdrojových dat": " B of source data",
    " B soubor / ": " B file / ",
    " bajtů": " bytes",
    " komponent": " components",
    "Odebrán externí zdroj: ": "External source removed: ",
    "Externí zdroj odebrán": "External sources removed",
    "Funkční diagnostika: ": "Functional diagnostics: ",
    "PROŠLA": "PASSED",
    "VAROVÁNÍ": "WARNING",
    "Vzorek: ": "Sample: ",
    "Podíl jedniček: ": "One-bit ratio: ",
    "Chí-kvadrát bajtů: ": "Byte chi-square: ",
    "Duplicitní 64B bloky: ": "Duplicate 64-byte blocks: ",
    "Rozsah: ": "Scope: ",
    "funkční smoke test; neověřuje nepředvídatelnost ani fyzickou entropii": (
        "functional smoke test; does not verify unpredictability or physical entropy"
    ),
    " – technický report": " – technical report",
    "Čas: ": "Time: ",
    "Požadovaný režim: ": "Requested mode: ",
    "Lokální časovací události: ": "Local timing events: ",
    "Externí soubory/balíčky: ": "External files/bundles: ",
    "Externí komponenty celkem: ": "Total external components: ",
    "Přísný Windows profil připraven: ": "Strict Windows profile ready: ",
    "Windows FIPS zásada: ": "Windows FIPS policy: ",
    "Stav certifikačních podkladů: ": "Validation evidence status: ",
    "Podkladový certifikát: ": "Underlying certificate: ",
    "Omezení tvrzení: ": "Claim limitation: ",
    "Externí zdroj ": "External source ",
    "  Zdrojová data: ": "  Source data: ",
    "  Kanonický otisk SHA-256: ": "  Canonical SHA-256 fingerprint: ",
    "  Formát: ": "  Format: ",
    "  Komponenty: ": "  Components: ",
    "  Vytvořeno UTC: ": "  Created UTC: ",
    "  Vytvořeno UTC: neuvedeno": "  Created UTC: not specified",
    "  Deklarované komponenty: ": "  Declared components: ",
    "  Deklarované komponenty: neuvedeny": "  Declared components: not specified",
    "  Jistota: ": "  Assurance: ",
    "Operační systém: ": "Operating system: ",
    "Aktivní výstupní zdroj: přímé BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG)": (
        "Active output source: direct BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG)"
    ),
    "Aktivní výstupní základ: os.urandom()": "Active output foundation: os.urandom()",
    "Doplňkový směšovač: vyřazen z přísného profilu": (
        "Supplementary mixer: excluded from the strict profile"
    ),
    "Doplňkový směšovač: HMAC-SHA-512, doménově oddělený": (
        "Supplementary mixer: domain-separated HMAC-SHA-512"
    ),
    "Síťová komunikace generátoru: žádná": "Generator network communication: none",
    "Volitelná síťová komunikace: pouze samostatný remote_entropy_collector.py": (
        "Optional network communication: separate remote_entropy_collector.py only"
    ),
    "Poznámka: certifikace podkladového kryptografického modulu není certifikací EntropyForge; diagnostika ani statistika souboru nejsou certifikací fyzické náhodnosti.": (
        "Note: certification of the underlying cryptographic module is not "
        "certification of EntropyForge; diagnostics and file statistics are not "
        "certification of physical randomness."
    ),
    "Uložit výstup": "Save output",
    "Report uložen: ": "Report saved: ",
    "Zkopírováno do schránky": "Copied to clipboard",
    "Uloženo: ": "Saved: ",
    "Výstup vymazán": "Output cleared",
    "ano": "yes",
    "ne": "no",
    "nezjištěno": "not detected",
    "nespárován": "unmatched",
    "neuvedeno": "not specified",
    "neuvedeny": "not specified",
    "binární / surová data": "binary / raw data",
    "textové bity": "text bits",
    "desítkové bajty": "decimal bytes",
    "hexadecimální text": "hexadecimal text",
    "pouze základní kontrola; původ ani entropie nejsou ověřeny": (
        "basic check only; origin and entropy are not verified"
    ),
    "obsahuje vzdálený fyzický zdroj doručený přes HTTPS; poskytovatel jeho bajty zná. Metadata původu po importu nejsou v aplikaci znovu kryptograficky ověřena": (
        "contains a remote physical source delivered over HTTPS; the provider "
        "knows its bytes. Origin metadata are not cryptographically reverified after import"
    ),
    "obsahuje pouze veřejné beacony; přidává nezávislou auditovatelnou diverzifikaci, nikoli tajnou entropii": (
        "contains public beacons only; adds independent auditable diversification, not secret entropy"
    ),
    "striktní struktura a kontrolní součty; původ zdrojů není při importu znovu ověřen": (
        "strict structure and checksums; source origin is not reverified during import"
    ),
    "uživatelem dodaný zdroj; fyzický původ a min-entropie nejsou ověřeny": (
        "user-supplied source; physical origin and min-entropy are not verified"
    ),
    "Neznámý režim generátoru.": "Unknown generator mode.",
    "Systémový kryptografický zdroj je dostupný.": "The system cryptographic source is available.",
    "Systémový zdroj prošel průběžnou kontrolou.": "The system source passed the continuous check.",
    "VAROVÁNÍ: systémový zdroj zopakoval celý 64B blok.": (
        "WARNING: the system source repeated an entire 64-byte block."
    ),
    "Počet bajtů musí být celé číslo.": "The number of bytes must be an integer.",
    "Počet bajtů nesmí být záporný.": "The number of bytes must not be negative.",
    "Přísný Windows profil selhal: ": "Strict Windows profile failed: ",
    "Přísný Windows CNG profil prošel průběžnou kontrolou.": (
        "The strict Windows CNG profile passed the continuous check."
    ),
    "Neplatný počet bajtů.": "Invalid byte count.",
    "Horní mez musí být celé číslo.": "The upper bound must be an integer.",
    "Horní mez musí být kladná.": "The upper bound must be positive.",
    "Minimum nesmí být větší než maximum.": "The minimum must not be greater than the maximum.",
    "Nelze vybírat z prázdného seznamu.": "Cannot choose from an empty list.",
    "Neplatný počet prvků pro výběr bez opakování.": (
        "Invalid item count for sampling without replacement."
    ),
    "Neplatný počet čísel pro výběr bez opakování.": (
        "Invalid number count for sampling without replacement."
    ),
    "Délka hesla musí být kladná.": "Password length must be positive.",
    "Skupiny znaků nesmí být prázdné.": "Character groups must not be empty.",
    "Heslo je kratší než počet vybraných skupin.": (
        "The password is shorter than the number of selected groups."
    ),
    "Neznámý formát externích dat.": "Unknown external data format.",
    "Soubor není platný text UTF-8 pro zvolený formát.": (
        "The file is not valid UTF-8 text for the selected format."
    ),
    "Externí soubor je prázdný.": "The external file is empty.",
    "Bitový text musí obsahovat pouze 0 a 1 a celý počet bajtů.": (
        "Bit text must contain only 0 and 1 and a whole number of bytes."
    ),
    "Desítkové bajty musí být oddělené mezerou, čárkou nebo středníkem.": (
        "Decimal bytes must be separated by spaces, commas, or semicolons."
    ),
    "Desítkové bajty musí být v rozsahu 0 až 255.": (
        "Decimal bytes must be in the range 0 to 255."
    ),
    "Hexadecimální text musí mít sudý počet platných hex znaků.": (
        "Hexadecimal text must have an even number of valid hex characters."
    ),
    "Soubor není platný Base64 nebo Base64 URL text.": (
        "The file is not valid Base64 or Base64 URL text."
    ),
    "Textový soubor neodpovídá žádnému podporovanému formátu. Vyber správný formát ručně nebo použij surový binární soubor.": (
        "The text file does not match any supported format. Select the correct "
        "format manually or use a raw binary file."
    ),
    "Externí zdroj musí obsahovat alespoň 4096 skutečných bajtů náhodných dat.": (
        "The external source must contain at least 4096 actual bytes of random data."
    ),
    "Dekódovaná externí data mohou mít nejvýše 32 MiB.": (
        "Decoded external data may be at most 32 MiB."
    ),
    "Soubor je zjevně degenerovaný a neprošel základní kontrolou neporušenosti.": (
        "The file is clearly degenerate and failed the basic integrity check."
    ),
    "Tento externí zdroj už byl v aktuální relaci zpracovaný.": (
        "This external source has already been processed in the current session."
    ),
    "Současně lze přidat nejvýše ": "At most ",
    " externích zdrojů.": " external sources can be added at once.",
    "Externí soubor může mít nejvýše 32 MiB.": "The external file may be at most 32 MiB.",
    "Neplatný EntropyForge vzdálený balíček: ": "Invalid EntropyForge remote bundle: ",
    "Soubor není EntropyForge Remote Bundle.": "The file is not an EntropyForge Remote Bundle.",
    "Balíček neobsahuje platný JSON.": "The bundle does not contain valid JSON.",
    "Balíček není platný text UTF-8.": "The bundle is not valid UTF-8 text.",
    "Duplicitní JSON klíč: ": "Duplicate JSON key: ",
    "Nepovolená JSON konstanta: ": "Disallowed JSON constant: ",
    "Metadata balíčku nelze kanonicky serializovat.": (
        "Bundle metadata cannot be serialized canonically."
    ),
    "Vnější obal balíčku": "Bundle envelope",
    "Obsah balíčku": "Bundle payload",
    "Vnější obal balíčku musí být JSON objekt.": (
        "The bundle envelope must be a JSON object."
    ),
    "Vnější obal balíčku není v požadovaném kanonickém JSON tvaru.": (
        "The bundle envelope is not in the required canonical JSON form."
    ),
    "Nepodporovaná verze EntropyForge balíčku.": (
        "Unsupported EntropyForge bundle version."
    ),
    "payload_sha256 nemá platný formát.": "payload_sha256 has an invalid format.",
    "Dekódovaný obsah balíčku musí mít 1 B až 1 MiB.": (
        "The decoded bundle payload must be between 1 B and 1 MiB."
    ),
    "Kontrolní součet vzdáleného balíčku nesouhlasí.": (
        "The remote bundle checksum does not match."
    ),
    "Obsah balíčku musí být JSON objekt.": "The bundle payload must be a JSON object.",
    "Obsah balíčku není v požadovaném kanonickém JSON tvaru.": (
        "The bundle payload is not in the required canonical JSON form."
    ),
    "Nepodporovaná verze obsahu EntropyForge balíčku.": (
        "Unsupported EntropyForge bundle payload version."
    ),
    "created_utc musí být UTC čas ve formátu ISO 8601 s koncovým Z.": (
        "created_utc must be an ISO 8601 UTC timestamp ending in Z."
    ),
    "created_utc musí být v UTC.": "created_utc must be in UTC.",
    "created_utc není platný kalendářní čas.": (
        "created_utc is not a valid calendar timestamp."
    ),
    "Metadata obsahují nepodporovaný JSON typ.": (
        "Metadata contain an unsupported JSON type."
    ),
    "Metadata obsahují příliš mnoho položek.": "Metadata contain too many items.",
    "Metadata jsou vnořena příliš hluboko.": "Metadata are nested too deeply.",
    "Metadata nesmějí obsahovat desetinná čísla.": (
        "Metadata must not contain floating-point numbers."
    ),
    "Číslo v metadatech přesahuje přenositelný bezpečný rozsah.": (
        "A metadata number exceeds the portable safe range."
    ),
    "Textová hodnota v metadatech je příliš dlouhá.": (
        "A metadata string value is too long."
    ),
    "Metadata obsahují neplatný Unicode znak.": (
        "Metadata contain an invalid Unicode character."
    ),
    "Seznam v metadatech obsahuje příliš mnoho položek.": (
        "A metadata list contains too many items."
    ),
    "Objekt v metadatech obsahuje příliš mnoho polí.": (
        "A metadata object contains too many fields."
    ),
    "Klíče metadat musí mít 1 až 96 tisknutelných ASCII znaků.": (
        "Metadata keys must contain 1 to 96 printable ASCII characters."
    ),
    "Balíček musí obsahovat 1 až ": "The bundle must contain between 1 and ",
    " zdrojů.": " sources.",
    " má neplatná pole (": " has invalid fields (",
    " musí být text délky ": " must be text with a length of ",
    " až ": " to ",
    " znaků.": " characters.",
    " smí obsahovat pouze tisknutelné ASCII znaky.": (
        " may contain printable ASCII characters only."
    ),
    " není kanonický Base64 text.": " is not canonical Base64 text.",
    " není kanonicky zapsaný Base64 text.": (
        " is not encoded as canonical Base64 text."
    ),
    " není platný Base64 text.": " is not valid Base64 text.",
    "chybí ": "missing ",
    "navíc ": "extra ",
    " musí být JSON objekt.": " must be a JSON object.",
    ": id má nepovolený formát.": ": id has a disallowed format.",
    ": duplicitní id ": ": duplicate id ",
    ": nepodporovaný kind.": ": unsupported kind.",
    ": nepodporovaná visibility.": ": unsupported visibility.",
    ": veřejný beacon musí mít visibility=public.": (
        ": a public beacon must have visibility=public."
    ),
    ": vzdálený TRNG musí mít visibility=provider_known.": (
        ": a remote TRNG must have visibility=provider_known."
    ),
    ": náhodná data musí mít ": ": random data must contain ",
    " bajtů.": " bytes.",
    ": náhodná data jsou zjevně degenerovaná.": (
        ": random data are clearly degenerate."
    ),
    ": data_sha256 nemá platný formát.": ": data_sha256 has an invalid format.",
    ": kontrolní součet náhodných dat nesouhlasí.": (
        ": the random-data checksum does not match."
    ),
    ": stejná náhodná data už balíček obsahuje.": (
        ": the bundle already contains the same random data."
    ),
    ": validation musí obsahovat 1 až 8 položek.": (
        ": validation must contain 1 to 8 items."
    ),
    ": metadata musí být JSON objekt.": ": metadata must be a JSON object.",
    " musí být celé číslo.": " must be an integer.",
    " může mít nejvýše ": " may have at most ",
    " číslic.": " digits.",
    "Požadovaný výstup je příliš velký. Limit je přibližně ": (
        "The requested output is too large. The limit is approximately "
    ),
    "Počet musí být mezi 1 a 100 000.": "The count must be between 1 and 100,000.",
    "Pro výběr bez opakování je interval příliš malý.": (
        "The interval is too small for sampling without replacement."
    ),
    "Zadej alespoň jednu možnost.": "Enter at least one option.",
    "Počet výběrů je větší než počet různých možností.": (
        "The number of selections exceeds the number of distinct options."
    ),
    "Délka hesla musí být mezi 4 a 4096.": "Password length must be between 4 and 4096.",
    "Počet hesel musí být mezi 1 a 5000.": "The number of passwords must be between 1 and 5000.",
    "Vyber alespoň jednu skupinu znaků.": "Select at least one character group.",
    "Počet výstupů musí být mezi 1 a 10 000.": (
        "The number of outputs must be between 1 and 10,000."
    ),
    "Počet bajtů musí být mezi 1 a 1 048 576.": (
        "The number of bytes must be between 1 and 1,048,576."
    ),
    "Přísný profil je dostupný pouze ve Windows.": (
        "The strict profile is available only on Windows."
    ),
    "BCryptGetFipsAlgorithmMode není dostupné.": "BCryptGetFipsAlgorithmMode is unavailable.",
    "Systémová zásada Windows „System cryptography: Use FIPS compliant algorithms“ není zapnutá.": (
        "The Windows policy “System cryptography: Use FIPS compliant algorithms” is not enabled."
    ),
    "Windows CNG je připravené a verze systému odpovídá aktivnímu podkladovému certifikátu v manifestu.": (
        "Windows CNG is ready and the system version matches an active underlying certificate in the manifest."
    ),
    "Windows CNG je připravené v systémovém FIPS režimu, ale přesná certifikační shoda prostředí není offline doložena.": (
        "Windows CNG is ready in system FIPS mode, but an exact validation match "
        "for the environment is not documented offline."
    ),
    "Přísný Windows CNG profil není připraven k použití.": (
        "The strict Windows CNG profile is not ready for use."
    ),
    "Certifikace se vztahuje pouze na podkladový kryptografický modul v podmínkách jeho Security Policy, nikoli na EntropyForge.": (
        "Certification applies only to the underlying cryptographic module under "
        "the conditions of its Security Policy, not to EntropyForge."
    ),
    "BCryptGenRandom není dostupné.": "BCryptGenRandom is unavailable.",
    "bcrypt.dll nelze načíst: ": "bcrypt.dll could not be loaded: ",
    "Windows CNG neposkytuje očekávané API: ": (
        "Windows CNG does not provide the expected API: "
    ),
    "Podkladový certifikát ": "Underlying certificate ",
    " dosáhl data sunset ": " reached its sunset date ",
    "Windows CNG zopakovalo celý 64bajtový kontrolní blok.": (
        "Windows CNG repeated the entire 64-byte health-check block."
    ),
    "Jeden požadavek přísného profilu může mít nejvýše ": (
        "A single strict-profile request may contain at most "
    ),
    "Verze Windows není v přiloženém offline manifestu spárována s dokončeným CMVP certifikátem; aktuální stav musí ověřit laboratoř.": (
        "The Windows version is not matched to a completed CMVP certificate in "
        "the bundled offline manifest; a laboratory must verify the current status."
    ),
    "Jazyk přepnut na češtinu.": "Language switched to Czech.",
    "Jazyk přepnut na angličtinu.": "Language switched to English.",
}


def translate_text(text: object, language: str) -> str:
    """Translate a canonical Czech UI message without touching generated data."""
    value = str(text)
    if language != "en":
        return value
    exact = EN_TRANSLATIONS.get(value)
    if exact is not None:
        return exact
    translated = value
    for source, target in sorted(
        EN_TRANSLATIONS.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if len(source) < 4:
            continue
        if source in translated:
            translated = translated.replace(source, target)
    return translated


class StrictRandomBackend(Protocol):
    @property
    def ready(self) -> bool: ...

    def status(self) -> object: ...

    def generate(self, n: int) -> bytes: ...


class EntropyEngine:
    """Thread-safe RNG with an OS CSPRNG foundation in every mode."""

    VALID_MODES = {"auto", "validated", "system", "hybrid", "external"}

    def __init__(
        self,
        validated_backend: StrictRandomBackend | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._counter = 0
        self._events = 0
        self._requested_mode = "auto"
        self._external_pool: bytes | None = None
        self._external_sources: list[tuple[bytes, dict[str, object]]] = []
        self._seen_external_keys: set[str] = set()
        self._seen_external_components: set[str] = set()
        self._last_os_probe: bytes | None = None
        self._health_ok = True
        self._health_message = "Systémový kryptografický zdroj je dostupný."
        self._last_event_ns = 0
        self._reservoir = b""
        self._reservoir_pos = 0
        self._reservoir_dirty = False
        self._validated_backend = validated_backend or WindowsCNGBackend()

        boot = os.urandom(64)
        self._last_os_probe = boot
        self._pool = hmac.new(
            boot,
            DOMAIN + b"boot|" + self._runtime_metadata(),
            hashlib.sha512,
        ).digest()

    @staticmethod
    def _runtime_metadata() -> bytes:
        parts = (
            str(time.time_ns()),
            str(time.perf_counter_ns()),
            str(time.process_time_ns()),
            str(os.getpid()),
            platform.system(),
            platform.release(),
            platform.machine(),
            platform.python_version(),
        )
        return "|".join(parts).encode("utf-8", "surrogatepass")

    @staticmethod
    def _u64(value: int) -> bytes:
        return struct.pack(">Q", value & ((1 << 64) - 1))

    @property
    def requested_mode(self) -> str:
        with self._lock:
            return self._requested_mode

    @property
    def effective_mode(self) -> str:
        with self._lock:
            if self._requested_mode == "auto":
                return "external" if self._external_pool is not None else "hybrid"
            if self._requested_mode == "external" and self._external_pool is None:
                return "hybrid"
            return self._requested_mode

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._events

    @property
    def external_info(self) -> dict[str, object] | None:
        with self._lock:
            if not self._external_sources:
                return None
            return dict(self._external_sources[-1][1])

    @property
    def external_sources_info(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(info) for _digest, info in self._external_sources]

    @property
    def external_source_count(self) -> int:
        with self._lock:
            return len(self._external_sources)

    @property
    def health(self) -> tuple[bool, str]:
        with self._lock:
            return self._health_ok, self._health_message

    @property
    def validated_ready(self) -> bool:
        return bool(self._validated_backend.ready)

    @property
    def validated_status(self) -> dict[str, object]:
        status = self._validated_backend.status()
        public = getattr(status, "public_dict", None)
        if callable(public):
            return dict(public())
        if isinstance(status, dict):
            return dict(status)
        return {
            "ready": bool(self._validated_backend.ready),
            "summary": str(status),
            "issues": [],
        }

    def set_mode(self, mode: str) -> None:
        if mode not in self.VALID_MODES:
            raise ValueError("Neznámý režim generátoru.")
        with self._lock:
            self._requested_mode = mode
            self._clear_reservoir_locked()

    def _clear_reservoir_locked(self) -> None:
        self._reservoir = b""
        self._reservoir_pos = 0
        self._reservoir_dirty = False

    def clear_reservoir(self) -> None:
        with self._lock:
            self._clear_reservoir_locked()

    def add_timing_event(self, kind: str) -> None:
        """Mix only event type and timing; no entropy credit is assigned."""
        now = time.perf_counter_ns()
        with self._lock:
            delta = max(0, now - self._last_event_ns) if self._last_event_ns else 0
            self._last_event_ns = now
            self._counter += 1
            payload = (
                kind.encode("ascii", "ignore")
                + b"|"
                + self._u64(delta)
                + self._u64(time.time_ns())
                + self._u64(self._events)
            )
            self._pool = hmac.new(
                self._pool,
                DOMAIN + b"event|" + self._u64(self._counter) + payload,
                hashlib.sha512,
            ).digest()
            self._events += 1
            self._reservoir_dirty = True

    def _health_probe_locked(self) -> bytes:
        probe = os.urandom(64)
        if self._last_os_probe is not None and probe == self._last_os_probe:
            self._health_ok = False
            self._health_message = "VAROVÁNÍ: systémový zdroj zopakoval celý 64B blok."
            raise RuntimeError(self._health_message)
        self._last_os_probe = probe
        self._health_ok = True
        self._health_message = "Systémový zdroj prošel průběžnou kontrolou."
        return probe

    def bytes(self, n: int) -> bytes:
        """Return n bytes from the selected cryptographic provider."""
        if not isinstance(n, int):
            raise TypeError("Počet bajtů musí být celé číslo.")
        if n < 0:
            raise ValueError("Počet bajtů nesmí být záporný.")
        if n == 0:
            return b""

        with self._lock:
            mode = self.effective_mode
            if mode == "validated":
                try:
                    output = self._validated_backend.generate(n)
                except (StrictProfileError, RuntimeError) as exc:
                    self._health_ok = False
                    self._health_message = f"Přísný Windows profil selhal: {exc}"
                    raise
                self._health_ok = True
                self._health_message = (
                    "Přísný Windows CNG profil prošel průběžnou kontrolou."
                )
                return output

            self._health_probe_locked()
            direct = os.urandom(n)
            if mode == "system":
                return direct

            fresh_seed = os.urandom(64)
            self._counter += 1
            external = self._external_pool if mode == "external" else b""
            metadata = (
                self._u64(self._counter)
                + self._u64(time.time_ns())
                + self._u64(time.perf_counter_ns())
                + self._runtime_metadata()
            )
            mixed_seed = hmac.new(
                self._pool,
                DOMAIN
                + b"derive|"
                + fresh_seed
                + (external or b"")
                + metadata,
                hashlib.sha512,
            ).digest()
            supplementary = self._expand_hmac(mixed_seed, n, b"stream|")
            result = bytes(a ^ b for a, b in zip(direct, supplementary))

            result_tag = hashlib.sha256(result).digest()
            self._pool = hmac.new(
                mixed_seed,
                DOMAIN
                + b"update|"
                + self._pool
                + fresh_seed
                + (external or b"")
                + result_tag
                + metadata,
                hashlib.sha512,
            ).digest()
            return result

    @staticmethod
    def _expand_hmac(key: bytes, n: int, label: bytes) -> bytes:
        """Expand a secret key with domain-separated HMAC-SHA-512 blocks."""
        output = bytearray()
        block = 1
        while len(output) < n:
            output.extend(
                hmac.new(
                    key,
                    DOMAIN + label + EntropyEngine._u64(block),
                    hashlib.sha512,
                ).digest()
            )
            block += 1
        return bytes(output[:n])

    def _take_bytes(self, n: int) -> bytes:
        """Serve small requests from a cryptographic reservoir for speed."""
        if n <= 0:
            return b""
        with self._lock:
            if self._reservoir_dirty and self.effective_mode not in {
                "system",
                "validated",
            }:
                self._reservoir = b""
                self._reservoir_pos = 0
                self._reservoir_dirty = False
            remaining = len(self._reservoir) - self._reservoir_pos
            if remaining < n:
                refill_size = max(65_536, n)
                self._reservoir = self.bytes(refill_size)
                self._reservoir_pos = 0
            start = self._reservoir_pos
            self._reservoir_pos += n
            return self._reservoir[start : start + n]

    def randbelow(self, upper: int) -> int:
        """Uniform integer in [0, upper), using rejection sampling."""
        if not isinstance(upper, int):
            raise TypeError("Horní mez musí být celé číslo.")
        if upper <= 0:
            raise ValueError("Horní mez musí být kladná.")
        if upper == 1:
            return 0

        bits = (upper - 1).bit_length()
        byte_count = (bits + 7) // 8
        excess = byte_count * 8 - bits
        mask = 0xFF >> excess if excess else 0xFF

        while True:
            raw = bytearray(self._take_bytes(byte_count))
            raw[0] &= mask
            candidate = int.from_bytes(raw, "big")
            if candidate < upper:
                return candidate

    def randint(self, minimum: int, maximum: int) -> int:
        if minimum > maximum:
            raise ValueError("Minimum nesmí být větší než maximum.")
        return minimum + self.randbelow(maximum - minimum + 1)

    def choice(self, items: Sequence[T]) -> T:
        if not items:
            raise IndexError("Nelze vybírat z prázdného seznamu.")
        return items[self.randbelow(len(items))]

    def sample(self, items: Sequence[T], k: int) -> list[T]:
        if k < 0 or k > len(items):
            raise ValueError("Neplatný počet prvků pro výběr bez opakování.")
        copy = list(items)
        for i in range(k):
            j = i + self.randbelow(len(copy) - i)
            copy[i], copy[j] = copy[j], copy[i]
        return copy[:k]

    def sample_integer_range(self, minimum: int, maximum: int, k: int) -> list[int]:
        """Uniformly sample k distinct integers without materializing the range."""
        if minimum > maximum:
            raise ValueError("Minimum nesmí být větší než maximum.")
        span = maximum - minimum + 1
        if k < 0 or k > span:
            raise ValueError("Neplatný počet čísel pro výběr bez opakování.")
        swaps: dict[int, int] = {}
        values: list[int] = []
        for index in range(k):
            selected_index = index + self.randbelow(span - index)
            selected = swaps.get(selected_index, selected_index)
            swaps[selected_index] = swaps.get(index, index)
            values.append(minimum + selected)
        return values

    def password(self, length: int, groups: Sequence[str]) -> str:
        """Return a uniform password conditioned on containing every group."""
        if length <= 0:
            raise ValueError("Délka hesla musí být kladná.")
        if not groups or any(not group for group in groups):
            raise ValueError("Skupiny znaků nesmí být prázdné.")
        if length < len(groups):
            raise ValueError("Heslo je kratší než počet vybraných skupin.")
        alphabet = "".join(groups)
        while True:
            candidate = "".join(self.choice(alphabet) for _ in range(length))
            if all(any(character in group for character in candidate) for group in groups):
                return candidate

    def token_hex(self, nbytes: int) -> str:
        return self.bytes(nbytes).hex()

    def token_base64(self, nbytes: int) -> str:
        return base64.urlsafe_b64encode(self.bytes(nbytes)).decode("ascii").rstrip("=")

    def uuid4(self) -> str:
        data = bytearray(self.bytes(16))
        data[6] = (data[6] & 0x0F) | 0x40
        data[8] = (data[8] & 0x3F) | 0x80
        h = data.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    @staticmethod
    def _decode_text_entropy(
        raw: bytes,
        format_hint: str = "auto",
    ) -> tuple[bytes, str]:
        """Strictly decode external data into canonical bytes."""
        valid_formats = {"auto", "binary", "hex", "base64", "decimal", "bits"}
        if format_hint not in valid_formats:
            raise ValueError("Neznámý formát externích dat.")
        if format_hint == "binary":
            return raw, "binární / surová data"

        try:
            decoded_text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            if format_hint == "auto":
                return raw, "binární / surová data"
            raise ValueError("Soubor není platný text UTF-8 pro zvolený formát.") from exc

        if format_hint == "auto" and not all(
            character.isprintable() or character.isspace()
            for character in decoded_text
        ):
            return raw, "binární / surová data"

        text = decoded_text.strip()
        if not text:
            raise ValueError("Externí soubor je prázdný.")
        compact = re.sub(r"\s+", "", text)

        def decode_bits() -> tuple[bytes, str]:
            if not compact or len(compact) % 8 != 0 or not re.fullmatch(r"[01]+", compact):
                raise ValueError("Bitový text musí obsahovat pouze 0 a 1 a celý počet bajtů.")
            return (
                bytes(int(compact[index : index + 8], 2) for index in range(0, len(compact), 8)),
                "textové bity",
            )

        def decode_decimal() -> tuple[bytes, str]:
            if not re.fullmatch(r"\s*[0-9]{1,3}(?:[\s,;]+[0-9]{1,3})*\s*", text):
                raise ValueError("Desítkové bajty musí být oddělené mezerou, čárkou nebo středníkem.")
            values = [int(item) for item in re.split(r"[\s,;]+", text.strip()) if item]
            if not all(0 <= value <= 255 for value in values):
                raise ValueError("Desítkové bajty musí být v rozsahu 0 až 255.")
            return bytes(values), "desítkové bajty"

        def decode_hex() -> tuple[bytes, str]:
            if not compact or len(compact) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
                raise ValueError("Hexadecimální text musí mít sudý počet platných hex znaků.")
            return bytes.fromhex(compact), "hexadecimální text"

        def decode_base64() -> tuple[bytes, str]:
            normalized = compact.replace("-", "+").replace("_", "/")
            if (
                not normalized
                or len(normalized) % 4 == 1
                or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", normalized)
            ):
                raise ValueError("Soubor není platný Base64 nebo Base64 URL text.")
            try:
                padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
                decoded = base64.b64decode(padded, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise ValueError("Soubor není platný Base64 nebo Base64 URL text.") from exc
            return decoded, "Base64 / Base64 URL text"

        decoders = {
            "bits": decode_bits,
            "decimal": decode_decimal,
            "hex": decode_hex,
            "base64": decode_base64,
        }
        if format_hint != "auto":
            return decoders[format_hint]()

        if re.fullmatch(r"[01\s]+", text) and len(compact) % 8 == 0:
            return decode_bits()
        if re.fullmatch(r"\s*[0-9]{1,3}(?:[\s,;]+[0-9]{1,3})+\s*", text):
            return decode_decimal()
        if len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            return decode_hex()
        if re.fullmatch(r"[A-Za-z0-9+/_-]*={0,2}", compact):
            return decode_base64()
        raise ValueError(
            "Textový soubor neodpovídá žádnému podporovanému formátu. "
            "Vyber správný formát ručně nebo použij surový binární soubor."
        )

    @staticmethod
    def _basic_external_test(sample: bytes) -> dict[str, float | int | str]:
        """Reject only obvious corruption; this is not entropy certification."""
        if len(sample) < MIN_EXTERNAL_BYTES:
            raise ValueError("Externí zdroj musí obsahovat alespoň 4096 skutečných bajtů náhodných dat.")
        if len(sample) > MAX_EXTERNAL_FILE_BYTES:
            raise ValueError("Dekódovaná externí data mohou mít nejvýše 32 MiB.")

        freq = [0] * 256
        ones = 0
        longest = 1
        current = 1
        previous: int | None = None
        for value in sample:
            freq[value] += 1
            ones += value.bit_count()
            if previous == value:
                current += 1
                longest = max(longest, current)
            else:
                current = 1
            previous = value

        ratio = ones / (len(sample) * 8)
        distinct = sum(1 for value in freq if value)
        max_frequency = max(freq) / len(sample)
        if distinct < 2 or not 0.01 <= ratio <= 0.99 or max_frequency > 0.95 or longest >= 2048:
            raise ValueError(
                "Soubor je zjevně degenerovaný a neprošel základní kontrolou neporušenosti."
            )
        return {
            "sample_size": len(sample),
            "ones_ratio": ratio,
            "distinct_bytes": distinct,
            "max_frequency": max_frequency,
            "longest_run": longest,
            "assessment": "pouze základní kontrola; původ ani entropie nejsou ověřeny",
        }

    def _rebuild_external_pool_locked(self) -> None:
        if not self._external_sources:
            self._external_pool = None
            self._clear_reservoir_locked()
            return
        material = bytearray(
            DOMAIN + b"external-set|" + self._u64(len(self._external_sources))
        )
        for index, (source_digest, _info) in enumerate(self._external_sources, start=1):
            material.extend(self._u64(index))
            material.extend(source_digest)
        self._external_pool = hmac.new(
            self._pool,
            DOMAIN + b"external-pool|" + os.urandom(64) + bytes(material),
            hashlib.sha512,
        ).digest()
        self._clear_reservoir_locked()

    def _add_external_source_locked(
        self,
        source_digest: bytes,
        info: dict[str, object],
    ) -> None:
        source_key = str(info["source_key"])
        component_keys = tuple(str(key) for key in info["component_keys"])
        if (
            source_key in self._seen_external_keys
            or any(key in self._seen_external_components for key in component_keys)
        ):
            raise ValueError("Tento externí zdroj už byl v aktuální relaci zpracovaný.")
        if len(self._external_sources) >= MAX_EXTERNAL_SOURCES:
            raise ValueError(f"Současně lze přidat nejvýše {MAX_EXTERNAL_SOURCES} externích zdrojů.")
        self._external_sources.append((source_digest, info))
        try:
            self._rebuild_external_pool_locked()
        except Exception:
            self._external_sources.pop()
            raise
        self._seen_external_keys.add(source_key)
        self._seen_external_components.update(component_keys)

    def load_external_file(self, filename: str, format_hint: str = "auto") -> dict[str, object]:
        valid_formats = {"auto", "binary", "hex", "base64", "decimal", "bits", "bundle"}
        if format_hint not in valid_formats:
            raise ValueError("Neznámý formát externích dat.")
        path = Path(filename)
        with path.open("rb") as handle:
            raw = handle.read(MAX_EXTERNAL_FILE_BYTES + 1)
        raw_size = len(raw)
        if not raw:
            raise ValueError("Externí soubor je prázdný.")
        if raw_size > MAX_EXTERNAL_FILE_BYTES:
            raise ValueError("Externí soubor může mít nejvýše 32 MiB.")

        is_remote_bundle = format_hint == "bundle" or (
            format_hint == "auto"
            and (path.suffix.lower() == ".efb" or looks_like_bundle(raw))
        )
        if is_remote_bundle:
            try:
                bundle = parse_bundle(raw)
            except BundleError as exc:
                raise ValueError(f"Neplatný EntropyForge vzdálený balíček: {exc}") from exc
            digest = hashlib.sha512(
                DOMAIN
                + b"remote-bundle|"
                + self._u64(len(bundle.payload_bytes))
                + bundle.payload_bytes
            ).digest()
            if bundle.provider_known_count:
                assurance = (
                    "obsahuje vzdálený fyzický zdroj doručený přes HTTPS; poskytovatel jeho bajty zná. "
                    "Metadata původu po importu nejsou v aplikaci znovu kryptograficky ověřena"
                )
            else:
                assurance = (
                    "obsahuje pouze veřejné beacony; přidává nezávislou auditovatelnou diverzifikaci, "
                    "nikoli tajnou entropii"
                )
            info: dict[str, object] = {
                "name": path.name,
                "raw_size": raw_size,
                "decoded_size": bundle.total_random_bytes,
                "digest": bundle.fingerprint,
                "format": "EntropyForge Remote Bundle v1",
                "stats": {
                    "sample_size": bundle.total_random_bytes,
                    "assessment": "striktní struktura a kontrolní součty; původ zdrojů není při importu znovu ověřen",
                },
                "assurance": assurance,
                "source_type": "remote_bundle",
                "source_key": f"bundle:{bundle.fingerprint}",
                "component_count": bundle.source_count,
                "public_components": bundle.public_count,
                "provider_known_components": bundle.provider_known_count,
                "component_labels": tuple(source["label"] for source in bundle.sources),
                "component_keys": tuple(
                    f"data:{source['data_sha256']}" for source in bundle.sources
                ),
                "created_utc": bundle.payload["created_utc"],
            }
        else:
            if format_hint == "bundle":
                raise ValueError("Soubor není EntropyForge Remote Bundle.")
            decoded, format_name = self._decode_text_entropy(raw, format_hint)
            stats = self._basic_external_test(decoded)
            digest = hashlib.sha512(
                DOMAIN + b"external-data|" + self._u64(len(decoded)) + decoded
            ).digest()
            fingerprint = hashlib.sha256(decoded).hexdigest()
            info = {
                "name": path.name,
                "raw_size": raw_size,
                "decoded_size": len(decoded),
                "digest": fingerprint,
                "format": format_name,
                "stats": stats,
                "assurance": (
                    "uživatelem dodaný zdroj; fyzický původ a min-entropie nejsou ověřeny"
                ),
                "source_type": "external_file",
                "source_key": f"data:{fingerprint}",
                "component_count": 1,
                "public_components": 0,
                "provider_known_components": 0,
                "component_keys": (f"data:{fingerprint}",),
            }

        with self._lock:
            self._add_external_source_locked(digest, info)
            result = dict(info)
            result["active_source_count"] = len(self._external_sources)
            return result

    def remove_last_external(self) -> dict[str, object] | None:
        with self._lock:
            if not self._external_sources:
                return None
            _digest, info = self._external_sources.pop()
            self._rebuild_external_pool_locked()
            return dict(info)

    def remove_external(self) -> None:
        with self._lock:
            self._external_sources.clear()
            self._external_pool = None
            self._clear_reservoir_locked()

    def diagnostics(self, sample_size: int = 65_536) -> dict[str, object]:
        """Run a smoke test that can detect gross faults, not prove randomness."""
        sample = self.bytes(sample_size)
        freq = [0] * 256
        ones = 0
        blocks: set[bytes] = set()
        for index, value in enumerate(sample):
            freq[value] += 1
            ones += value.bit_count()
            if index % 64 == 0:
                blocks.add(sample[index : index + 64])

        ratio = ones / (sample_size * 8)
        expected = sample_size / 256
        chi_square = sum((value - expected) ** 2 / expected for value in freq)
        expected_blocks = math.ceil(sample_size / 64)
        duplicated = expected_blocks - len(blocks)
        ok = 0.48 < ratio < 0.52 and 100 < chi_square < 450 and duplicated == 0
        return {
            "ok": ok,
            "sample_size": sample_size,
            "ones_ratio": ratio,
            "chi_square": chi_square,
            "duplicated_blocks": duplicated,
            "mode": self.effective_mode,
            "scope": "funkční smoke test; neověřuje nepředvídatelnost ani fyzickou entropii",
        }

    def self_test(self, sample_size: int = 65_536) -> dict[str, object]:
        """Backward-compatible alias for diagnostics()."""
        return self.diagnostics(sample_size)


class ScrollablePage(tk.Frame):
    """Whole-window vertical scrolling for compact displays."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.content = tk.Frame(self.canvas, bg=BG)
        self.window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.content.bind("<Configure>", self._sync_scrollregion)
        self.canvas.bind("<Configure>", self._sync_width)

    def _sync_scrollregion(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _sync_width(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self.window_id, width=max(event.width, 650))

    def scroll_units(self, units: int) -> None:
        self.canvas.yview_scroll(units, "units")


class EntropyForgeApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.engine = EntropyEngine()
        self.language_code = self._load_language_preference()
        self._translatable_widgets: list[tuple[tk.Misc, str]] = []
        self._last_diagnostic: dict[str, object] | None = None
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1240x880")
        self.root.minsize(640, 460)
        self.root.configure(bg=BG)

        self._status_var = tk.StringVar(value=self._tr("Připraveno"))
        self._entropy_var = tk.StringVar(
            value=self._tr(
                "Doplňkové časování: 0 událostí • aktivně použito jako bonusová diverzifikace"
            )
        )
        self._health_var = tk.StringVar(value=self._tr("Systémový zdroj: v pořádku"))
        self._last_motion_ns = 0
        self._active_tab = "numbers"
        self._tab_buttons: dict[str, tk.Button] = {}
        self._tab_panels: dict[str, tk.Frame] = {}
        self._mode_cards: dict[str, tk.Frame] = {}
        self._meter_bars: list[tk.Frame] = []

        self._configure_ttk()
        self.page = ScrollablePage(root)
        self.page.pack(fill="both", expand=True)
        self.main = tk.Frame(self.page.content, bg=BG, padx=22, pady=20)
        self.main.pack(fill="both", expand=True)

        self._build_ui()
        self._bind_entropy_events()
        self._update_quality()
        self._refresh_health()

    @staticmethod
    def _settings_path() -> Path:
        if os.name == "nt" and os.environ.get("APPDATA"):
            base = Path(os.environ["APPDATA"])
        elif os.environ.get("XDG_CONFIG_HOME"):
            base = Path(os.environ["XDG_CONFIG_HOME"])
        else:
            base = Path.home() / ".config"
        return base / "EntropyForge" / "settings.json"

    @classmethod
    def _load_language_preference(cls) -> str:
        try:
            value = json.loads(cls._settings_path().read_text(encoding="utf-8"))
            language = value.get("language") if isinstance(value, dict) else None
            return language if language in LANGUAGE_NAMES else "cs"
        except (OSError, UnicodeError, json.JSONDecodeError):
            return "cs"

    def _save_language_preference(self) -> None:
        try:
            path = self._settings_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {"language": self.language_code},
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
        except OSError:
            # A read-only or locked profile must not prevent RNG operation.
            pass

    def _tr(self, text: object) -> str:
        return translate_text(text, self.language_code)

    def _register_translatable(self, widget: tk.Misc, source_text: str) -> tk.Misc:
        if source_text:
            self._translatable_widgets.append((widget, source_text))
        return widget

    def _configure_ttk(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Dark.Vertical.TScrollbar",
            background=PANEL_2,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=TEXT,
            lightcolor=PANEL_2,
            darkcolor=PANEL_2,
        )
        style.configure(
            "Dark.TCombobox",
            fieldbackground=PANEL_DARK,
            background=PANEL_2,
            foreground=TEXT,
            arrowcolor=TEXT,
            bordercolor=LINE,
            lightcolor=LINE,
            darkcolor=LINE,
            padding=7,
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", PANEL_DARK)],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", PANEL_DARK)],
            selectforeground=[("readonly", TEXT)],
        )

    def _label(self, parent: tk.Misc, text: str, *, size: int = 10, bold: bool = False,
               color: str = TEXT, wrap: int | None = None, justify: str = "left") -> tk.Label:
        label = tk.Label(
            parent,
            text=self._tr(text),
            bg=parent.cget("bg"),
            fg=color,
            font=("Segoe UI", size, "bold" if bold else "normal"),
            wraplength=wrap or 0,
            justify=justify,
            anchor="w",
        )
        self._register_translatable(label, text)
        return label

    def _button(self, parent: tk.Misc, text: str, command: Callable[[], None], *, primary: bool = False,
                danger: bool = False, width: int | None = None) -> tk.Button:
        bg = ACCENT if primary else PANEL_2
        fg = "#07131d" if primary else ("#ffc5cc" if danger else TEXT)
        active_bg = ACCENT_2 if primary else "#203147"
        button = tk.Button(
            parent,
            text=self._tr(text),
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground="#07131d" if primary else TEXT,
            relief="flat",
            bd=0,
            padx=13,
            pady=9,
            font=("Segoe UI", 10, "bold" if primary else "normal"),
            cursor="hand2",
            width=width,
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=ACCENT,
        )
        self._register_translatable(button, text)
        return button

    @staticmethod
    def _entry(parent: tk.Misc, variable: tk.StringVar, width: int = 16) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            width=width,
            bg=PANEL_DARK,
            fg=TEXT,
            disabledbackground="#0b121b",
            disabledforeground=MUTED,
            insertbackground=TEXT,
            selectbackground="#284b67",
            selectforeground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=ACCENT,
            font=("Segoe UI", 10),
        )

    def _check(self, parent: tk.Misc, text: str, variable: tk.BooleanVar) -> tk.Checkbutton:
        check = tk.Checkbutton(
            parent,
            text=self._tr(text),
            variable=variable,
            bg=parent.cget("bg"),
            fg=MUTED,
            activebackground=parent.cget("bg"),
            activeforeground=TEXT,
            selectcolor=PANEL_DARK,
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        self._register_translatable(check, text)
        return check

    @staticmethod
    def _card(parent: tk.Misc, *, bg: str = PANEL, padx: int = 16, pady: int = 16) -> tk.Frame:
        return tk.Frame(
            parent,
            bg=bg,
            padx=padx,
            pady=pady,
            highlightthickness=1,
            highlightbackground=LINE,
            bd=0,
        )

    def _build_ui(self) -> None:
        self._build_header()
        self._build_notice()
        self._build_tabs()
        self._build_numbers_tab()
        self._build_choices_tab()
        self._build_passwords_tab()
        self._build_tokens_tab()
        self._build_quality_tab()
        self._build_info_tab()
        self._show_tab("numbers")
        self._build_statusbar()

    def _build_header(self) -> None:
        top = tk.Frame(self.main, bg=BG)
        top.pack(fill="x")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=2, minsize=330)

        brand = tk.Frame(top, bg=BG, padx=2, pady=8)
        brand.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        title_row = tk.Frame(brand, bg=BG)
        title_row.pack(fill="x")
        self._label(
            title_row,
            f"EntropyForge {APP_VERSION}",
            size=28,
            bold=True,
        ).pack(side="left", anchor="w")
        language_box = tk.Frame(title_row, bg=BG)
        language_box.pack(side="right", anchor="ne", padx=(12, 0))
        self._label(language_box, "Jazyk", size=8, color=MUTED).pack(
            anchor="w",
            pady=(0, 4),
        )
        self.language_var = tk.StringVar(value=LANGUAGE_NAMES[self.language_code])
        self.language_combo = ttk.Combobox(
            language_box,
            textvariable=self.language_var,
            values=tuple(LANGUAGE_NAMES.values()),
            state="readonly",
            width=10,
            style="Dark.TCombobox",
        )
        self.language_combo.pack(fill="x")
        self.language_combo.bind("<<ComboboxSelected>>", self._on_language_changed)
        self._label(
            brand,
            "Offline generátor s kryptografickým zdrojem systému, bezpečným "
            "vícezdrojovým vrstvením a odděleným přísným profilem Windows CNG. "
            "Žádná telemetrie, žádná síť v generátoru.",
            size=10,
            color=MUTED,
            wrap=650,
        ).pack(anchor="w", pady=(5, 10))
        chips = tk.Frame(brand, bg=BG)
        chips.pack(anchor="w", fill="x")
        for text in (
            "os.urandom",
            "Windows CNG",
            "HMAC-SHA-512",
            "bez modulo zkreslení",
            "offline generátor",
            "více externích zdrojů",
        ):
            chip = tk.Label(
                chips,
                text=self._tr(text),
                bg="#0b1420",
                fg=MUTED,
                font=("Segoe UI", 8),
                padx=8,
                pady=4,
                highlightthickness=1,
                highlightbackground=LINE,
            )
            self._register_translatable(chip, text)
            chip.pack(side="left", padx=(0, 6), pady=2)

        quality = self._card(top, bg="#122033", padx=16, pady=15)
        quality.grid(row=0, column=1, sticky="nsew")
        head = tk.Frame(quality, bg=quality.cget("bg"))
        head.pack(fill="x")
        left = tk.Frame(head, bg=head.cget("bg"))
        left.pack(side="left", fill="x", expand=True)
        self._label(left, "Bezpečnostní stav", size=8, color=MUTED).pack(anchor="w")
        self.quality_name = self._label(left, "Kryptograficky bezpečný • diverzifikovaný", size=15, bold=True, wrap=250)
        self.quality_name.pack(anchor="w", pady=(1, 0))
        self.quality_badge = tk.Label(
            head,
            text=self._tr("DIVERZIFIKOVANÝ"),
            bg=ACCENT_2,
            fg="#07150e",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
            width=17,
            height=2,
            anchor="center",
            justify="center",
        )
        self._register_translatable(self.quality_badge, "DIVERZIFIKOVANÝ")
        self.quality_badge.pack(side="right", anchor="n")

        meter_row = tk.Frame(quality, bg=quality.cget("bg"))
        meter_row.pack(fill="x", pady=(12, 8))
        meter = tk.Frame(meter_row, bg=quality.cget("bg"))
        meter.pack(side="left", fill="x", expand=True)
        for index in range(3):
            meter.columnconfigure(index, weight=1)
            bar = tk.Frame(meter, bg="#26364a", height=8)
            bar.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 3, 0 if index == 2 else 3))
            bar.grid_propagate(False)
            self._meter_bars.append(bar)
        self.quality_level_text = self._label(meter_row, "VRSTVY: 2/3", size=8, bold=True, color=MUTED)
        self.quality_level_text.pack(side="right", padx=(10, 0))

        self.quality_desc = self._label(
            quality,
            "Dvě ze tří vrstev diverzifikace. Čerstvý systémový CSPRNG zůstává garantovaným základem.",
            size=9,
            color=MUTED,
            wrap=340,
        )
        self.quality_desc.pack(fill="x")
        sep = tk.Frame(quality, bg=LINE, height=1)
        sep.pack(fill="x", pady=(10, 8))
        source = tk.Frame(quality, bg=quality.cget("bg"))
        source.pack(fill="x")
        self._label(source, "Aktivní zdroj", size=8, color=MUTED).pack(side="left")
        self.active_engine = self._label(source, "Diverzifikovaný software", size=8, bold=True)
        self.active_engine.pack(side="right")

    def _build_notice(self) -> None:
        notice = self._card(self.main, bg="#0d1724", padx=13, pady=10)
        notice.pack(fill="x", pady=(17, 10))
        self._label(
            notice,
            "Nemusíš nic nastavovat. Automatický režim vždy zachová čerstvý systémový CSPRNG a bezpečně přimíchá "
            "dostupné doplňkové zdroje. Přísný Windows profil je samostatný, "
            "nepoužívá vlastní směšovač a nikdy se nezaměňuje za certifikát celé aplikace.",
            size=9,
            color="#c9daee",
            wrap=1000,
        ).pack(fill="x")

    def _build_tabs(self) -> None:
        bar = tk.Frame(self.main, bg=BG)
        bar.pack(fill="x", pady=(4, 10))
        tabs = (
            ("numbers", "Čísla"),
            ("choices", "Losování"),
            ("passwords", "Hesla"),
            ("tokens", "Tokeny"),
            ("quality", "Zdroje a diagnostika"),
            ("info", "Jak to funguje"),
        )
        for key, title in tabs:
            button = self._button(bar, title, lambda k=key: self._show_tab(k))
            button.pack(side="left", padx=(0, 7), pady=3)
            self._tab_buttons[key] = button

        self.panel_host = tk.Frame(self.main, bg=BG)
        self.panel_host.pack(fill="both", expand=True)

    def _new_panel(self, key: str) -> tk.Frame:
        panel = self._card(self.panel_host, bg=PANEL, padx=18, pady=18)
        self._tab_panels[key] = panel
        return panel

    def _show_tab(self, key: str) -> None:
        self._active_tab = key
        for panel in self._tab_panels.values():
            panel.pack_forget()
        self._tab_panels[key].pack(fill="both", expand=True)
        for tab_key, button in self._tab_buttons.items():
            active = tab_key == key
            button.configure(
                bg=ACCENT if active else PANEL,
                fg="#07131d" if active else TEXT,
                activebackground=ACCENT_2 if active else "#203147",
                font=("Segoe UI", 10, "bold" if active else "normal"),
            )
        self.page.canvas.yview_moveto(0)

    def _field(self, parent: tk.Misc, label: str, default: str, width: int = 16) -> tuple[tk.Frame, tk.StringVar]:
        frame = tk.Frame(parent, bg=parent.cget("bg"))
        self._label(frame, label, size=8, color=MUTED).pack(anchor="w", pady=(0, 5))
        variable = tk.StringVar(value=default)
        entry = self._entry(frame, variable, width)
        entry.pack(fill="x", ipady=7)
        return frame, variable

    def _output_area(self, parent: tk.Misc, height: int = 12) -> tk.Text:
        wrapper = tk.Frame(parent, bg=parent.cget("bg"))
        wrapper.pack(fill="both", expand=True, pady=(14, 0))
        text = tk.Text(
            wrapper,
            height=height,
            wrap="word",
            bg=OUTPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground="#284b67",
            selectforeground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=ACCENT,
            padx=12,
            pady=11,
            font=("Consolas", 10),
            undo=False,
        )
        scroll = ttk.Scrollbar(wrapper, orient="vertical", command=text.yview, style="Dark.Vertical.TScrollbar")
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return text

    def _output_actions(self, parent: tk.Misc, widget: tk.Text) -> None:
        row = tk.Frame(parent, bg=parent.cget("bg"))
        row.pack(fill="x", pady=(9, 0))
        self._button(row, "Kopírovat", lambda: self._copy(widget)).pack(side="left", padx=(0, 7))
        self._button(row, "Uložit TXT", lambda: self._save(widget)).pack(side="left", padx=(0, 7))
        self._button(row, "Vymazat", lambda: self._clear_output(widget)).pack(side="left")

    def _build_numbers_tab(self) -> None:
        panel = self._new_panel("numbers")
        self._label(panel, "Náhodná čísla", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        controls = tk.Frame(panel, bg=panel.cget("bg"))
        controls.pack(fill="x")
        f1, self.min_var = self._field(controls, "Minimum včetně", "1")
        f2, self.max_var = self._field(controls, "Maximum včetně", "100")
        f3, self.number_count_var = self._field(controls, "Počet čísel", "1")
        for frame in (f1, f2, f3):
            frame.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.unique_numbers_var = tk.BooleanVar(value=False)
        self._check(controls, "Bez opakování", self.unique_numbers_var).pack(side="left", padx=8, pady=(20, 0))
        self._button(controls, "Generovat", self._generate_numbers, primary=True).pack(side="right", pady=(17, 0))
        self._label(
            panel,
            f"Podporuje celá čísla až do {MAX_INTEGER_DIGITS} číslic; celkový výstup je bezpečně omezen.",
            size=8,
            color=MUTED,
        ).pack(anchor="w", pady=(8, 0))
        self.number_output = self._output_area(panel)
        self._output_actions(panel, self.number_output)

    def _build_choices_tab(self) -> None:
        panel = self._new_panel("choices")
        self._label(panel, "Losování možností", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        self._label(panel, "Jedna možnost na řádek", size=8, color=MUTED).pack(anchor="w", pady=(0, 5))
        self.choice_input = tk.Text(
            panel,
            height=8,
            wrap="word",
            bg=PANEL_DARK,
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground="#284b67",
            selectforeground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=ACCENT,
            padx=10,
            pady=9,
            font=("Segoe UI", 10),
        )
        self.choice_input.pack(fill="x")
        self.choice_input.insert("1.0", self._tr("Kámen\nNůžky\nPapír"))
        self._default_choice_language = self.language_code
        controls = tk.Frame(panel, bg=panel.cget("bg"))
        controls.pack(fill="x", pady=(12, 0))
        field, self.choice_count_var = self._field(controls, "Počet výběrů", "1")
        field.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.unique_choices_var = tk.BooleanVar(value=False)
        self._check(controls, "Bez opakování", self.unique_choices_var).pack(side="left", padx=8, pady=(20, 0))
        self._button(controls, "Losovat", self._generate_choices, primary=True).pack(side="right", pady=(17, 0))
        self._label(
            panel,
            "V režimu bez opakování se shodné řádky sloučí. S opakováním mohou duplicity sloužit jako váhy.",
            size=8,
            color=MUTED,
        ).pack(anchor="w", pady=(8, 0))
        self.choice_output = self._output_area(panel)
        self._output_actions(panel, self.choice_output)

    def _build_passwords_tab(self) -> None:
        panel = self._new_panel("passwords")
        self._label(panel, "Silná hesla", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        controls = tk.Frame(panel, bg=panel.cget("bg"))
        controls.pack(fill="x")
        f1, self.password_length_var = self._field(controls, "Délka hesla", "24")
        f2, self.password_count_var = self._field(controls, "Počet hesel", "1")
        f1.pack(side="left", fill="x", expand=True, padx=(0, 10))
        f2.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._button(controls, "Generovat", self._generate_passwords, primary=True).pack(side="right", pady=(17, 0))

        checks = tk.Frame(panel, bg=panel.cget("bg"))
        checks.pack(fill="x", pady=(13, 0))
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        for text, var in (
            ("malá písmena", self.lower_var),
            ("VELKÁ písmena", self.upper_var),
            ("číslice", self.digits_var),
            ("symboly", self.symbols_var),
        ):
            self._check(checks, text, var).pack(side="left", padx=(0, 13))
        self._label(
            panel,
            "Celé heslo se vybírá rovnoměrně. Nevyhovující kandidát se zahodí a vygeneruje znovu.",
            size=8,
            color=MUTED,
            wrap=900,
        ).pack(anchor="w", pady=(8, 0))
        self.password_output = self._output_area(panel)
        self._output_actions(panel, self.password_output)

    def _build_tokens_tab(self) -> None:
        panel = self._new_panel("tokens")
        self._label(panel, "Tokeny a identifikátory", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        controls = tk.Frame(panel, bg=panel.cget("bg"))
        controls.pack(fill="x")
        f1, self.byte_count_var = self._field(controls, "Počet bajtů", "32")
        self.byte_count_entry = next(child for child in f1.winfo_children() if isinstance(child, tk.Entry))
        self.token_byte_hint_var = tk.StringVar(
            value=self._tr("Platí pro Hex a Base64 URL.")
        )
        self._label(f1, "", size=8, color=MUTED).configure(textvariable=self.token_byte_hint_var)
        hint_label = f1.winfo_children()[-1]
        hint_label.pack(anchor="w", pady=(4, 0))
        f2, self.token_count_var = self._field(controls, "Počet výstupů", "1")
        f1.pack(side="left", fill="x", expand=True, padx=(0, 10))
        f2.pack(side="left", fill="x", expand=True, padx=(0, 10))
        format_frame = tk.Frame(controls, bg=controls.cget("bg"))
        self._label(format_frame, "Formát", size=8, color=MUTED).pack(anchor="w", pady=(0, 5))
        self.token_format_var = tk.StringVar(value="Hex")
        combo = ttk.Combobox(
            format_frame,
            textvariable=self.token_format_var,
            values=("Hex", "Base64 URL", "UUID v4"),
            state="readonly",
            width=16,
            style="Dark.TCombobox",
        )
        combo.pack(fill="x")
        combo.bind("<<ComboboxSelected>>", self._on_token_format_changed)
        self.token_format_combo = combo
        format_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._button(controls, "Generovat", self._generate_tokens, primary=True).pack(side="right", pady=(17, 0))
        self.token_output = self._output_area(panel)
        self._output_actions(panel, self.token_output)
        self._on_token_format_changed()

    def _build_quality_tab(self) -> None:
        panel = self._new_panel("quality")
        self._label(panel, "Zdroje a funkční diagnostika", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        cards = tk.Frame(panel, bg=panel.cget("bg"))
        cards.pack(fill="x")
        cards.columnconfigure((0, 1), weight=1)
        definitions = (
            (
                "validated",
                "Přísný Windows CNG profil",
                "Přímé BCryptGenRandom bez vlastního HMAC mixéru. Aktivuje se "
                "jen ve Windows se zapnutou systémovou FIPS zásadou.",
                "PŘÍMÉ CNG • NE CERTIFIKÁT APLIKACE",
            ),
            (
                "system",
                "Systémový CSPRNG",
                "Nejjednodušší auditovatelná varianta. Přímo používá kryptografický generátor operačního systému.",
                "KRYPTOGRAFICKY BEZPEČNÝ",
            ),
            (
                "hybrid",
                "Diverzifikovaný software",
                "Stejný systémový základ plus HMAC proud a časování událostí bez připsané entropické garance.",
                "STEJNÁ GARANCE + DIVERZITA",
            ),
            (
                "external",
                "Vícezdrojový režim",
                "Navíc vrství až osm souborů či vzdálených .efb balíčků. Žádný z nich nenahrazuje systémový základ.",
                "VYŽADUJE EXTERNÍ DATA",
            ),
        )
        for index, (key, title, description, tag) in enumerate(definitions):
            row_index, column = divmod(index, 2)
            card = self._card(cards, bg="#0a131e", padx=13, pady=13)
            card.grid(
                row=row_index,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 6, 6 if column == 0 else 0),
                pady=(0 if row_index == 0 else 6, 6 if row_index == 0 else 0),
            )
            self._label(card, title, size=11, bold=True).pack(anchor="w")
            self._label(card, description, size=8, color=MUTED, wrap=300).pack(anchor="w", fill="x", pady=(5, 8))
            tag_label = tk.Label(
                card,
                text=self._tr(tag),
                bg="#17273a",
                fg=TEXT,
                font=("Segoe UI", 8),
                padx=7,
                pady=3,
            )
            self._register_translatable(tag_label, tag)
            tag_label.pack(anchor="w")
            self._mode_cards[key] = card
            self._bind_mode_card(card, key)

        hardware = self._card(panel, bg="#09121c", padx=14, pady=14)
        hardware.pack(fill="x", pady=(15, 0))
        self._label(hardware, "Přidat další externí zdroj", size=11, bold=True).pack(anchor="w")
        self._label(
            hardware,
            "Lze postupně navrstvit až osm souborů z lokálního hardwaru i .efb balíčků vytvořených vzdáleným "
            "sběračem. Duplicitní zdroj se odmítne a původní bajty se po jednosměrném zpracování nedrží jako výstupní proud.",
            size=8,
            color=MUTED,
            wrap=950,
        ).pack(anchor="w", fill="x", pady=(5, 10))
        row = tk.Frame(hardware, bg=hardware.cget("bg"))
        row.pack(fill="x")
        format_field = tk.Frame(row, bg=row.cget("bg"))
        self._label(format_field, "Formát souboru", size=8, color=MUTED).pack(anchor="w", pady=(0, 5))
        self.external_format_values = self._localized_external_format_values()
        self.external_format_var = tk.StringVar(
            value=next(
                label
                for label, value in self.external_format_values.items()
                if value == "auto"
            )
        )
        self.external_format_combo = ttk.Combobox(
            format_field,
            textvariable=self.external_format_var,
            values=tuple(self.external_format_values),
            state="readonly",
            width=25,
            style="Dark.TCombobox",
        )
        self.external_format_combo.pack(fill="x")
        format_field.pack(side="left", padx=(0, 10))
        self._button(row, "Přidat soubor", self._load_external).pack(side="left", padx=(0, 8))
        self.remove_external_button = self._button(
            row,
            "Odebrat poslední",
            self._remove_last_external,
            danger=True,
        )
        self.remove_external_button.pack(side="left", padx=(0, 10))
        self.remove_external_button.configure(state="disabled")
        self.remove_all_external_button = self._button(
            row,
            "Odebrat vše",
            self._remove_external,
            danger=True,
        )
        self.remove_all_external_button.pack(side="left", padx=(0, 10))
        self.remove_all_external_button.configure(state="disabled")
        self.hardware_state = self._label(row, "Externí zdroj není připojen.", size=8, color=MUTED, wrap=470)
        self.hardware_state.pack(side="left", fill="x", expand=True)
        self._label(
            hardware,
            "Vzdálený balíček vytvoří samostatný nástroj remote_entropy_collector.py "
            "(ve Windows run_remote_collector.bat). Samotný generátor tak zůstává offline.",
            size=8,
            color=MUTED,
            wrap=950,
        ).pack(anchor="w", fill="x", pady=(9, 0))

        advanced = self._card(panel, bg="#0a121c", padx=14, pady=14)
        advanced.pack(fill="x", pady=(14, 0))
        self._label(advanced, "Pokročilé nastavení zdroje", size=11, bold=True).pack(anchor="w")
        advanced_row = tk.Frame(advanced, bg=advanced.cget("bg"))
        advanced_row.pack(fill="x", pady=(11, 0))
        mode_field = tk.Frame(advanced_row, bg=advanced_row.cget("bg"))
        self._label(mode_field, "Režim", size=8, color=MUTED).pack(anchor="w", pady=(0, 5))
        self.mode_values = self._localized_mode_values()
        self.mode_var = tk.StringVar(
            value=next(
                label
                for label, value in self.mode_values.items()
                if value == "auto"
            )
        )
        self.mode_combo = ttk.Combobox(
            mode_field,
            textvariable=self.mode_var,
            values=tuple(
                label
                for label, value in self.mode_values.items()
                if value not in {"external", "validated"}
                or (value == "validated" and self.engine.validated_ready)
            ),
            state="readonly",
            width=37,
            style="Dark.TCombobox",
        )
        self.mode_combo.pack(fill="x")
        self.mode_combo.bind("<<ComboboxSelected>>", self._on_mode_changed)
        mode_field.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._button(advanced_row, "Spustit funkční diagnostiku", self._self_test).pack(side="left", padx=(0, 8), pady=(17, 0))
        self._button(advanced_row, "Uložit technický report", self._export_report).pack(side="left", pady=(17, 0))
        self._label(
            advanced,
            "Automatický režim použije dostupné doplňkové zdroje. Přísný profil "
            "je záměrně oddělený: čte přímo Windows CNG, nepřimíchává časování "
            "ani externí data a při nesplnění podmínek selže bez náhradního režimu.",
            size=8,
            color=MUTED,
            wrap=900,
        ).pack(anchor="w", pady=(8, 0))

        self.test_report = tk.Text(
            panel,
            height=8,
            wrap="word",
            bg=OUTPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=LINE,
            padx=11,
            pady=10,
            font=("Consolas", 9),
        )
        self.test_report.pack(fill="x", pady=(13, 0))
        self.test_report.insert(
            "1.0",
            self._tr("Funkční diagnostika zatím nebyla spuštěna."),
        )
        self.test_report.configure(state="disabled")

    def _build_info_tab(self) -> None:
        panel = self._new_panel("info")
        self._label(panel, "Co je uvnitř", size=16, bold=True).pack(anchor="w", pady=(0, 13))
        grid = tk.Frame(panel, bg=panel.cget("bg"))
        grid.pack(fill="x")
        grid.columnconfigure((0, 1), weight=1)
        info = (
            (
                "Bezpečný základ",
                "Běžné režimy stojí na os.urandom(); přísný Windows profil "
                "volá přímo BCryptGenRandom se systémově preferovaným poskytovatelem.",
            ),
            ("Bez zkreslení", "Čísla v intervalu používají rejection sampling, nikoli jednoduché modulo."),
            ("Soukromí kláves", "Zpracovává se pouze časování události. Znak, keycode ani napsaný text se nesbírá."),
            ("Standardní promíchání", "Doplňkový proud používá doménově oddělený HMAC-SHA-512 a je XORován s čerstvým systémovým proudem."),
            (
                "Poctivé omezení",
                "Certifikace podkladového modulu Windows není certifikací "
                "EntropyForge. Časování ani statistika souboru nedostávají "
                "automatický odhad entropie.",
            ),
            (
                "Fail-closed profil",
                "Přísný režim se bez Windows CNG a zapnuté FIPS zásady "
                "neaktivuje a nikdy tiše nepřejde na jiný zdroj.",
            ),
            (
                "Oddělená síťová vrstva",
                "Generátor zůstává offline. Samostatný sběrač může vytvořit kontrolovaný .efb balíček z drand, NIST a volitelně RANDOM.ORG.",
            ),
        )
        for index, (title, description) in enumerate(info):
            block = self._card(grid, bg="#09121d", padx=13, pady=13)
            block.grid(row=index // 2, column=index % 2, sticky="nsew", padx=(0 if index % 2 == 0 else 6, 0 if index % 2 else 6), pady=6)
            self._label(block, title, size=10, bold=True).pack(anchor="w")
            self._label(block, description, size=8, color=MUTED, wrap=460).pack(anchor="w", fill="x", pady=(5, 0))

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.main, bg=BG)
        bar.pack(fill="x", pady=(11, 4))
        status = self._label(bar, "", size=8, color=MUTED)
        status.configure(textvariable=self._status_var)
        status.pack(side="left")
        entropy = self._label(bar, "", size=8, color=MUTED)
        entropy.configure(textvariable=self._entropy_var)
        entropy.pack(side="left", padx=18)
        health = self._label(bar, "", size=8, color=ACCENT_2)
        health.configure(textvariable=self._health_var)
        health.pack(side="right")

    def _localized_external_format_values(self) -> dict[str, str]:
        return {
            self._tr("Automaticky rozpoznat"): "auto",
            self._tr("Surová binární data"): "binary",
            self._tr("Hexadecimální text"): "hex",
            "Base64 / Base64 URL": "base64",
            self._tr("Desítkové bajty"): "decimal",
            self._tr("Textové bity"): "bits",
            "EntropyForge Remote Bundle (.efb)": "bundle",
        }

    def _localized_mode_values(self) -> dict[str, str]:
        return {
            self._tr("Automaticky, doporučeno"): "auto",
            self._tr("Přísný Windows CNG profil"): "validated",
            self._tr("Pouze systémový CSPRNG"): "system",
            self._tr("Diverzifikovaný software"): "hybrid",
            self._tr("Vícezdrojový s externími daty"): "external",
        }

    @staticmethod
    def _canonical_selection(mapping: dict[str, str], selected: str, fallback: str) -> str:
        return mapping.get(selected, fallback)

    def _on_language_changed(self, _event: tk.Event | None = None) -> None:
        selected = self.language_var.get()
        new_language = next(
            (
                code
                for code, display_name in LANGUAGE_NAMES.items()
                if display_name == selected
            ),
            self.language_code,
        )
        if new_language == self.language_code:
            return

        old_language = self.language_code
        requested_mode = self._canonical_selection(
            self.mode_values,
            self.mode_var.get(),
            self.engine.requested_mode,
        )
        external_format = self._canonical_selection(
            self.external_format_values,
            self.external_format_var.get(),
            "auto",
        )
        current_choices = self.choice_input.get("1.0", "end-1c")
        old_default_choices = translate_text("Kámen\nNůžky\nPapír", old_language)

        self.language_code = new_language
        self._save_language_preference()

        for widget, source_text in tuple(self._translatable_widgets):
            try:
                if widget.winfo_exists():
                    widget.configure(text=self._tr(source_text))
            except tk.TclError:
                continue

        self.mode_values = self._localized_mode_values()
        self.mode_var.set(self._mode_display_name(requested_mode))
        self._refresh_mode_choices()

        self.external_format_values = self._localized_external_format_values()
        self.external_format_combo.configure(
            values=tuple(self.external_format_values),
        )
        self.external_format_var.set(
            next(
                label
                for label, value in self.external_format_values.items()
                if value == external_format
            )
        )

        if current_choices == old_default_choices:
            self.choice_input.delete("1.0", "end")
            self.choice_input.insert(
                "1.0",
                self._tr("Kámen\nNůžky\nPapír"),
            )

        self._on_token_format_changed()
        self._render_hardware_state()
        self._render_diagnostic()
        self._update_quality()
        self._render_health()
        self._status_var.set(
            self._tr(
                "Jazyk přepnut na češtinu."
                if new_language == "cs"
                else "Jazyk přepnut na angličtinu."
            )
        )

    def _render_hardware_state(self) -> None:
        sources = self.engine.external_sources_info
        if not sources:
            text = "Externí zdroj není připojen."
        else:
            last = sources[-1]
            text = (
                f"Aktivní soubory/balíčky: {len(sources)} • poslední: "
                f"{last['name']} • {last['format']} • "
                f"{int(last['raw_size']):,} B soubor / "
                f"{int(last['decoded_size']):,} B zdrojových dat • "
                f"{int(last.get('component_count', 1))} komponent"
            ).replace(",", " ")
        self.hardware_state.configure(text=self._tr(text))
        state = "normal" if sources else "disabled"
        self.remove_external_button.configure(state=state)
        self.remove_all_external_button.configure(state=state)

    def _render_diagnostic(self) -> None:
        result = self._last_diagnostic
        if result is None:
            text = self._tr("Funkční diagnostika zatím nebyla spuštěna.")
        else:
            lines = [
                f"Funkční diagnostika: {'PROŠLA' if result['ok'] else 'VAROVÁNÍ'}",
                f"Režim: {self._mode_label(str(result['mode']))}",
                f"Vzorek: {int(result['sample_size']):,} bajtů".replace(",", " "),
                f"Podíl jedniček: {float(result['ones_ratio']) * 100:.3f} %",
                f"Chí-kvadrát bajtů: {float(result['chi_square']):.2f}",
                f"Duplicitní 64B bloky: {int(result['duplicated_blocks'])}",
                "Rozsah: funkční smoke test; neověřuje nepředvídatelnost ani fyzickou entropii.",
            ]
            text = self._tr("\n".join(lines))
        self.test_report.configure(state="normal")
        self.test_report.delete("1.0", "end")
        self.test_report.insert("1.0", text)
        self.test_report.configure(state="disabled")

    def _bind_entropy_events(self) -> None:
        self.root.bind_all("<Motion>", self._on_motion, add="+")
        self.root.bind_all("<ButtonPress>", self._on_button, add="+")
        self.root.bind_all("<KeyPress>", self._on_key, add="+")
        self.root.bind_all("<MouseWheel>", self._on_wheel, add="+")
        self.root.bind_all("<Button-4>", self._on_linux_wheel_up, add="+")
        self.root.bind_all("<Button-5>", self._on_linux_wheel_down, add="+")

    def _on_motion(self, _event: tk.Event) -> None:
        now = time.perf_counter_ns()
        if now - self._last_motion_ns >= 10_000_000:
            self._last_motion_ns = now
            self.engine.add_timing_event("pointer")
            self._update_entropy_text()

    def _on_button(self, _event: tk.Event) -> None:
        self.engine.add_timing_event("click")
        self._update_entropy_text()

    def _on_key(self, _event: tk.Event) -> None:
        self.engine.add_timing_event("key")
        self._update_entropy_text()

    def _widget_is_scrollable_text(self, widget: tk.Misc | None) -> bool:
        return isinstance(widget, (tk.Text, tk.Listbox))

    def _on_wheel(self, event: tk.Event) -> None:
        self.engine.add_timing_event("wheel")
        self._update_entropy_text()
        widget = self.root.winfo_containing(event.x_root, event.y_root)
        if self._widget_is_scrollable_text(widget):
            return
        delta = -1 if event.delta > 0 else 1
        self.page.scroll_units(delta * 3)

    def _on_linux_wheel_up(self, event: tk.Event) -> None:
        self.engine.add_timing_event("wheel")
        self._update_entropy_text()
        widget = self.root.winfo_containing(event.x_root, event.y_root)
        if not self._widget_is_scrollable_text(widget):
            self.page.scroll_units(-3)

    def _on_linux_wheel_down(self, event: tk.Event) -> None:
        self.engine.add_timing_event("wheel")
        self._update_entropy_text()
        widget = self.root.winfo_containing(event.x_root, event.y_root)
        if not self._widget_is_scrollable_text(widget):
            self.page.scroll_units(3)

    def _update_entropy_text(self) -> None:
        mode = self.engine.effective_mode
        count = self.engine.event_count
        if mode in {"system", "validated"}:
            text = f"Doplňkové časování: nepoužívá se ({count} zaznamenaných událostí)"
        else:
            text = (
                f"Doplňkové časování: {count} událostí "
                "• aktivně použito jako bonusová diverzifikace"
            )
        self._entropy_var.set(self._tr(text))

    def _mode_label(self, mode: str) -> str:
        return self._tr({
            "validated": "Přísný Windows CNG profil",
            "system": "Systémový CSPRNG",
            "hybrid": "Diverzifikovaný software",
            "external": "Vícezdrojový režim",
        }[mode])

    def _update_quality(self) -> None:
        mode = self.engine.effective_mode
        diversity_level = DIVERSITY_LEVELS[mode]
        sources = self.engine.external_sources_info
        source_count = len(sources)
        component_count = sum(int(info.get("component_count", 1)) for info in sources)
        public_components = sum(int(info.get("public_components", 0)) for info in sources)
        provider_known_components = sum(
            int(info.get("provider_known_components", 0)) for info in sources
        )
        for index, bar in enumerate(self._meter_bars):
            bar.configure(bg=ACCENT_2 if index < diversity_level else "#26364a")

        if mode == "validated":
            strict = self.engine.validated_status
            evidence = str(strict.get("evidence_state", "unmatched"))
            name = "Kryptograficky bezpečný • přísný Windows profil"
            badge = "WINDOWS CNG\nPŘÍMÝ"
            evidence_text = (
                f" Offline podklad odpovídá {strict.get('certificate')}."
                if evidence == "matched-active"
                else " Přesnou certifikační shodu prostředí musí potvrdit laboratoř."
            )
            description = (
                "Jedna přímá vrstva: BCryptGenRandom se systémově preferovaným "
                "poskytovatelem. Vlastní HMAC, časování i externí data jsou "
                "z výstupní cesty vyřazeny."
                + evidence_text
            )
        elif mode == "system":
            name = "Kryptograficky bezpečný"
            badge = "SYSTÉMOVÝ\nCSPRNG"
            description = (
                "Jedna vrstva: přímý kryptografický generátor operačního systému. "
                "Nejmenší vlastní kód a nejsnazší audit."
            )
        elif mode == "external":
            name = "Kryptograficky bezpečný • vícezdrojový"
            source_word = (
                "ZDROJ"
                if component_count == 1
                else "ZDROJE"
                if 2 <= component_count <= 4
                else "ZDROJŮ"
            )
            badge = f"{component_count} EXTERNÍ\n{source_word}"
            provenance = (
                " Součástí je vzdálený fyzický zdroj známý poskytovateli."
                if provider_known_components
                else (
                    " Veřejné beacony zvyšují auditovatelnou diverzitu, ale nejsou tajnou entropií."
                    if public_components
                    else ""
                )
            )
            description = (
                f"Tři konstrukční vrstvy; aktivní soubory/balíčky: {source_count}, "
                f"samostatné externí komponenty: {component_count}. Systémový proud zůstává základem."
                + provenance
            )
        else:
            name = "Kryptograficky bezpečný • diverzifikovaný"
            badge = "DIVERZIFIKOVANÝ"
            description = (
                "Dvě vrstvy: čerstvý systémový proud a doménově oddělená HMAC diverzifikace s časováním. "
                "Formální garance zůstává stejná jako u systémového CSPRNG."
            )
        self.quality_name.configure(text=self._tr(name))
        self.quality_badge.configure(text=self._tr(badge))
        self.quality_desc.configure(text=self._tr(description))
        self.active_engine.configure(
            text=self._tr(
                f"{self._mode_label(mode)} "
                f"({component_count} "
                f"{'externí komponenta' if component_count == 1 else 'externí komponenty' if 2 <= component_count <= 4 else 'externích komponent'})"
                if mode == "external"
                else self._mode_label(mode)
            )
        )
        self.quality_level_text.configure(
            text=self._tr(
                "DIVERZITA: 1/3 • PŘÍMÝ PROFIL"
                if mode == "validated"
                else f"VRSTVY: {diversity_level}/3"
            )
        )

        for key, card in self._mode_cards.items():
            unavailable = (
                (key == "external" and self.engine.external_info is None)
                or (key == "validated" and not self.engine.validated_ready)
            )
            card.configure(
                highlightbackground=(
                    ACCENT if key == mode else "#6b5660" if unavailable else LINE
                ),
                highlightthickness=2 if key == mode else 1,
            )
        self._update_entropy_text()

    def _render_health(self) -> None:
        ok, message = self.engine.health
        if self.engine.effective_mode == "validated":
            self._health_var.set(
                self._tr("Windows CNG profil: v pořádku" if ok else message)
            )
        else:
            self._health_var.set(
                self._tr("Systémový zdroj: v pořádku" if ok else message)
            )

    def _refresh_health(self) -> None:
        self._render_health()
        self.root.after(1000, self._refresh_health)

    def _mode_display_name(self, mode: str) -> str:
        return next(label for label, value in self.mode_values.items() if value == mode)

    def _refresh_mode_choices(self) -> None:
        has_external = self.engine.external_info is not None
        has_validated = self.engine.validated_ready
        values = tuple(
            label
            for label, value in self.mode_values.items()
            if (
                value not in {"external", "validated"}
                or (value == "external" and has_external)
                or (value == "validated" and has_validated)
            )
        )
        self.mode_combo.configure(values=values)

    def _bind_mode_card(self, widget: tk.Misc, mode: str) -> None:
        widget.configure(cursor="hand2")
        widget.bind("<Button-1>", lambda _event, selected=mode: self._select_mode_card(selected), add="+")
        for child in widget.winfo_children():
            self._bind_mode_card(child, mode)

    def _select_mode_card(self, mode: str) -> None:
        if mode == "validated" and not self.engine.validated_ready:
            status = self.engine.validated_status
            issues = status.get("issues", [])
            detail = "\n\n".join(self._tr(issue) for issue in issues)
            self._status_var.set(self._tr("Přísný Windows profil není připraven"))
            messagebox.showinfo(
                APP_NAME,
                self._tr(status.get("summary", "Přísný profil není dostupný."))
                + (f"\n\n{detail}" if detail else "")
                + self._tr("\n\nAplikace nepřepnula na náhradní zdroj."),
            )
            return
        if mode == "external" and self.engine.external_info is None:
            self._status_var.set(self._tr("Nejdřív přidej externí zdroj"))
            messagebox.showinfo(
                APP_NAME,
                self._tr(
                    "Externí zdroj zatím není přidaný. Aktivní režim se nezměnil."
                ),
            )
            return
        self.mode_var.set(self._mode_display_name(mode))
        self._on_mode_changed()

    def _on_mode_changed(self, _event: tk.Event | None = None) -> None:
        mode = self.mode_values[self.mode_var.get()]
        if mode == "validated" and not self.engine.validated_ready:
            self.mode_var.set(self._mode_display_name("auto"))
            self.engine.set_mode("auto")
            messagebox.showinfo(
                APP_NAME,
                self._tr(
                    "Přísný Windows profil není připraven. Aktivní režim se "
                    "nezměnil a nebyl použit žádný náhradní zdroj."
                ),
            )
        elif mode == "external" and self.engine.external_info is None:
            self.mode_var.set(self._mode_display_name("auto"))
            self.engine.set_mode("auto")
            messagebox.showinfo(
                APP_NAME,
                self._tr(
                    "Externí zdroj zatím není přidaný. Aktivní zůstává diverzifikovaný režim."
                ),
            )
        else:
            self.engine.set_mode(mode)
        self._update_quality()
        self._status_var.set(
            self._tr(f"Aktivní režim: {self._mode_label(self.engine.effective_mode)}")
        )

    def _on_token_format_changed(self, _event: tk.Event | None = None) -> None:
        uuid_mode = self.token_format_var.get() == "UUID v4"
        self.byte_count_entry.configure(state="disabled" if uuid_mode else "normal")
        self.token_byte_hint_var.set(
            self._tr(
                "UUID v4 má vždy pevně 16 bajtů."
                if uuid_mode
                else "Platí pro Hex a Base64 URL."
            )
        )

    @staticmethod
    def _parse_int(value: str, name: str) -> int:
        text = value.strip()
        if not re.fullmatch(r"[+-]?[0-9]+", text):
            raise ValueError(f"{name} musí být celé číslo.")
        significant = text.lstrip("+-").lstrip("0") or "0"
        if len(significant) > MAX_INTEGER_DIGITS:
            raise ValueError(f"{name} může mít nejvýše {MAX_INTEGER_DIGITS} číslic.")
        return int(text)

    @staticmethod
    def _ensure_output_limit(estimated_characters: int) -> None:
        if estimated_characters > MAX_OUTPUT_CHARACTERS:
            raise ValueError(
                f"Požadovaný výstup je příliš velký. Limit je přibližně "
                f"{MAX_OUTPUT_CHARACTERS:,} znaků.".replace(",", " ")
            )

    def _run_action(self, label: str, action: Callable[[], None]) -> None:
        self._status_var.set(self._tr(label))
        self.root.update_idletasks()
        try:
            action()
            self._status_var.set(self._tr("Hotovo"))
        except Exception as exc:
            self._status_var.set(self._tr("Chyba"))
            messagebox.showerror(APP_NAME, self._tr(exc))

    @staticmethod
    def _set_output(widget: tk.Text, lines: Iterable[str]) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", "\n".join(lines))

    def _generate_numbers(self) -> None:
        def action() -> None:
            minimum = self._parse_int(self.min_var.get(), "Minimum")
            maximum = self._parse_int(self.max_var.get(), "Maximum")
            count = self._parse_int(self.number_count_var.get(), "Počet")
            if minimum > maximum:
                raise ValueError("Minimum nesmí být větší než maximum.")
            if not 1 <= count <= 100_000:
                raise ValueError("Počet musí být mezi 1 a 100 000.")
            span = maximum - minimum + 1
            estimated_digits = max(len(str(minimum)), len(str(maximum)))
            self._ensure_output_limit(count * (estimated_digits + 1))
            if self.unique_numbers_var.get():
                if count > span:
                    raise ValueError("Pro výběr bez opakování je interval příliš malý.")
                values = self.engine.sample_integer_range(minimum, maximum, count)
            else:
                values = [self.engine.randint(minimum, maximum) for _ in range(count)]
            self._set_output(self.number_output, map(str, values))

        self._run_action("Generuji čísla…", action)

    def _generate_choices(self) -> None:
        def action() -> None:
            items = [line.strip() for line in self.choice_input.get("1.0", "end").splitlines() if line.strip()]
            if not items:
                raise ValueError("Zadej alespoň jednu možnost.")
            count = self._parse_int(self.choice_count_var.get(), "Počet")
            if not 1 <= count <= 100_000:
                raise ValueError("Počet musí být mezi 1 a 100 000.")
            if self.unique_choices_var.get():
                items = list(dict.fromkeys(items))
                if count > len(items):
                    raise ValueError("Počet výběrů je větší než počet různých možností.")
                self._ensure_output_limit(count * (max(len(item) for item in items) + 1))
                selected = self.engine.sample(items, count)
            else:
                self._ensure_output_limit(count * (max(len(item) for item in items) + 1))
                selected = [self.engine.choice(items) for _ in range(count)]
            self._set_output(self.choice_output, selected)

        self._run_action("Losuji…", action)

    def _generate_passwords(self) -> None:
        def action() -> None:
            length = self._parse_int(self.password_length_var.get(), "Délka")
            count = self._parse_int(self.password_count_var.get(), "Počet")
            if not 4 <= length <= 4096:
                raise ValueError("Délka hesla musí být mezi 4 a 4096.")
            if not 1 <= count <= 5000:
                raise ValueError("Počet hesel musí být mezi 1 a 5000.")
            self._ensure_output_limit(count * (length + 1))
            groups: list[str] = []
            if self.lower_var.get():
                groups.append(LOWER)
            if self.upper_var.get():
                groups.append(UPPER)
            if self.digits_var.get():
                groups.append(DIGITS)
            if self.symbols_var.get():
                groups.append(SYMBOLS)
            if not groups:
                raise ValueError("Vyber alespoň jednu skupinu znaků.")
            if length < len(groups):
                raise ValueError("Heslo je kratší než počet vybraných skupin.")
            passwords = [self.engine.password(length, groups) for _ in range(count)]
            self._set_output(self.password_output, passwords)

        self._run_action("Generuji hesla…", action)

    def _generate_tokens(self) -> None:
        def action() -> None:
            fmt = self.token_format_var.get()
            count = self._parse_int(self.token_count_var.get(), "Počet výstupů")
            if not 1 <= count <= 10_000:
                raise ValueError("Počet výstupů musí být mezi 1 a 10 000.")
            nbytes = 16 if fmt == "UUID v4" else self._parse_int(self.byte_count_var.get(), "Počet bajtů")
            if fmt != "UUID v4" and not 1 <= nbytes <= 1_048_576:
                raise ValueError("Počet bajtů musí být mezi 1 a 1 048 576.")
            if fmt == "UUID v4":
                estimated_characters = count * 37
            elif fmt == "Base64 URL":
                estimated_characters = count * (((4 * nbytes + 2) // 3) + 1)
            else:
                estimated_characters = count * ((2 * nbytes) + 1)
            self._ensure_output_limit(estimated_characters)
            if fmt == "UUID v4":
                values = [self.engine.uuid4() for _ in range(count)]
            elif fmt == "Base64 URL":
                values = [self.engine.token_base64(nbytes) for _ in range(count)]
            else:
                values = [self.engine.token_hex(nbytes) for _ in range(count)]
            self._set_output(self.token_output, values)

        self._run_action("Generuji tokeny…", action)

    def _load_external(self) -> None:
        path = filedialog.askopenfilename(
            title=self._tr("Vybrat data z externího RNG"),
            filetypes=(
                ("EntropyForge bundle", "*.efb"),
                (self._tr("Všechny soubory"), "*.*"),
                (self._tr("Binární soubory"), "*.bin"),
                (self._tr("Textové soubory"), "*.txt"),
            ),
        )
        if not path:
            return

        def action() -> None:
            format_hint = self.external_format_values[self.external_format_var.get()]
            info = self.engine.load_external_file(path, format_hint)
            raw_size = int(info["raw_size"])
            decoded_size = int(info["decoded_size"])
            active_count = int(info["active_source_count"])
            component_count = int(info.get("component_count", 1))
            self.hardware_state.configure(
                text=self._tr(
                    (
                        f"Aktivní soubory/balíčky: {active_count} • poslední: {info['name']} • "
                        f"{info['format']} • {raw_size:,} B soubor / {decoded_size:,} B zdrojových dat • "
                        f"{component_count} komponent"
                    ).replace(",", " ")
                )
            )
            self.remove_external_button.configure(state="normal")
            self.remove_all_external_button.configure(state="normal")
            self._refresh_mode_choices()
            self._update_quality()

        self._run_action("Dekóduji a zpracovávám externí zdroj…", action)

    def _remove_last_external(self) -> None:
        requested_external = self.engine.requested_mode == "external"
        removed = self.engine.remove_last_external()
        if removed is None:
            return
        remaining = self.engine.external_source_count
        if requested_external and remaining == 0:
            self.engine.set_mode("auto")
            self.mode_var.set(self._mode_display_name("auto"))
        if remaining:
            last = self.engine.external_info
            assert last is not None
            self.hardware_state.configure(
                text=self._tr(
                    f"Aktivní soubory/balíčky: {remaining} • poslední: "
                    f"{last['name']} • {last['format']}"
                )
            )
        else:
            self.hardware_state.configure(
                text=self._tr("Externí zdroj není připojen.")
            )
        state = "normal" if remaining else "disabled"
        self.remove_external_button.configure(state=state)
        self.remove_all_external_button.configure(state=state)
        self._refresh_mode_choices()
        self._update_quality()
        self._status_var.set(
            self._tr(f"Odebrán externí zdroj: {removed['name']}")
        )

    def _remove_external(self) -> None:
        requested_external = self.engine.requested_mode == "external"
        self.engine.remove_external()
        if requested_external:
            self.engine.set_mode("auto")
            self.mode_var.set(self._mode_display_name("auto"))
        self.hardware_state.configure(
            text=self._tr("Externí zdroj není připojen.")
        )
        self.remove_external_button.configure(state="disabled")
        self.remove_all_external_button.configure(state="disabled")
        self._refresh_mode_choices()
        self._update_quality()
        self._status_var.set(self._tr("Externí zdroj odebrán"))

    def _self_test(self) -> None:
        def action() -> None:
            result = self.engine.diagnostics()
            self._last_diagnostic = dict(result)
            self._render_diagnostic()

        self._run_action("Spouštím funkční diagnostiku…", action)

    def _technical_report(self) -> str:
        sources = self.engine.external_sources_info
        strict = self.engine.validated_status
        lines = [
            f"EntropyForge {APP_VERSION} – technický report",
            f"Čas: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
            f"Požadovaný režim: {self.engine.requested_mode}",
            f"Aktivní režim: {self.engine.effective_mode}",
            f"Lokální časovací události: {self.engine.event_count}",
            f"Externí soubory/balíčky: {len(sources)}",
            f"Externí komponenty celkem: {sum(int(info.get('component_count', 1)) for info in sources)}",
            f"Přísný Windows profil připraven: {self._tr('ano' if strict.get('ready') else 'ne')}",
            f"Windows FIPS zásada: {strict.get('fips_policy_enabled')}",
            f"Stav certifikačních podkladů: {strict.get('evidence_state')}",
            f"Podkladový certifikát: {strict.get('certificate') or 'nespárován'}",
            f"Omezení tvrzení: {strict.get('claim_limit')}",
        ]
        for index, info in enumerate(sources, start=1):
            lines.extend(
                [
                    f"Externí zdroj {index}: {info['name']} ({info['raw_size']} B)",
                    f"  Zdrojová data: {info['decoded_size']} B",
                    f"  Kanonický otisk SHA-256: {info['digest']}",
                    f"  Formát: {info['format']}",
                    f"  Komponenty: {info.get('component_count', 1)}",
                    (
                        f"  Vytvořeno UTC: {info['created_utc']}"
                        if info.get("created_utc")
                        else "  Vytvořeno UTC: neuvedeno"
                    ),
                    (
                        "  Deklarované komponenty: "
                        + ", ".join(str(label) for label in info.get("component_labels", ()))
                        if info.get("component_labels")
                        else "  Deklarované komponenty: neuvedeny"
                    ),
                    f"  Jistota: {info['assurance']}",
                ]
            )
        lines.extend(
            [
                f"Python: {platform.python_version()}",
                f"Operační systém: {platform.platform()}",
                (
                    "Aktivní výstupní zdroj: přímé BCryptGenRandom "
                    "(BCRYPT_USE_SYSTEM_PREFERRED_RNG)"
                    if self.engine.effective_mode == "validated"
                    else "Aktivní výstupní základ: os.urandom()"
                ),
                (
                    "Doplňkový směšovač: vyřazen z přísného profilu"
                    if self.engine.effective_mode == "validated"
                    else "Doplňkový směšovač: HMAC-SHA-512, doménově oddělený"
                ),
                "Síťová komunikace generátoru: žádná",
                "Volitelná síťová komunikace: pouze samostatný remote_entropy_collector.py",
                (
                    "Poznámka: certifikace podkladového kryptografického modulu "
                    "není certifikací EntropyForge; diagnostika ani statistika "
                    "souboru nejsou certifikací fyzické náhodnosti."
                ),
            ]
        )
        return self._tr("\n".join(lines))

    def _export_report(self) -> None:
        path = filedialog.asksaveasfilename(
            title=self._tr("Uložit technický report"),
            defaultextension=".txt",
            initialfile="EntropyForge_report.txt",
            filetypes=(
                (self._tr("Textový soubor"), "*.txt"),
                (self._tr("Všechny soubory"), "*.*"),
            ),
        )
        if path:
            Path(path).write_text(self._technical_report(), encoding="utf-8", newline="\n")
            self._status_var.set(self._tr(f"Report uložen: {path}"))

    def _copy(self, widget: tk.Text) -> None:
        content = widget.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._status_var.set(self._tr("Zkopírováno do schránky"))

    def _save(self, widget: tk.Text) -> None:
        content = widget.get("1.0", "end-1c")
        path = filedialog.asksaveasfilename(
            title=self._tr("Uložit výstup"),
            defaultextension=".txt",
            initialfile="EntropyForge_output.txt",
            filetypes=(
                (self._tr("Textový soubor"), "*.txt"),
                (self._tr("Všechny soubory"), "*.*"),
            ),
        )
        if path:
            Path(path).write_text(content, encoding="utf-8", newline="\n")
            self._status_var.set(self._tr(f"Uloženo: {path}"))

    def _clear_output(self, widget: tk.Text) -> None:
        widget.delete("1.0", "end")
        self._status_var.set(self._tr("Výstup vymazán"))


def main() -> None:
    root = tk.Tk()
    EntropyForgeApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
