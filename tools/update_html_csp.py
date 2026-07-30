#!/usr/bin/env python3
"""Update or verify the SHA-256 CSP lock for EntropyForge.html."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_HTML = PROJECT_DIR / "EntropyForge.html"
SCRIPT_RE = re.compile(r"<script>([\s\S]*?)</script>")
CSP_RE = re.compile(r"(script-src 'sha256-)([^']+)(')")


def calculate_hash(document: str) -> str:
    scripts = SCRIPT_RE.findall(document)
    if len(scripts) != 1:
        raise ValueError(
            f"Očekáván je právě jeden vložený <script>, nalezeno: {len(scripts)}."
        )
    digest = hashlib.sha256(scripts[0].encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def current_hash(document: str) -> str:
    matches = CSP_RE.findall(document)
    if len(matches) != 1:
        raise ValueError(
            f"Očekáván je právě jeden CSP script hash, nalezeno: {len(matches)}."
        )
    return matches[0][1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Aktualizuje nebo ověří CSP hash vloženého JavaScriptu."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Pouze ověří shodu a soubor nezmění.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_HTML,
        help="Cesta k HTML souboru.",
    )
    args = parser.parse_args()

    path = args.file.resolve()
    try:
        document = path.read_text(encoding="utf-8")
        expected = calculate_hash(document)
        found = current_hash(document)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"CSP kontrola selhala: {error}", file=sys.stderr)
        return 2

    if found == expected:
        print(f"CSP hash je aktuální: sha256-{expected}")
        return 0

    if args.check:
        print("CSP hash neodpovídá vloženému JavaScriptu.", file=sys.stderr)
        print(f"V souboru: sha256-{found}", file=sys.stderr)
        print(f"Požadovaný: sha256-{expected}", file=sys.stderr)
        return 1

    updated, replacements = CSP_RE.subn(rf"\g<1>{expected}\g<3>", document, count=1)
    if replacements != 1:
        print("CSP hash se nepodařilo jednoznačně nahradit.", file=sys.stderr)
        return 2

    try:
        path.write_text(updated, encoding="utf-8", newline="\n")
    except OSError as error:
        print(f"HTML se nepodařilo uložit: {error}", file=sys.stderr)
        return 2

    print(f"CSP hash aktualizován: sha256-{expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
