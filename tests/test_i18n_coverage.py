#!/usr/bin/env python3
"""Static coverage checks for the Czech and English user interfaces."""

from __future__ import annotations

import ast
import json
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from entropy_forge import translate_text  # noqa: E402


CZECH_CHARACTERS = frozenset(
    "áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ"
)


def contains_czech(text: str) -> bool:
    return any(character in CZECH_CHARACTERS for character in text)


class VisibleHtmlTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.visible_text: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        _attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag in {"script", "style"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            text = data.strip()
            if text:
                self.visible_text.append(text)


class InternationalizationCoverageTests(unittest.TestCase):
    def test_python_static_widgets_have_english_text(self) -> None:
        source = (PROJECT_DIR / "entropy_forge.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        helper_argument = {"_label": 1, "_button": 1, "_check": 1}
        exempt = {
            "",
            "os.urandom",
            "Windows CNG",
            "HMAC-SHA-512",
            "Hex",
            "Base64 URL",
            "UUID v4",
            "EntropyForge Remote Bundle (.efb)",
        }
        missing: list[tuple[int, str]] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func,
                ast.Attribute,
            ):
                continue
            index = helper_argument.get(node.func.attr)
            if index is None or len(node.args) <= index:
                continue
            try:
                text = ast.literal_eval(node.args[index])
            except (ValueError, TypeError):
                continue
            if (
                isinstance(text, str)
                and text not in exempt
                and contains_czech(text)
                and translate_text(text, "en") == text
            ):
                missing.append((node.lineno, text))

        self.assertEqual(missing, [])

    def test_html_visible_czech_text_has_english_catalog_entry(self) -> None:
        html = (PROJECT_DIR / "EntropyForge.html").read_text(encoding="utf-8")
        match = re.search(
            r"const EN_TEXT = new Map\(\[\n(?P<body>[\s\S]*?)\n\]\);",
            html,
        )
        self.assertIsNotNone(match)
        assert match is not None

        entries = re.findall(
            r'^\s*\[("(?:\\.|[^"\\])*")\s*,',
            match.group("body"),
            flags=re.MULTILINE,
        )
        keys = [json.loads(entry) for entry in entries]
        self.assertEqual(len(keys), len(set(keys)), "Duplicate HTML translation keys")

        parser = VisibleHtmlTextParser()
        parser.feed(html)
        exempt = {
            "Čeština",
            "Kámen\nNůžky\nPapír",
        }
        missing = sorted(
            {
                text
                for text in parser.visible_text
                if contains_czech(text)
                and text not in exempt
                and text not in set(keys)
            }
        )
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
