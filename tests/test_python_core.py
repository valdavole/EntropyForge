#!/usr/bin/env python3
"""Reproducible unit tests for the EntropyForge 3.3 Python core."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import math
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_DIR = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_DIR / "entropy_forge.py"
sys.path.insert(0, str(PROJECT_DIR))
SPEC = importlib.util.spec_from_file_location("entropy_forge_tested", MODULE_PATH)
assert SPEC and SPEC.loader
entropy_forge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entropy_forge)

EntropyEngine = entropy_forge.EntropyEngine


class FakeStrictBackend:
    def __init__(self, ready: bool = True) -> None:
        self._ready = ready
        self.counter = 0

    @property
    def ready(self) -> bool:
        return self._ready

    def status(self) -> dict[str, object]:
        return {
            "ready": self._ready,
            "profile": "entropyforge.windows-cng.strict.v1",
            "summary": "test backend",
            "issues": [] if self._ready else ["not ready"],
            "evidence_state": "test",
            "claim_limit": "test only",
        }

    def generate(self, n: int) -> bytes:
        if not self._ready:
            raise entropy_forge.StrictProfileError("not ready")
        self.counter += 1
        return bytes((self.counter * 31 + index * 17) & 0xFF for index in range(n))


class EntropyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = EntropyEngine()

    def test_hmac_expansion_known_answer(self) -> None:
        expected = (
            "08eaa0e330e829a365a7c277861b8a9cdae058401243e6f7dcaa6d141ca8500f"
            "95c6f8578e20c5a391d344b0163b1c9c513acb0aff2aa6118eef60d983c0fe40"
            "a92e92e755df5169855f1786ba94f0fba6d4d10e727287c1bb1338e6df58abef"
        )
        actual = EntropyEngine._expand_hmac(bytes(range(64)), 96, b"stream|").hex()
        self.assertEqual(actual, expected)

    def test_bilingual_ui_translation_preserves_construction_version(self) -> None:
        self.assertEqual(entropy_forge.APP_VERSION, "3.3")
        self.assertEqual(entropy_forge.DOMAIN, b"EntropyForge-3.2|")
        self.assertEqual(
            entropy_forge.translate_text("Náhodná čísla", "en"),
            "Random numbers",
        )
        self.assertEqual(
            entropy_forge.translate_text(
                "Doplňkové časování: 17 událostí • aktivně použito jako bonusová diverzifikace",
                "en",
            ),
            "Supplementary timing: 17 events • actively used as bonus diversification",
        )
        self.assertEqual(
            entropy_forge.translate_text("Náhodná čísla", "cs"),
            "Náhodná čísla",
        )
        app = entropy_forge.EntropyForgeApp.__new__(entropy_forge.EntropyForgeApp)
        app.language_code = "en"
        self.assertEqual(
            app._localized_mode_values()["Automatic, recommended"],
            "auto",
        )
        self.assertEqual(
            app._localized_external_format_values()["Raw binary data"],
            "binary",
        )

    def test_random_bytes_in_every_mode(self) -> None:
        for mode in ("system", "hybrid"):
            with self.subTest(mode=mode):
                self.engine.set_mode(mode)
                first = self.engine.bytes(128)
                second = self.engine.bytes(128)
                self.assertEqual(len(first), 128)
                self.assertNotEqual(first, second)
                self.assertNotEqual(first, bytes(128))

    def test_validated_mode_uses_only_strict_backend(self) -> None:
        strict = FakeStrictBackend()
        engine = EntropyEngine(strict)
        engine.set_mode("validated")
        with mock.patch.object(
            entropy_forge.os,
            "urandom",
            side_effect=AssertionError("os.urandom must not be used in strict output"),
        ):
            first = engine.bytes(128)
            second = engine.bytes(128)
        self.assertEqual(len(first), 128)
        self.assertNotEqual(first, second)
        self.assertEqual(strict.counter, 2)

    def test_unavailable_validated_mode_never_falls_back(self) -> None:
        engine = EntropyEngine(FakeStrictBackend(ready=False))
        engine.set_mode("validated")
        self.assertEqual(engine.effective_mode, "validated")
        with self.assertRaisesRegex(entropy_forge.StrictProfileError, "not ready"):
            engine.bytes(32)

    def test_repeated_os_health_block_is_rejected(self) -> None:
        repeated = bytes([0xA5]) * 64
        self.engine._last_os_probe = repeated
        with mock.patch.object(entropy_forge.os, "urandom", return_value=repeated):
            with self.assertRaisesRegex(RuntimeError, "zopakoval"):
                self.engine.bytes(32)

    def test_randbelow_range_and_coverage(self) -> None:
        counts = [0] * 10
        for _ in range(5_000):
            value = self.engine.randbelow(10)
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, 10)
            counts[value] += 1
        self.assertTrue(all(counts))

    def test_unique_integer_sample_and_password_constraints(self) -> None:
        values = self.engine.sample_integer_range(-50, 50, 100)
        self.assertEqual(len(values), 100)
        self.assertEqual(len(set(values)), 100)
        self.assertTrue(all(-50 <= value <= 50 for value in values))

        groups = (
            entropy_forge.LOWER,
            entropy_forge.UPPER,
            entropy_forge.DIGITS,
            entropy_forge.SYMBOLS,
        )
        for _ in range(10):
            password = self.engine.password(24, groups)
            self.assertEqual(len(password), 24)
            self.assertTrue(all(any(character in group for character in password) for group in groups))

    def test_uuid_v4_and_token_formats(self) -> None:
        uuid_value = self.engine.uuid4()
        self.assertRegex(
            uuid_value,
            re.compile(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
        )
        self.assertEqual(len(bytes.fromhex(self.engine.token_hex(32))), 32)
        encoded = self.engine.token_base64(32)
        decoded = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        self.assertEqual(len(decoded), 32)

    def test_all_external_text_formats_round_trip(self) -> None:
        raw = bytes(range(256)) * 16
        representations = {
            "binary": (raw, "binary"),
            "hex": (raw.hex().encode("ascii"), "auto"),
            "base64-padded": (base64.urlsafe_b64encode(raw), "auto"),
            "base64-unpadded": (base64.urlsafe_b64encode(raw).rstrip(b"="), "auto"),
            "decimal": (" ".join(map(str, raw)).encode("ascii"), "auto"),
            "bits": ("".join(f"{value:08b}" for value in raw).encode("ascii"), "auto"),
        }
        for name, (encoded, hint) in representations.items():
            with self.subTest(format=name):
                decoded, _format_name = EntropyEngine._decode_text_entropy(encoded, hint)
                self.assertEqual(decoded, raw)

    def test_external_fingerprint_is_canonical(self) -> None:
        raw = bytes(range(256)) * 16
        expected = hashlib.sha256(raw).hexdigest()
        representations = (
            (raw, "binary"),
            (raw.hex().encode("ascii"), "auto"),
            (base64.urlsafe_b64encode(raw).rstrip(b"="), "auto"),
        )
        for encoded, hint in representations:
            with self.subTest(hint=hint):
                with tempfile.TemporaryDirectory() as directory:
                    source_path = Path(directory) / "external-source.bin"
                    source_path.write_bytes(encoded)
                    info = EntropyEngine().load_external_file(
                        str(source_path),
                        hint,
                    )
                self.assertEqual(info["decoded_size"], len(raw))
                self.assertEqual(info["digest"], expected)

    def test_too_small_base64_source_is_rejected_after_decoding(self) -> None:
        raw = bytes(range(256)) * 12
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "too-small-source.txt"
            source_path.write_bytes(encoded)
            with self.assertRaisesRegex(ValueError, "alespoň 4096"):
                self.engine.load_external_file(str(source_path), "auto")

    def test_degenerate_external_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "degenerovaný"):
            EntropyEngine._basic_external_test(bytes(4_096))

    def test_mode_fallback_and_external_activation(self) -> None:
        self.engine.set_mode("external")
        self.assertEqual(self.engine.effective_mode, "hybrid")
        raw = bytes(range(256)) * 16
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "external-source.bin"
            source_path.write_bytes(raw)
            self.engine.load_external_file(str(source_path), "binary")
        self.assertEqual(self.engine.effective_mode, "external")
        self.assertEqual(self.engine.external_source_count, 1)
        self.engine.remove_external()
        self.assertEqual(self.engine.effective_mode, "hybrid")
        self.assertEqual(self.engine.external_source_count, 0)

    def test_multiple_external_sources_stack_and_duplicates_are_rejected(self) -> None:
        first = bytes(range(256)) * 16
        second = bytes(reversed(range(256))) * 16
        with tempfile.TemporaryDirectory() as directory:
            paths: list[str] = []
            for raw in (first, second):
                source_path = Path(directory) / f"source-{len(paths)}.bin"
                source_path.write_bytes(raw)
                paths.append(str(source_path))
            first_info = self.engine.load_external_file(paths[0], "binary")
            second_info = self.engine.load_external_file(paths[1], "binary")
            self.assertEqual(first_info["active_source_count"], 1)
            self.assertEqual(second_info["active_source_count"], 2)
            self.assertEqual(self.engine.external_source_count, 2)
            with self.assertRaisesRegex(ValueError, "už byl"):
                self.engine.load_external_file(paths[0], "binary")
            removed = self.engine.remove_last_external()
            self.assertEqual(removed["digest"], hashlib.sha256(second).hexdigest())
            self.assertEqual(self.engine.external_source_count, 1)
            self.assertEqual(self.engine.effective_mode, "external")

    def test_external_source_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths: list[str] = []
            for offset in range(entropy_forge.MAX_EXTERNAL_SOURCES + 1):
                raw = bytes((value + offset) & 0xFF for value in range(4_096))
                source_path = Path(directory) / f"source-{offset}.bin"
                source_path.write_bytes(raw)
                paths.append(str(source_path))
            for source_path in paths[: entropy_forge.MAX_EXTERNAL_SOURCES]:
                self.engine.load_external_file(source_path, "binary")
            self.assertEqual(
                self.engine.external_source_count,
                entropy_forge.MAX_EXTERNAL_SOURCES,
            )
            with self.assertRaisesRegex(ValueError, "nejvýše 8"):
                self.engine.load_external_file(paths[-1], "binary")

    def test_integer_digit_limit_matches_html(self) -> None:
        parse = entropy_forge.EntropyForgeApp._parse_int
        self.assertEqual(parse("9" * 2_000, "Číslo"), int("9" * 2_000))
        with self.assertRaisesRegex(ValueError, "nejvýše 2000"):
            parse("9" * 2_001, "Číslo")

    def test_shared_limits_match_html_source(self) -> None:
        html = (PROJECT_DIR / "EntropyForge.html").read_text(encoding="utf-8")
        expected = {
            "MIN_EXTERNAL_BYTES": entropy_forge.MIN_EXTERNAL_BYTES,
            "MAX_EXTERNAL_FILE_BYTES": entropy_forge.MAX_EXTERNAL_FILE_BYTES,
            "MAX_EXTERNAL_SOURCES": entropy_forge.MAX_EXTERNAL_SOURCES,
            "MAX_OUTPUT_CHARACTERS": entropy_forge.MAX_OUTPUT_CHARACTERS,
            "MAX_INTEGER_DIGITS": entropy_forge.MAX_INTEGER_DIGITS,
        }
        for name, value in expected.items():
            with self.subTest(constant=name):
                match = re.search(rf"const {name} = ([0-9 *]+);", html)
                self.assertIsNotNone(match)
                html_value = math.prod(
                    int(part.strip()) for part in match.group(1).split("*")
                )
                self.assertEqual(html_value, value)

    def test_diversity_levels_are_explicit_and_ordered(self) -> None:
        self.assertEqual(
            entropy_forge.DIVERSITY_LEVELS,
            {"validated": 1, "system": 1, "hybrid": 2, "external": 3},
        )

    def test_html_csp_hash_matches_inline_script(self) -> None:
        html = (PROJECT_DIR / "EntropyForge.html").read_text(encoding="utf-8")
        script = re.search(r"<script>([\s\S]*?)</script>", html)
        self.assertIsNotNone(script)
        expected_hash = base64.b64encode(
            hashlib.sha256(script.group(1).encode("utf-8")).digest()
        ).decode("ascii")
        self.assertIn(f"script-src 'sha256-{expected_hash}'", html)
        self.assertNotIn("script-src 'unsafe-inline'", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
