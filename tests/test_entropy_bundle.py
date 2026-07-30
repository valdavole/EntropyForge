#!/usr/bin/env python3
"""Tests for the portable EntropyForge remote-bundle format."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from entropy_bundle import (  # noqa: E402
    BUNDLE_SCHEMA,
    BundleError,
    build_bundle,
    canonical_json,
    make_source_record,
    parse_bundle,
)
from entropy_forge import EntropyEngine  # noqa: E402


EXPECTED_PORTABLE_BUNDLE_FINGERPRINT = (
    "24506993cbe7225548312fe1c174b4bfaca81e90c2ba137243cc1f47a4ab0b9a"
)


def public_source() -> dict[str, object]:
    return make_source_record(
        identifier="test.public",
        label="Test public beacon",
        kind="public_beacon",
        visibility="public",
        data=bytes(range(32)),
        validation=("HTTPS certificate validation", "Fixture proof checked"),
        metadata={"round": 123, "signature_hex": "ab" * 48},
    )


def provider_source() -> dict[str, object]:
    return make_source_record(
        identifier="test.remote",
        label="Test provider-known TRNG",
        kind="remote_trng",
        visibility="provider_known",
        data=bytes(range(256)) * 16,
        validation=("HTTPS certificate validation", "Signature verified"),
        metadata={"serial": 456},
    )


class BundleTests(unittest.TestCase):
    def test_round_trip_and_source_classification(self) -> None:
        raw = build_bundle(
            [public_source(), provider_source()],
            collector="EntropyForge test collector",
            created_utc="2026-07-29T12:34:56Z",
        )
        parsed = parse_bundle(raw)
        self.assertEqual(parsed.source_count, 2)
        self.assertEqual(parsed.public_count, 1)
        self.assertEqual(parsed.provider_known_count, 1)
        self.assertEqual(parsed.total_random_bytes, 32 + 4096)
        self.assertEqual(parsed.fingerprint, hashlib.sha256(parsed.payload_bytes).hexdigest())
        self.assertTrue(raw.endswith(b"\n"))

        invalid_date_source = public_source()
        with self.assertRaisesRegex(BundleError, "created_utc"):
            build_bundle(
                [invalid_date_source],
                collector="EntropyForge test collector",
                created_utc="2026-02-30T12:34:56Z",
            )

        nonportable_source = public_source()
        nonportable_source["metadata"] = {"unsafe_integer": 2**53}
        with self.assertRaisesRegex(BundleError, "bezpečný rozsah"):
            build_bundle(
                [nonportable_source],
                collector="EntropyForge test collector",
                created_utc="2026-07-29T12:34:56Z",
            )

        duplicate_data_source = public_source()
        duplicate_data_source["id"] = "test.same-data"
        duplicate_data_source["label"] = "Same data under another identity"
        with self.assertRaisesRegex(BundleError, "stejná náhodná data"):
            build_bundle(
                [public_source(), duplicate_data_source],
                collector="EntropyForge test collector",
                created_utc="2026-07-29T12:34:56Z",
            )

    def test_payload_tampering_is_rejected(self) -> None:
        raw = build_bundle(
            [public_source()],
            collector="EntropyForge test collector",
            created_utc="2026-07-29T12:34:56Z",
        )
        outer = json.loads(raw)
        payload = bytearray(base64.b64decode(outer["payload_base64"]))
        payload[-2] ^= 1
        outer["payload_base64"] = base64.b64encode(payload).decode("ascii")
        tampered = canonical_json(outer) + b"\n"
        with self.assertRaisesRegex(BundleError, "součet"):
            parse_bundle(tampered)

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = build_bundle(
            [public_source()],
            collector="EntropyForge test collector",
            created_utc="2026-07-29T12:34:56Z",
        )
        outer_text = raw.decode("utf-8").rstrip()
        duplicated = outer_text[:-1] + f',"schema":"{BUNDLE_SCHEMA}"' + "}\n"
        with self.assertRaisesRegex(BundleError, "Duplicitní"):
            parse_bundle(duplicated.encode("utf-8"))

    def test_degenerate_short_source_is_rejected(self) -> None:
        source = public_source()
        data = bytes(32)
        source["data_base64"] = base64.b64encode(data).decode("ascii")
        source["data_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(BundleError, "degenerovaná"):
            build_bundle(
                [source],
                collector="EntropyForge test collector",
                created_utc="2026-07-29T12:34:56Z",
            )

    def test_engine_auto_imports_small_public_bundle_and_rejects_replay(self) -> None:
        raw = build_bundle(
            [public_source()],
            collector="EntropyForge test collector",
            created_utc="2026-07-29T12:34:56Z",
        )
        self.assertEqual(
            parse_bundle(raw).fingerprint,
            EXPECTED_PORTABLE_BUNDLE_FINGERPRINT,
        )
        engine = EntropyEngine()
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = Path(directory) / "remote-entropy.efb"
            bundle_path.write_bytes(raw)
            info = engine.load_external_file(str(bundle_path), "auto")
            self.assertEqual(info["source_type"], "remote_bundle")
            self.assertEqual(info["component_count"], 1)
            self.assertEqual(info["decoded_size"], 32)
            self.assertEqual(engine.effective_mode, "external")
            with self.assertRaisesRegex(ValueError, "už byl"):
                engine.load_external_file(str(bundle_path), "bundle")
            engine.remove_external()
            with self.assertRaisesRegex(ValueError, "už byl"):
                engine.load_external_file(str(bundle_path), "bundle")


if __name__ == "__main__":
    unittest.main(verbosity=2)
