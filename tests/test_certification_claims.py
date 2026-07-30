#!/usr/bin/env python3
"""Guardrails against accidentally turning evidence into a false claim."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent


class CertificationClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (PROJECT_DIR / "certification" / "validation_manifest.json").read_text(
                encoding="utf-8"
            )
        )

    def test_manifest_explicitly_says_product_is_not_certified(self) -> None:
        self.assertEqual(
            self.manifest["project"]["certification_status"],
            "not-certified",
        )
        self.assertFalse(self.manifest["target"]["product_certificate_issued"])
        self.assertFalse(self.manifest["target"]["laboratory_review_completed"])

    def test_embedded_windows_evidence_is_not_mislabeled_as_fips_140_3(self) -> None:
        evidence = self.manifest["embedded_evidence"][0]
        self.assertEqual(evidence["certificate"], "4825")
        self.assertEqual(evidence["standard"], "FIPS 140-2")
        self.assertIn("not an EntropyForge certificate", evidence["scope_limit"])
        self.assertFalse(
            self.manifest["fips_140_3_dependency"]["may_be_claimed_as_validated"]
        )

    def test_user_interfaces_display_claim_limit(self) -> None:
        readme = (PROJECT_DIR / "README.txt").read_text(encoding="utf-8")
        html = (PROJECT_DIR / "EntropyForge.html").read_text(encoding="utf-8")
        python_source = (PROJECT_DIR / "entropy_forge.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("EntropyForge NENÍ FIPS", readme)
        self.assertIn("NE CERTIFIKÁT APLIKACE", html)
        self.assertIn("NE CERTIFIKÁT APLIKACE", python_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
