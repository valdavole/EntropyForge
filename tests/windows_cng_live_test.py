#!/usr/bin/env python3
"""On-target live test for the real Windows CNG strict backend."""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from validated_backend import WindowsCNGBackend, human_status  # noqa: E402


SAMPLE_BYTES = 1024 * 1024


def main() -> int:
    backend = WindowsCNGBackend()
    status = backend.status()
    print(human_status(status))
    if not status.ready:
        print("\nLIVE TEST: NELZE SPUSTIT – profil není připraven.")
        return 2

    sample = backend.generate(SAMPLE_BYTES)
    frequencies = collections.Counter(sample)
    ones = sum(value.bit_count() for value in sample)
    expected = len(sample) / 256
    chi_square = sum(
        (frequencies.get(value, 0) - expected) ** 2 / expected
        for value in range(256)
    )
    blocks = {
        sample[offset : offset + 64]
        for offset in range(0, len(sample), 64)
    }
    result = {
        "scope": (
            "Live functional/statistical smoke test of Windows CNG; not "
            "certification or entropy estimation."
        ),
        "profile": status.profile,
        "sample_bytes": len(sample),
        "ones_percent": ones * 100 / (len(sample) * 8),
        "byte_chi_square": chi_square,
        "duplicate_64_byte_blocks": len(sample) // 64 - len(blocks),
        "fips_policy_enabled": status.fips_policy_enabled,
        "evidence_state": status.evidence_state,
        "certificate": status.certificate,
        "claim_limit": status.claim_limit,
    }
    print("\n" + json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    passed = (
        49.8 < result["ones_percent"] < 50.2
        and 100 < chi_square < 450
        and result["duplicate_64_byte_blocks"] == 0
    )
    print(f"\nLIVE TEST: {'PASS' if passed else 'VAROVÁNÍ'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
