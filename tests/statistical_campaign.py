#!/usr/bin/env python3
"""Reproducible statistical smoke campaign for EntropyForge.

These checks can reveal gross implementation faults.  They do not prove
entropy, unpredictability, independence or certification.
"""

from __future__ import annotations

import collections
import json
import math
import sys
import tempfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from entropy_forge import EntropyEngine  # noqa: E402


SAMPLE_BYTES = 1024 * 1024
RANDBELOW_DRAWS = 200_000


try:
    from scipy.stats import chi2 as scipy_chi2
    from scipy.stats import t as scipy_t
except ImportError:
    scipy_chi2 = None
    scipy_t = None


BIT_COUNTS = tuple(value.bit_count() for value in range(256))


def chi_square_survival(value: float, degrees: int) -> float | None:
    if scipy_chi2 is None:
        return None
    return float(scipy_chi2.sf(value, degrees))


def analyze(sample: bytes) -> dict[str, float | int | None]:
    size = len(sample)
    frequencies = collections.Counter(sample)
    ones = sum(BIT_COUNTS[value] * count for value, count in frequencies.items())
    bit_count = size * 8
    zeros = bit_count - ones
    expected = size / 256
    byte_chi = sum(
        (frequencies.get(value, 0) - expected) ** 2 / expected
        for value in range(256)
    )
    monobit_p = math.erfc(abs(ones - zeros) / math.sqrt(2 * bit_count))

    previous = sample[0] >> 7
    runs = 1
    for value in sample:
        for shift in range(7, -1, -1):
            current = (value >> shift) & 1
            if current != previous:
                runs += 1
            previous = current
    proportion = ones / bit_count
    expected_runs = 2 * bit_count * proportion * (1 - proportion)
    denominator = (
        2
        * math.sqrt(2 * bit_count)
        * proportion
        * (1 - proportion)
    )
    runs_p = math.erfc(abs(runs - expected_runs) / denominator)

    count = size - 1
    mean_x = sum(sample[:-1]) / count
    mean_y = sum(sample[1:]) / count
    covariance = sum(
        (sample[index] - mean_x) * (sample[index + 1] - mean_y)
        for index in range(count)
    )
    variance_x = sum((value - mean_x) ** 2 for value in sample[:-1])
    variance_y = sum((value - mean_y) ** 2 for value in sample[1:])
    correlation = covariance / math.sqrt(variance_x * variance_y)
    if scipy_t is None:
        correlation_p = None
    else:
        statistic = correlation * math.sqrt(
            (count - 2) / max(1e-300, 1 - correlation * correlation)
        )
        correlation_p = float(2 * scipy_t.sf(abs(statistic), count - 2))

    entropy = -sum(
        (count_value / size) * math.log2(count_value / size)
        for count_value in frequencies.values()
    )
    blocks = {
        sample[offset : offset + 64]
        for offset in range(0, size, 64)
    }
    return {
        "sample_bytes": size,
        "ones_percent": ones * 100 / bit_count,
        "byte_chi_square": byte_chi,
        "byte_chi_square_p": chi_square_survival(byte_chi, 255),
        "monobit_p": monobit_p,
        "runs_p": runs_p,
        "lag1_correlation": correlation,
        "lag1_correlation_p": correlation_p,
        "shannon_bits_per_byte": entropy,
        "duplicate_64_byte_blocks": math.ceil(size / 64) - len(blocks),
    }


def interval_campaign(engine: EntropyEngine) -> dict[str, object]:
    counts = [0] * 10
    for _ in range(RANDBELOW_DRAWS):
        counts[engine.randbelow(10)] += 1
    expected = RANDBELOW_DRAWS / 10
    statistic = sum((count - expected) ** 2 / expected for count in counts)
    return {
        "draws": RANDBELOW_DRAWS,
        "counts": counts,
        "chi_square": statistic,
        "p": chi_square_survival(statistic, 9),
    }


def configure_external(engine: EntropyEngine) -> None:
    raw = bytes(range(256)) * 16
    with tempfile.NamedTemporaryFile() as handle:
        handle.write(raw)
        handle.flush()
        engine.load_external_file(handle.name, "binary")


def main() -> int:
    results: dict[str, object] = {
        "scope": (
            "Statistical smoke campaign only; not entropy estimation or "
            "certification."
        ),
        "sample_bytes_per_mode": SAMPLE_BYTES,
        "randbelow_draws_per_mode": RANDBELOW_DRAWS,
        "modes": {},
        "strict_windows_profile": (
            "Not exercised unless run on a configured Windows target; fake "
            "providers are intentionally excluded from statistical claims."
        ),
    }
    for mode in ("system", "hybrid", "external"):
        engine = EntropyEngine()
        if mode == "external":
            configure_external(engine)
        engine.set_mode(mode)
        diagnostics = [bool(engine.diagnostics()["ok"]) for _ in range(10)]
        results["modes"][mode] = {
            "sample": analyze(engine.bytes(SAMPLE_BYTES)),
            "randbelow_10": interval_campaign(engine),
            "diagnostics_passes": sum(diagnostics),
            "diagnostics_runs": len(diagnostics),
        }
    print(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
