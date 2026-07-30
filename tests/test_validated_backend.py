#!/usr/bin/env python3
"""Tests for the fail-closed Windows CNG profile."""

from __future__ import annotations

import ctypes
import sys
import unittest
from datetime import date
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from validated_backend import (  # noqa: E402
    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    StrictProfileError,
    WindowsCNGBackend,
)


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class FakeBCrypt:
    def __init__(self, *, fips: bool = True, generate_status: int = 0) -> None:
        self.fips = fips
        self.generate_status = generate_status
        self.counter = 0
        self.generate_calls = 0
        self.BCryptGetFipsAlgorithmMode = FakeFunction(self._get_fips)
        self.BCryptGenRandom = FakeFunction(self._generate)

    def _get_fips(self, output_pointer) -> int:
        output = ctypes.cast(output_pointer, ctypes.POINTER(ctypes.c_ubyte))
        output[0] = 1 if self.fips else 0
        return 0

    def _generate(self, handle, output, length, flags) -> int:
        self.generate_calls += 1
        if self.generate_status:
            return self.generate_status
        if handle is not None or flags != BCRYPT_USE_SYSTEM_PREFERRED_RNG:
            return -1
        for index in range(length):
            output[index] = (self.counter + index * 29 + 17) & 0xFF
        self.counter = (self.counter + length + 1) & 0xFFFFFFFF
        return 0


def backend(fake: FakeBCrypt, *, today: date = date(2026, 7, 30)) -> WindowsCNGBackend:
    return WindowsCNGBackend(
        bcrypt=fake,
        os_name="nt",
        os_version="10.0.22000",
        architecture="AMD64",
        today=today,
    )


class WindowsCNGBackendTests(unittest.TestCase):
    def test_ready_profile_matches_embedded_active_evidence(self) -> None:
        status = backend(FakeBCrypt()).status()
        self.assertTrue(status.ready)
        self.assertTrue(status.fips_policy_enabled)
        self.assertEqual(status.evidence_state, "matched-active")
        self.assertEqual(status.certificate, "CMVP #4825")
        self.assertIn("nikoli na EntropyForge", status.claim_limit)

    def test_generation_calls_system_preferred_rng_and_changes(self) -> None:
        fake = FakeBCrypt()
        source = backend(fake)
        first = source.generate(128)
        second = source.generate(128)
        self.assertEqual(len(first), 128)
        self.assertEqual(len(second), 128)
        self.assertNotEqual(first, second)
        self.assertEqual(fake.generate_calls, 4)  # probe + requested output per call

    def test_fips_policy_off_fails_without_generating(self) -> None:
        fake = FakeBCrypt(fips=False)
        source = backend(fake)
        self.assertFalse(source.ready)
        with self.assertRaisesRegex(StrictProfileError, "FIPS"):
            source.generate(32)
        self.assertEqual(fake.generate_calls, 0)

    def test_provider_failure_is_sticky_and_fail_closed(self) -> None:
        fake = FakeBCrypt(generate_status=-1073741811)
        source = backend(fake)
        with self.assertRaisesRegex(StrictProfileError, "0xC000000D"):
            source.generate(32)
        status = source.status()
        self.assertFalse(status.ready)
        self.assertTrue(any("BCryptGenRandom" in issue for issue in status.issues))

    def test_non_windows_runtime_is_unavailable(self) -> None:
        source = WindowsCNGBackend(
            os_name="posix",
            os_version="6.8",
            architecture="x86_64",
            today=date(2026, 7, 30),
        )
        status = source.status()
        self.assertFalse(status.available)
        self.assertFalse(status.ready)
        with self.assertRaises(StrictProfileError):
            source.generate(1)

    def test_sunset_is_reported_without_faking_application_certificate(self) -> None:
        status = backend(FakeBCrypt(), today=date(2026, 9, 22)).status()
        self.assertTrue(status.ready)
        self.assertEqual(status.evidence_state, "matched-sunset")
        self.assertTrue(any("sunset" in issue for issue in status.issues))


if __name__ == "__main__":
    unittest.main(verbosity=2)
