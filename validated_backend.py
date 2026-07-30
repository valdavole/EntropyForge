#!/usr/bin/env python3
"""Strict Windows CNG backend for EntropyForge.

This module deliberately does not implement another DRBG.  In the strict
profile it calls the Windows system-preferred RNG directly through
BCryptGenRandom and refuses to operate unless Windows reports that FIPS mode is
enabled.  Any formal validation claim remains limited to the underlying
Microsoft module and its exact validated operational environment.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Any


BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
MAX_CNG_CALL_BYTES = 1024 * 1024
MAX_PROFILE_REQUEST_BYTES = 16 * 1024 * 1024

# This manifest is evidence metadata, not a certificate for EntropyForge.
# It is intentionally narrow and must be reviewed when NIST or Microsoft
# publishes a new validation.
WINDOWS_CNG_EVIDENCE = (
    {
        "certificate": "CMVP #4825",
        "standard": "FIPS 140-2 Level 1",
        "module": "Microsoft Windows Cryptographic Primitives Library",
        "software_versions": ("10.0.22000",),
        "validated_os": "Windows 11 64-bit",
        "validation_date": "2024-10-07",
        "sunset_date": "2026-09-21",
        "url": (
            "https://csrc.nist.gov/projects/"
            "cryptographic-module-validation-program/certificate/4825"
        ),
    },
)


class StrictProfileError(RuntimeError):
    """The strict Windows profile cannot safely produce output."""


@dataclass(frozen=True)
class StrictProfileStatus:
    profile: str
    available: bool
    ready: bool
    provider: str
    api: str
    os_name: str
    os_version: str
    architecture: str
    fips_policy_enabled: bool | None
    evidence_state: str
    certificate: str | None
    certificate_standard: str | None
    certificate_module: str | None
    certificate_sunset: str | None
    certificate_url: str | None
    checked_utc: str
    summary: str
    issues: tuple[str, ...]
    claim_limit: str

    def public_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["issues"] = list(self.issues)
        return value


def _runtime_windows_version() -> str:
    try:
        value = sys.getwindowsversion()
    except AttributeError:
        return platform.version()
    return f"{value.major}.{value.minor}.{value.build}"


def _format_ntstatus(status: int) -> str:
    return f"0x{int(status) & 0xFFFFFFFF:08X}"


class WindowsCNGBackend:
    """Direct, fail-closed wrapper around the Windows system-preferred RNG."""

    provider_name = "Microsoft Windows CNG"
    api_name = "BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)"

    def __init__(
        self,
        *,
        bcrypt: Any | None = None,
        os_name: str | None = None,
        os_version: str | None = None,
        architecture: str | None = None,
        today: date | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._last_probe: bytes | None = None
        self._fatal_error: str | None = None
        self._os_name = os.name if os_name is None else os_name
        self._os_version = (
            _runtime_windows_version() if os_version is None else os_version
        )
        self._architecture = (
            platform.machine() if architecture is None else architecture
        )
        self._today = datetime.now(timezone.utc).date() if today is None else today
        self._bcrypt = bcrypt
        self._load_error: str | None = None

        if self._bcrypt is None and self._os_name == "nt":
            try:
                self._bcrypt = ctypes.WinDLL("bcrypt.dll", use_last_error=True)
            except (AttributeError, OSError) as exc:
                self._load_error = f"bcrypt.dll nelze načíst: {exc}"

        self._gen_random = None
        self._get_fips_mode = None
        if self._bcrypt is not None:
            try:
                self._gen_random = self._bcrypt.BCryptGenRandom
                self._get_fips_mode = self._bcrypt.BCryptGetFipsAlgorithmMode
                self._configure_signatures()
            except AttributeError as exc:
                self._load_error = f"Windows CNG neposkytuje očekávané API: {exc}"
                self._gen_random = None
                self._get_fips_mode = None

    def _configure_signatures(self) -> None:
        assert self._gen_random is not None
        assert self._get_fips_mode is not None
        try:
            self._gen_random.argtypes = (
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_ubyte),
                ctypes.c_ulong,
                ctypes.c_ulong,
            )
            self._gen_random.restype = ctypes.c_long
            self._get_fips_mode.argtypes = (ctypes.POINTER(ctypes.c_ubyte),)
            self._get_fips_mode.restype = ctypes.c_long
        except (AttributeError, TypeError):
            # Small injected test doubles may not expose ctypes attributes.
            pass

    def _query_fips_mode(self) -> tuple[bool | None, str | None]:
        if self._get_fips_mode is None:
            return None, self._load_error or "BCryptGetFipsAlgorithmMode není dostupné."
        enabled = ctypes.c_ubyte(0)
        status = self._get_fips_mode(ctypes.byref(enabled))
        if status != 0:
            return (
                None,
                "BCryptGetFipsAlgorithmMode selhalo se stavem "
                f"{_format_ntstatus(status)}.",
            )
        return bool(enabled.value), None

    def _matching_evidence(self) -> dict[str, object] | None:
        for item in WINDOWS_CNG_EVIDENCE:
            versions = item["software_versions"]
            if self._os_version in versions:
                return item
        return None

    def status(self) -> StrictProfileStatus:
        checked = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        issues: list[str] = []
        available = (
            self._os_name == "nt"
            and self._gen_random is not None
            and self._get_fips_mode is not None
        )

        if self._os_name != "nt":
            issues.append("Přísný profil je dostupný pouze ve Windows.")
        if self._load_error:
            issues.append(self._load_error)
        if self._fatal_error:
            issues.append(self._fatal_error)

        fips_enabled: bool | None = None
        if available:
            fips_enabled, query_error = self._query_fips_mode()
            if query_error:
                issues.append(query_error)
            elif not fips_enabled:
                issues.append(
                    "Systémová zásada Windows „System cryptography: Use FIPS "
                    "compliant algorithms“ není zapnutá."
                )

        evidence = self._matching_evidence()
        evidence_state = "unmatched"
        if evidence is not None:
            sunset = date.fromisoformat(str(evidence["sunset_date"]))
            if self._today <= sunset:
                evidence_state = "matched-active"
            else:
                evidence_state = "matched-sunset"
                issues.append(
                    f"Podkladový certifikát {evidence['certificate']} dosáhl "
                    f"data sunset {evidence['sunset_date']}."
                )
        elif self._os_name == "nt":
            issues.append(
                "Verze Windows není v přiloženém offline manifestu spárována "
                "s dokončeným CMVP certifikátem; aktuální stav musí ověřit laboratoř."
            )

        ready = available and fips_enabled is True and self._fatal_error is None
        if ready and evidence_state == "matched-active":
            summary = (
                "Windows CNG je připravené a verze systému odpovídá aktivnímu "
                "podkladovému certifikátu v manifestu."
            )
        elif ready:
            summary = (
                "Windows CNG je připravené v systémovém FIPS režimu, ale přesná "
                "certifikační shoda prostředí není offline doložena."
            )
        else:
            summary = "Přísný Windows CNG profil není připraven k použití."

        return StrictProfileStatus(
            profile="entropyforge.windows-cng.strict.v1",
            available=available,
            ready=ready,
            provider=self.provider_name,
            api=self.api_name,
            os_name=platform.system() if self._os_name == os.name else self._os_name,
            os_version=self._os_version,
            architecture=self._architecture,
            fips_policy_enabled=fips_enabled,
            evidence_state=evidence_state,
            certificate=str(evidence["certificate"]) if evidence else None,
            certificate_standard=(
                str(evidence["standard"]) if evidence else None
            ),
            certificate_module=str(evidence["module"]) if evidence else None,
            certificate_sunset=(
                str(evidence["sunset_date"]) if evidence else None
            ),
            certificate_url=str(evidence["url"]) if evidence else None,
            checked_utc=checked,
            summary=summary,
            issues=tuple(issues),
            claim_limit=(
                "Certifikace se vztahuje pouze na podkladový kryptografický "
                "modul v podmínkách jeho Security Policy, nikoli na EntropyForge."
            ),
        )

    @property
    def ready(self) -> bool:
        return self.status().ready

    def _raw(self, n: int) -> bytes:
        if self._gen_random is None:
            raise StrictProfileError("BCryptGenRandom není dostupné.")
        output = bytearray()
        remaining = n
        while remaining:
            take = min(remaining, MAX_CNG_CALL_BYTES)
            buffer = (ctypes.c_ubyte * take)()
            status = self._gen_random(
                None,
                buffer,
                take,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
            if status != 0:
                raise StrictProfileError(
                    "BCryptGenRandom selhalo se stavem "
                    f"{_format_ntstatus(status)}."
                )
            output.extend(buffer)
            remaining -= take
        return bytes(output)

    def generate(self, n: int) -> bytes:
        if not isinstance(n, int):
            raise TypeError("Počet bajtů musí být celé číslo.")
        if n < 0:
            raise ValueError("Počet bajtů nesmí být záporný.")
        if n > MAX_PROFILE_REQUEST_BYTES:
            raise ValueError(
                f"Jeden požadavek přísného profilu může mít nejvýše "
                f"{MAX_PROFILE_REQUEST_BYTES} bajtů."
            )
        if n == 0:
            return b""

        with self._lock:
            current = self.status()
            if not current.ready:
                detail = " ".join(current.issues) or current.summary
                raise StrictProfileError(detail)

            try:
                probe = self._raw(64)
                if self._last_probe is not None and probe == self._last_probe:
                    raise StrictProfileError(
                        "Windows CNG zopakovalo celý 64bajtový kontrolní blok."
                    )
                self._last_probe = probe
                return self._raw(n)
            except StrictProfileError as exc:
                self._fatal_error = str(exc)
                raise


def human_status(status: StrictProfileStatus) -> str:
    lines = [
        "EntropyForge – přísný Windows CNG profil",
        f"Připraven: {'ANO' if status.ready else 'NE'}",
        f"Poskytovatel: {status.provider}",
        f"API: {status.api}",
        f"Systém: {status.os_name} {status.os_version} ({status.architecture})",
        (
            "Systémový FIPS režim: "
            + (
                "zapnutý"
                if status.fips_policy_enabled is True
                else "vypnutý"
                if status.fips_policy_enabled is False
                else "nelze zjistit"
            )
        ),
        f"Stav podkladů: {status.evidence_state}",
        f"Shrnutí: {status.summary}",
    ]
    if status.certificate:
        lines.extend(
            [
                f"Podkladový certifikát: {status.certificate}",
                f"Standard: {status.certificate_standard}",
                f"Modul: {status.certificate_module}",
                f"Sunset: {status.certificate_sunset}",
            ]
        )
    if status.issues:
        lines.append("Nálezy:")
        lines.extend(f"- {issue}" for issue in status.issues)
    lines.append(f"Omezení tvrzení: {status.claim_limit}")
    return "\n".join(lines)


if __name__ == "__main__":
    backend = WindowsCNGBackend()
    result = backend.status()
    print(human_status(result))
    raise SystemExit(0 if result.ready else 2)
