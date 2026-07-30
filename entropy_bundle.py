#!/usr/bin/env python3
"""Strict, portable EntropyForge remote-bundle format.

The bundle is deliberately an offline transport container.  It records random
bytes collected by the companion network collector together with provenance
metadata and an integrity checksum.  The checksum detects accidental changes;
it is not a digital signature and does not independently prove physical origin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


BUNDLE_SCHEMA = "entropyforge.remote-bundle.v1"
PAYLOAD_SCHEMA = "entropyforge.remote-payload.v1"
MAX_BUNDLE_PAYLOAD_BYTES = 1_048_576
MAX_BUNDLE_SOURCES = 8
MIN_SOURCE_BYTES = 32
MAX_SOURCE_BYTES = 131_072
MAX_METADATA_DEPTH = 12
MAX_METADATA_NODES = 4_096
MAX_METADATA_ITEMS = 256
MAX_METADATA_STRING_CHARS = 262_144
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class BundleError(ValueError):
    """Raised when an EntropyForge bundle is malformed or inconsistent."""


@dataclass(frozen=True)
class ParsedBundle:
    payload: dict[str, Any]
    payload_bytes: bytes
    fingerprint: str
    source_count: int
    total_random_bytes: int
    public_count: int
    provider_known_count: int
    sources: tuple[dict[str, Any], ...]


def _reject_constant(value: str) -> None:
    raise BundleError(f"Nepovolená JSON konstanta: {value}.")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"Duplicitní JSON klíč: {key}.")
        result[key] = value
    return result


def strict_json_loads(data: bytes | str) -> Any:
    """Decode UTF-8 JSON while rejecting duplicate keys and NaN/Infinity."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError("Balíček není platný text UTF-8.") from exc
    else:
        text = data
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except BundleError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BundleError("Balíček neobsahuje platný JSON.") from exc


def canonical_json(value: Any) -> bytes:
    """Serialize deterministic UTF-8 JSON shared with the HTML implementation."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BundleError("Metadata balíčku nelze kanonicky serializovat.") from exc


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append("chybí " + ", ".join(missing))
        if extra:
            details.append("navíc " + ", ".join(extra))
        raise BundleError(f"{label} má neplatná pole ({'; '.join(details)}).")


def _require_ascii_text(value: Any, label: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise BundleError(f"{label} musí být text délky {minimum} až {maximum} znaků.")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise BundleError(f"{label} smí obsahovat pouze tisknutelné ASCII znaky.")
    return value


def _decode_canonical_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not _B64_RE.fullmatch(value):
        raise BundleError(f"{label} není kanonický Base64 text.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise BundleError(f"{label} není platný Base64 text.") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BundleError(f"{label} není kanonicky zapsaný Base64 text.")
    return decoded


def _validate_utc(value: Any) -> str:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise BundleError("created_utc musí být UTC čas ve formátu ISO 8601 s koncovým Z.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BundleError("created_utc není platný kalendářní čas.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BundleError("created_utc musí být v UTC.")
    return value


def _validate_metadata(value: Any) -> None:
    """Require a bounded JSON profile with identical Python/JavaScript semantics."""
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_METADATA_NODES:
            raise BundleError("Metadata obsahují příliš mnoho položek.")
        if depth > MAX_METADATA_DEPTH:
            raise BundleError("Metadata jsou vnořena příliš hluboko.")

        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_JSON_INTEGER:
                raise BundleError("Číslo v metadatech přesahuje přenositelný bezpečný rozsah.")
            return
        if isinstance(item, float):
            raise BundleError("Metadata nesmějí obsahovat desetinná čísla.")
        if isinstance(item, str):
            if len(item) > MAX_METADATA_STRING_CHARS:
                raise BundleError("Textová hodnota v metadatech je příliš dlouhá.")
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise BundleError("Metadata obsahují neplatný Unicode znak.")
            return
        if isinstance(item, list):
            if len(item) > MAX_METADATA_ITEMS:
                raise BundleError("Seznam v metadatech obsahuje příliš mnoho položek.")
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > MAX_METADATA_ITEMS:
                raise BundleError("Objekt v metadatech obsahuje příliš mnoho polí.")
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or not 1 <= len(key) <= 96
                    or any(ord(character) < 0x20 or ord(character) > 0x7E for character in key)
                ):
                    raise BundleError(
                        "Klíče metadat musí mít 1 až 96 tisknutelných ASCII znaků."
                    )
                visit(child, depth + 1)
            return
        raise BundleError("Metadata obsahují nepodporovaný JSON typ.")

    visit(value, 0)


def looks_like_bundle(raw: bytes) -> bool:
    stripped = raw.lstrip()
    return stripped.startswith(b"{") and BUNDLE_SCHEMA.encode("ascii") in raw


def make_source_record(
    *,
    identifier: str,
    label: str,
    kind: str,
    visibility: str,
    data: bytes,
    validation: Iterable[str],
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one canonical source record for build_bundle()."""
    raw = bytes(data)
    return {
        "data_base64": base64.b64encode(raw).decode("ascii"),
        "data_sha256": hashlib.sha256(raw).hexdigest(),
        "id": identifier,
        "kind": kind,
        "label": label,
        "metadata": dict(metadata),
        "validation": list(validation),
        "visibility": visibility,
    }


def build_bundle(
    sources: Iterable[Mapping[str, Any]],
    *,
    collector: str,
    created_utc: str | None = None,
) -> bytes:
    """Create and self-validate a canonical EntropyForge remote bundle."""
    timestamp = created_utc or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    payload = {
        "collector": collector,
        "created_utc": timestamp,
        "schema": PAYLOAD_SCHEMA,
        "sources": [dict(source) for source in sources],
    }
    payload_bytes = canonical_json(payload)
    outer = {
        "payload_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "schema": BUNDLE_SCHEMA,
    }
    result = canonical_json(outer) + b"\n"
    parse_bundle(result)
    return result


def parse_bundle(raw: bytes) -> ParsedBundle:
    """Strictly validate a bundle and return its canonical source metadata."""
    outer = strict_json_loads(raw)
    if not isinstance(outer, dict):
        raise BundleError("Vnější obal balíčku musí být JSON objekt.")
    _require_exact_keys(
        outer,
        {"schema", "payload_base64", "payload_sha256"},
        "Vnější obal balíčku",
    )
    if canonical_json(outer) + b"\n" != raw:
        raise BundleError("Vnější obal balíčku není v požadovaném kanonickém JSON tvaru.")
    if outer["schema"] != BUNDLE_SCHEMA:
        raise BundleError("Nepodporovaná verze EntropyForge balíčku.")
    if not isinstance(outer["payload_sha256"], str) or not _SHA256_RE.fullmatch(outer["payload_sha256"]):
        raise BundleError("payload_sha256 nemá platný formát.")

    payload_bytes = _decode_canonical_base64(outer["payload_base64"], "payload_base64")
    if not payload_bytes or len(payload_bytes) > MAX_BUNDLE_PAYLOAD_BYTES:
        raise BundleError("Dekódovaný obsah balíčku musí mít 1 B až 1 MiB.")
    fingerprint = hashlib.sha256(payload_bytes).hexdigest()
    if fingerprint != outer["payload_sha256"]:
        raise BundleError("Kontrolní součet vzdáleného balíčku nesouhlasí.")

    payload = strict_json_loads(payload_bytes)
    if not isinstance(payload, dict):
        raise BundleError("Obsah balíčku musí být JSON objekt.")
    _require_exact_keys(
        payload,
        {"schema", "created_utc", "collector", "sources"},
        "Obsah balíčku",
    )
    if canonical_json(payload) != payload_bytes:
        raise BundleError("Obsah balíčku není v požadovaném kanonickém JSON tvaru.")
    if payload["schema"] != PAYLOAD_SCHEMA:
        raise BundleError("Nepodporovaná verze obsahu EntropyForge balíčku.")
    _validate_utc(payload["created_utc"])
    _require_ascii_text(payload["collector"], "collector", 1, 96)

    records = payload["sources"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_BUNDLE_SOURCES:
        raise BundleError(f"Balíček musí obsahovat 1 až {MAX_BUNDLE_SOURCES} zdrojů.")

    seen_ids: set[str] = set()
    seen_data_hashes: set[str] = set()
    summaries: list[dict[str, Any]] = []
    total_bytes = 0
    public_count = 0
    provider_known_count = 0
    expected_keys = {
        "id",
        "label",
        "kind",
        "visibility",
        "data_base64",
        "data_sha256",
        "validation",
        "metadata",
    }
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise BundleError(f"Zdroj {index} musí být JSON objekt.")
        _require_exact_keys(record, expected_keys, f"Zdroj {index}")

        identifier = _require_ascii_text(record["id"], f"Zdroj {index}: id", 1, 64)
        if not _ID_RE.fullmatch(identifier):
            raise BundleError(f"Zdroj {index}: id má nepovolený formát.")
        if identifier in seen_ids:
            raise BundleError(f"Zdroj {index}: duplicitní id {identifier}.")
        seen_ids.add(identifier)

        label = _require_ascii_text(record["label"], f"Zdroj {index}: label", 1, 80)
        kind = record["kind"]
        visibility = record["visibility"]
        if kind not in {"public_beacon", "remote_trng"}:
            raise BundleError(f"Zdroj {index}: nepodporovaný kind.")
        if visibility not in {"public", "provider_known"}:
            raise BundleError(f"Zdroj {index}: nepodporovaná visibility.")
        if kind == "public_beacon" and visibility != "public":
            raise BundleError(f"Zdroj {index}: veřejný beacon musí mít visibility=public.")
        if kind == "remote_trng" and visibility != "provider_known":
            raise BundleError(f"Zdroj {index}: vzdálený TRNG musí mít visibility=provider_known.")

        data = _decode_canonical_base64(record["data_base64"], f"Zdroj {index}: data_base64")
        if not MIN_SOURCE_BYTES <= len(data) <= MAX_SOURCE_BYTES:
            raise BundleError(
                f"Zdroj {index}: náhodná data musí mít {MIN_SOURCE_BYTES} až {MAX_SOURCE_BYTES} bajtů."
            )
        if len(set(data)) < 2:
            raise BundleError(f"Zdroj {index}: náhodná data jsou zjevně degenerovaná.")
        if not isinstance(record["data_sha256"], str) or not _SHA256_RE.fullmatch(record["data_sha256"]):
            raise BundleError(f"Zdroj {index}: data_sha256 nemá platný formát.")
        if hashlib.sha256(data).hexdigest() != record["data_sha256"]:
            raise BundleError(f"Zdroj {index}: kontrolní součet náhodných dat nesouhlasí.")
        if record["data_sha256"] in seen_data_hashes:
            raise BundleError(f"Zdroj {index}: stejná náhodná data už balíček obsahuje.")
        seen_data_hashes.add(record["data_sha256"])

        validation = record["validation"]
        if not isinstance(validation, list) or not 1 <= len(validation) <= 8:
            raise BundleError(f"Zdroj {index}: validation musí obsahovat 1 až 8 položek.")
        checked_validation = tuple(
            _require_ascii_text(item, f"Zdroj {index}: validation", 1, 160)
            for item in validation
        )
        if not isinstance(record["metadata"], dict):
            raise BundleError(f"Zdroj {index}: metadata musí být JSON objekt.")
        _validate_metadata(record["metadata"])

        total_bytes += len(data)
        if visibility == "public":
            public_count += 1
        else:
            provider_known_count += 1
        summaries.append(
            {
                "id": identifier,
                "label": label,
                "kind": kind,
                "visibility": visibility,
                "size": len(data),
                "data_sha256": record["data_sha256"],
                "validation": checked_validation,
            }
        )

    return ParsedBundle(
        payload=payload,
        payload_bytes=payload_bytes,
        fingerprint=fingerprint,
        source_count=len(records),
        total_random_bytes=total_bytes,
        public_count=public_count,
        provider_known_count=provider_known_count,
        sources=tuple(summaries),
    )
