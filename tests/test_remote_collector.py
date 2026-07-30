#!/usr/bin/env python3
"""Offline mocked tests for the optional remote entropy collector."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import remote_entropy_collector as collector  # noqa: E402
from entropy_bundle import parse_bundle  # noqa: E402


DRAND_SIGNATURE = bytes(range(48))
DRAND_RANDOMNESS = hashlib.sha256(DRAND_SIGNATURE).digest()
NIST_OUTPUT = bytes(range(64))
NIST_URI = "https://beacon.nist.gov/beacon/2.0/chain/2/pulse/123"
RANDOM_ORG_DATA = bytes(range(256)) * 16


def fake_request(url: str, payload: dict[str, Any] | None) -> Any:
    if "drand" in url:
        return {
            "round": 987654,
            "randomness": DRAND_RANDOMNESS.hex(),
            "signature": DRAND_SIGNATURE.hex(),
        }
    if url.startswith("https://beacon.nist.gov/"):
        return {
            "pulse": {
                "version": "2.0",
                "statusCode": 0,
                "chainIndex": 2,
                "pulseIndex": 123,
                "timeStamp": "2026-07-29T12:34:00.000Z",
                "uri": NIST_URI,
                "outputValue": NIST_OUTPUT.hex().upper(),
                "signatureValue": (bytes(reversed(range(64))) * 8).hex().upper(),
            }
        }
    if url == collector.RANDOM_ORG_URL and payload:
        method = payload["method"]
        if method == "generateSignedBlobs":
            params = payload["params"]
            random_object = {
                "method": "generateSignedBlobs",
                "hashedApiKey": "hashed-not-secret",
                "n": 1,
                "size": len(RANDOM_ORG_DATA) * 8,
                "format": "base64",
                "pregeneratedRandomization": None,
                "data": [base64.b64encode(RANDOM_ORG_DATA).decode("ascii")],
                "license": {"type": "developer", "text": "fixture", "infoUrl": None},
                "licenseData": None,
                "userData": params["userData"],
                "ticketData": None,
                "completionTime": "2026-07-29 12:34:00Z",
                "serialNumber": 1234,
            }
            return {
                "jsonrpc": "2.0",
                "result": {
                    "random": random_object,
                    "signature": base64.b64encode(bytes(range(128))).decode("ascii"),
                    "bitsUsed": len(RANDOM_ORG_DATA) * 8,
                    "bitsLeft": 100_000,
                    "requestsLeft": 100,
                    "advisoryDelay": 0,
                },
                "id": payload["id"],
            }
        if method == "verifySignature":
            return {
                "jsonrpc": "2.0",
                "result": {"authenticity": True},
                "id": payload["id"],
            }
    raise AssertionError(f"Unexpected request: {url} {payload}")


class CollectorTests(unittest.TestCase):
    def test_drand_quorum_and_signature_hash(self) -> None:
        source = collector.fetch_drand(fake_request)
        self.assertEqual(source["id"], "drand.quicknet")
        self.assertEqual(base64.b64decode(source["data_base64"]), DRAND_RANDOMNESS)
        self.assertEqual(source["metadata"]["round"], 987654)
        self.assertEqual(len(source["metadata"]["agreeing_relays"]), 3)
        self.assertEqual(len(bytes.fromhex(source["metadata"]["signature_hex"])), 48)

    def test_drand_rejects_randomness_not_matching_signature(self) -> None:
        def bad_request(_url: str, _payload: dict[str, Any] | None) -> Any:
            return {
                "round": 1,
                "randomness": bytes(32).hex(),
                "signature": DRAND_SIGNATURE.hex(),
            }

        with self.assertRaisesRegex(collector.CollectionError, "SHA-256"):
            collector.fetch_drand(bad_request)

        long_signature = bytes(range(96))

        def wrong_length(_url: str, _payload: dict[str, Any] | None) -> Any:
            return {
                "round": 1,
                "randomness": hashlib.sha256(long_signature).hexdigest(),
                "signature": long_signature.hex(),
            }

        with self.assertRaisesRegex(collector.CollectionError, "48"):
            collector.fetch_drand(wrong_length)

    def test_drand_tolerates_one_unavailable_relay(self) -> None:
        def one_down(url: str, payload: dict[str, Any] | None) -> Any:
            if url.startswith("https://api3.drand.sh"):
                raise collector.CollectionError("fixture relay unavailable")
            return fake_request(url, payload)

        source = collector.fetch_drand(one_down)
        self.assertEqual(len(source["metadata"]["agreeing_relays"]), 2)
        self.assertIn(
            "https://api3.drand.sh",
            source["metadata"]["latest_failed_relays"],
        )

    def test_nist_exact_refetch(self) -> None:
        source = collector.fetch_nist(fake_request)
        self.assertEqual(source["id"], "nist.beacon-v2")
        self.assertEqual(base64.b64decode(source["data_base64"]), NIST_OUTPUT)
        self.assertEqual(source["metadata"]["pulse_index"], 123)

        calls = 0

        def changed_exact_uri(url: str, payload: dict[str, Any] | None) -> Any:
            nonlocal calls
            response = fake_request(url, payload)
            if url.startswith("https://beacon.nist.gov/"):
                calls += 1
                if calls == 2:
                    response = json.loads(json.dumps(response))
                    response["pulse"]["uri"] = NIST_URI + "-changed"
            return response

        with self.assertRaisesRegex(collector.CollectionError, "neshoduje"):
            collector.fetch_nist(changed_exact_uri)

    def test_random_org_signed_blob_and_no_plain_api_key_in_bundle(self) -> None:
        api_key = "test-secret-api-key"
        source = collector.fetch_random_org(
            api_key,
            fake_request,
            byte_count=len(RANDOM_ORG_DATA),
        )
        self.assertEqual(source["id"], "random.org.signed")
        self.assertEqual(base64.b64decode(source["data_base64"]), RANDOM_ORG_DATA)
        self.assertNotIn(api_key, json.dumps(source))

        def echoing_key(url: str, payload: dict[str, Any] | None) -> Any:
            response = fake_request(url, payload)
            if payload and payload["method"] == "generateSignedBlobs":
                response = json.loads(json.dumps(response))
                response["result"]["random"]["apiKey"] = api_key
            return response

        with self.assertRaisesRegex(collector.CollectionError, "API klíč"):
            collector.fetch_random_org(
                api_key,
                echoing_key,
                byte_count=len(RANDOM_ORG_DATA),
            )

        redirect_handler = collector._SameHostHttpsRedirectHandler()
        request = collector.urllib.request.Request(
            collector.RANDOM_ORG_URL,
            data=b"secret-bearing-request",
            method="POST",
        )
        with self.assertRaisesRegex(collector.CollectionError, "původ"):
            redirect_handler.redirect_request(
                request,
                None,
                307,
                "Temporary Redirect",
                {},
                "https://example.invalid/steal",
            )

    def test_complete_three_source_bundle(self) -> None:
        raw = collector.collect_bundle(
            include_drand=True,
            include_nist=True,
            random_org_key="test-secret-api-key",
            request_json=fake_request,
        )
        parsed = parse_bundle(raw)
        self.assertEqual(parsed.source_count, 3)
        self.assertEqual(parsed.public_count, 2)
        self.assertEqual(parsed.provider_known_count, 1)
        self.assertEqual(parsed.total_random_bytes, 32 + 64 + len(RANDOM_ORG_DATA))


if __name__ == "__main__":
    unittest.main(verbosity=2)
