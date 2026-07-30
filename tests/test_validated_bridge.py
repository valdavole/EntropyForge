#!/usr/bin/env python3
"""HTTP security and output tests for the loopback HTML bridge."""

from __future__ import annotations

import base64
import http.client
import json
import sys
import threading
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from validated_backend import StrictProfileError  # noqa: E402
from validated_bridge import EntropyForgeBridgeServer  # noqa: E402


class FakeStatus:
    def public_dict(self) -> dict[str, object]:
        return {
            "profile": "entropyforge.windows-cng.strict.v1",
            "ready": True,
            "summary": "test ready",
            "issues": [],
        }


class FakeBackend:
    def __init__(self) -> None:
        self.fail = False
        self.calls: list[int] = []

    def status(self) -> FakeStatus:
        return FakeStatus()

    def generate(self, n: int) -> bytes:
        self.calls.append(n)
        if self.fail:
            raise StrictProfileError("simulated provider failure")
        return bytes((index * 37 + 11) & 0xFF for index in range(n))


class ValidatedBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = FakeBackend()
        cls.token = "test-session-token"
        cls.server = EntropyForgeBridgeServer(
            ("127.0.0.1", 0),
            cls.backend,
            cls.token,
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        origin: str | None = None,
        cookie: bool = True,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Accept": "application/json"}
        if cookie:
            headers["Cookie"] = f"EntropyForgeBridge={self.token}"
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, payload

    def test_root_sets_http_only_same_site_cookie(self) -> None:
        status, headers, payload = self.request("GET", "/", cookie=False)
        self.assertEqual(status, 200)
        self.assertIn(b"EntropyForge 3.3", payload)
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=Strict", headers["set-cookie"])
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_status_requires_bridge_session(self) -> None:
        status, _headers, _payload = self.request(
            "GET",
            "/api/v1/status",
            cookie=False,
        )
        self.assertEqual(status, 403)
        status, _headers, payload = self.request("GET", "/api/v1/status")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["ready"])

    def test_random_endpoint_is_same_origin_and_exact_length(self) -> None:
        body = json.dumps({"bytes": 257}).encode("utf-8")
        status, headers, payload = self.request(
            "POST",
            "/api/v1/random",
            body=body,
            origin=self.origin,
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")
        value = json.loads(payload)
        self.assertEqual(value["bytes"], 257)
        self.assertEqual(len(base64.b64decode(value["data_base64"], validate=True)), 257)
        self.assertEqual(value["profile"], "entropyforge.windows-cng.strict.v1")

    def test_cross_origin_request_is_rejected_before_generation(self) -> None:
        before = len(self.backend.calls)
        status, _headers, _payload = self.request(
            "POST",
            "/api/v1/random",
            body=b'{"bytes":32}',
            origin="http://evil.invalid",
        )
        self.assertEqual(status, 403)
        self.assertEqual(len(self.backend.calls), before)

    def test_provider_failure_returns_no_output(self) -> None:
        self.backend.fail = True
        try:
            status, _headers, payload = self.request(
                "POST",
                "/api/v1/random",
                body=b'{"bytes":32}',
                origin=self.origin,
            )
        finally:
            self.backend.fail = False
        self.assertEqual(status, 503)
        value = json.loads(payload)
        self.assertNotIn("data_base64", value)
        self.assertIn("simulated provider failure", value["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
