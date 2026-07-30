#!/usr/bin/env python3
"""Loopback-only bridge for the EntropyForge HTML strict Windows profile."""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import sys
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from validated_backend import (
    MAX_PROFILE_REQUEST_BYTES,
    StrictProfileError,
    WindowsCNGBackend,
    human_status,
)


APP_DIR = Path(__file__).resolve().parent
HTML_PATH = APP_DIR / "EntropyForge.html"
MAX_JSON_REQUEST_BYTES = 1024


class EntropyForgeBridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        backend: WindowsCNGBackend,
        session_token: str,
    ) -> None:
        super().__init__(server_address, EntropyForgeBridgeHandler)
        self.backend = backend
        self.session_token = session_token
        self.html_bytes = HTML_PATH.read_bytes()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    @property
    def accepted_hosts(self) -> set[str]:
        return {
            f"127.0.0.1:{self.server_port}",
            f"localhost:{self.server_port}",
        }


class EntropyForgeBridgeHandler(BaseHTTPRequestHandler):
    server: EntropyForgeBridgeServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Do not create an access log containing local browsing details.
        return

    def _send_headers(
        self,
        status: HTTPStatus,
        content_type: str,
        length: int,
        *,
        set_cookie: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if set_cookie:
            self.send_header(
                "Set-Cookie",
                "EntropyForgeBridge="
                + self.server.session_token
                + "; HttpOnly; SameSite=Strict; Path=/",
            )
        self.end_headers()

    def _json(
        self,
        status: HTTPStatus,
        payload: dict[str, object],
    ) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self._send_headers(status, "application/json; charset=utf-8", len(encoded))
        self.wfile.write(encoded)

    def _host_is_allowed(self) -> bool:
        return self.headers.get("Host", "") in self.server.accepted_hosts

    def _origin_is_same(self) -> bool:
        host = self.headers.get("Host", "")
        return self.headers.get("Origin", "") == f"http://{host}"

    def _session_is_valid(self) -> bool:
        cookies = self.headers.get("Cookie", "").split(";")
        supplied = ""
        for item in cookies:
            name, separator, value = item.strip().partition("=")
            if separator and name == "EntropyForgeBridge":
                supplied = value
                break
        return bool(supplied) and hmac.compare_digest(
            supplied,
            self.server.session_token,
        )

    def _authorized_api_request(self, *, require_origin: bool = True) -> bool:
        if not self._host_is_allowed():
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Neplatná hlavička Host."})
            return False
        if require_origin and not self._origin_is_same():
            self._json(
                HTTPStatus.FORBIDDEN,
                {"error": "Požadavek nemá povolený same-origin původ."},
            )
            return False
        if not self._session_is_valid():
            self._json(
                HTTPStatus.FORBIDDEN,
                {"error": "Chybí platná relace lokálního bridge."},
            )
            return False
        return True

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            if not self._host_is_allowed():
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Neplatná hlavička Host."})
                return
            body = self.server.html_bytes
            self._send_headers(
                HTTPStatus.OK,
                "text/html; charset=utf-8",
                len(body),
                set_cookie=True,
            )
            self.wfile.write(body)
            return

        if path == "/api/v1/status":
            if not self._authorized_api_request(require_origin=False):
                return
            self._json(HTTPStatus.OK, self.server.backend.status().public_dict())
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "Nenalezeno."})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != "/api/v1/random":
            self._json(HTTPStatus.NOT_FOUND, {"error": "Nenalezeno."})
            return
        if not self._authorized_api_request():
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != (
            "application/json"
        ):
            self._json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "Požadován je Content-Type application/json."},
            )
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if length < 1 or length > MAX_JSON_REQUEST_BYTES:
            self._json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "Neplatná velikost požadavku."},
            )
            return

        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Neplatný JSON."})
            return
        if (
            not isinstance(request, dict)
            or set(request) != {"bytes"}
            or type(request["bytes"]) is not int
            or not 1 <= request["bytes"] <= MAX_PROFILE_REQUEST_BYTES
        ):
            self._json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": (
                        "Pole bytes musí být celé číslo od 1 do "
                        f"{MAX_PROFILE_REQUEST_BYTES}."
                    )
                },
            )
            return

        try:
            output = self.server.backend.generate(request["bytes"])
        except (StrictProfileError, OSError) as exc:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": f"Přísný profil odmítl výstup: {exc}"},
            )
            return
        encoded = base64.b64encode(output).decode("ascii")
        self._json(
            HTTPStatus.OK,
            {
                "bytes": len(output),
                "data_base64": encoded,
                "profile": "entropyforge.windows-cng.strict.v1",
            },
        )

    def do_OPTIONS(self) -> None:
        self._json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "CORS není povolen; bridge je pouze same-origin."},
        )


def _session_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Spustí EntropyForge HTML z lokálního serveru a zpřístupní mu "
            "přísný Windows CNG profil."
        )
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Neotevírat automaticky výchozí prohlížeč.",
    )
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="Pouze vypsat stav přísného profilu a skončit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    backend = WindowsCNGBackend()
    status = backend.status()
    print(human_status(status), flush=True)
    if args.status_only:
        return 0 if status.ready else 2

    server = EntropyForgeBridgeServer(("127.0.0.1", 0), backend, _session_token())
    print(
        "\nLokální HTML rozhraní běží pouze na tomto počítači:\n"
        f"{server.origin}\n"
        "Okno ukončíš klávesami Ctrl+C.",
        flush=True,
    )
    if not args.no_browser:
        webbrowser.open(server.origin, new=1)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nUkončuji lokální bridge.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
