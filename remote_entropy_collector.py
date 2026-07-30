#!/usr/bin/env python3
"""Optional network collector for EntropyForge 3.3.

The generator itself remains offline.  This companion obtains public beacons
and, when the user supplies an API key, provider-known physical random bytes.
It writes a portable .efb bundle that both EntropyForge editions can import.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import threading
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from entropy_bundle import (
    BundleError,
    build_bundle,
    make_source_record,
    strict_json_loads,
)


APP_VERSION = "1.0"
COLLECTOR_NAME = f"EntropyForge Remote Collector {APP_VERSION}"
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_RANDOM_ORG_BYTES = 4_096

DRAND_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_RELAYS = (
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
)
NIST_LATEST_URL = "https://beacon.nist.gov/beacon/2.0/chain/last/pulse/last"
RANDOM_ORG_URL = "https://api.random.org/json-rpc/4/invoke"

JsonRequest = Callable[[str, dict[str, Any] | None], Any]


class CollectionError(RuntimeError):
    """A remote source failed validation or could not be reached."""


class _SameHostHttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward a request, especially an API key, to another origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        original = urllib.parse.urlparse(req.full_url)
        redirected = urllib.parse.urlparse(urllib.parse.urljoin(req.full_url, newurl))
        try:
            redirected_port = redirected.port
        except ValueError as exc:
            raise CollectionError("HTTPS přesměrování obsahuje neplatný port.") from exc
        if (
            redirected.scheme != "https"
            or redirected.hostname != original.hostname
            or redirected_port not in {None, 443}
            or redirected.username is not None
            or redirected.password is not None
        ):
            raise CollectionError("HTTPS přesměrování změnilo důvěryhodný původ požadavku.")
        return super().redirect_request(req, fp, code, msg, headers, redirected.geturl())


def _json_request(url: str, payload: dict[str, Any] | None = None) -> Any:
    parsed = urllib.parse.urlparse(url)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise CollectionError("HTTPS adresa obsahuje neplatný port.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed_port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise CollectionError("Síťový sběrač dovoluje pouze HTTPS adresy.")
    body = None
    headers = {
        "Accept": "application/json",
        "User-Agent": f"EntropyForge-Remote-Collector/{APP_VERSION}",
    }
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _SameHostHttpsRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise CollectionError(f"Server vrátil HTTP {response.status}.")
            final = urllib.parse.urlparse(response.geturl())
            if (
                final.scheme != "https"
                or final.hostname != parsed.hostname
                or final.port not in {None, 443}
            ):
                raise CollectionError("HTTPS požadavek skončil na neočekávaném původu.")
            raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise CollectionError(f"HTTPS požadavek selhal: {parsed.hostname}.") from exc
    if not raw or len(raw) > MAX_HTTP_RESPONSE_BYTES:
        raise CollectionError("Server vrátil prázdnou nebo příliš velkou odpověď.")
    try:
        return strict_json_loads(raw)
    except BundleError as exc:
        raise CollectionError("Server nevrátil platný striktní JSON.") from exc


def _hex_bytes(value: Any, *, label: str, exact_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2:
        raise CollectionError(f"{label} nemá platný hexadecimální formát.")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise CollectionError(f"{label} nemá platný hexadecimální formát.") from exc
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise CollectionError(f"{label} musí mít přesně {exact_bytes} bajtů.")
    return decoded


def _parse_drand_response(response: Any, expected_round: int | None = None) -> tuple[int, bytes, str]:
    if not isinstance(response, dict):
        raise CollectionError("drand odpověď není JSON objekt.")
    round_value = response.get("round")
    if not isinstance(round_value, int) or isinstance(round_value, bool) or round_value <= 0:
        raise CollectionError("drand round není kladné celé číslo.")
    if expected_round is not None and round_value != expected_round:
        raise CollectionError("drand relay vrátil jiný round.")
    randomness = _hex_bytes(response.get("randomness"), label="drand randomness", exact_bytes=32)
    signature = _hex_bytes(response.get("signature"), label="drand signature", exact_bytes=48)
    if hashlib.sha256(signature).digest() != randomness:
        raise CollectionError("drand randomness není SHA-256 otisk přiloženého podpisu.")
    return round_value, randomness, signature.hex()


def fetch_drand(request_json: JsonRequest = _json_request) -> dict[str, Any]:
    """Fetch one pinned quicknet round and require agreement of two relays."""
    latest_rounds: list[tuple[str, int]] = []
    latest_failures: list[str] = []
    latest_errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(DRAND_RELAYS)) as executor:
        futures = {
            executor.submit(
                request_json,
                f"{relay}/{DRAND_CHAIN_HASH}/public/latest",
                None,
            ): relay
            for relay in DRAND_RELAYS
        }
        for future in as_completed(futures):
            relay = futures[future]
            try:
                latest = future.result()
                latest_round, _randomness, _signature = _parse_drand_response(latest)
                latest_rounds.append((relay, latest_round))
            except (CollectionError, OSError) as exc:
                latest_failures.append(relay)
                latest_errors.append(f"{relay}: {exc}")
    if len(latest_rounds) < 2:
        detail = latest_errors[0] if latest_errors else "bez podrobností"
        raise CollectionError(
            "Nepodařilo se načíst platný poslední drand round alespoň ze dvou relayů. "
            f"První chyba: {detail}"
        )
    ordered_rounds = sorted(round_value for _relay, round_value in latest_rounds)
    round_value = ordered_rounds[(len(ordered_rounds) - 1) // 2]

    valid: list[tuple[str, int, bytes, str]] = []
    exact_failures: list[str] = []
    with ThreadPoolExecutor(max_workers=len(DRAND_RELAYS)) as executor:
        futures = {
            executor.submit(
                request_json,
                f"{relay}/{DRAND_CHAIN_HASH}/public/{round_value}",
                None,
            ): relay
            for relay in DRAND_RELAYS
        }
        for future in as_completed(futures):
            relay = futures[future]
            try:
                response = future.result()
                parsed_round, randomness, signature = _parse_drand_response(response, round_value)
                valid.append((relay, parsed_round, randomness, signature))
            except (CollectionError, OSError):
                exact_failures.append(relay)

    if len(valid) < 2:
        raise CollectionError("Nepodařilo se získat platný drand round alespoň ze dvou relayů.")
    counts = Counter((item[1], item[2], item[3]) for item in valid)
    winner, agreement = counts.most_common(1)[0]
    if agreement < 2:
        raise CollectionError("Nezávislé drand relaye se neshodly na stejném výsledku.")
    agreed_relays = [relay for relay, r, data, sig in valid if (r, data, sig) == winner]
    agreed_round, data, signature = winner
    return make_source_record(
        identifier="drand.quicknet",
        label="drand League of Entropy quicknet",
        kind="public_beacon",
        visibility="public",
        data=data,
        validation=(
            "HTTPS certificate validation",
            "Pinned quicknet chain hash",
            "SHA-256(signature) equals randomness",
            f"{agreement}/{len(DRAND_RELAYS)} relay agreement",
            "BLS signature retained but not locally verified",
        ),
        metadata={
            "agreeing_relays": agreed_relays,
            "chain_hash": DRAND_CHAIN_HASH,
            "exact_failed_relays": exact_failures,
            "latest_failed_relays": latest_failures,
            "latest_rounds": {relay: latest_round for relay, latest_round in latest_rounds},
            "round": agreed_round,
            "signature_hex": signature,
        },
    )


def _parse_nist_pulse(response: Any) -> tuple[dict[str, Any], bytes]:
    if not isinstance(response, dict) or not isinstance(response.get("pulse"), dict):
        raise CollectionError("NIST odpověď neobsahuje objekt pulse.")
    pulse = response["pulse"]
    if pulse.get("version") != "2.0" or pulse.get("statusCode") != 0:
        raise CollectionError("NIST pulse nemá očekávanou verzi nebo stav.")
    chain_index = pulse.get("chainIndex")
    pulse_index = pulse.get("pulseIndex")
    if not isinstance(chain_index, int) or chain_index <= 0:
        raise CollectionError("NIST chainIndex je neplatný.")
    if not isinstance(pulse_index, int) or pulse_index <= 0:
        raise CollectionError("NIST pulseIndex je neplatný.")
    output = _hex_bytes(pulse.get("outputValue"), label="NIST outputValue", exact_bytes=64)
    _hex_bytes(pulse.get("signatureValue"), label="NIST signatureValue")
    timestamp = pulse.get("timeStamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise CollectionError("NIST pulse nemá platné UTC časové razítko.")
    try:
        datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as exc:
        raise CollectionError("NIST pulse nemá platné časové razítko.") from exc
    uri = pulse.get("uri")
    parsed_uri = urllib.parse.urlparse(uri) if isinstance(uri, str) else None
    try:
        parsed_uri_port = parsed_uri.port if parsed_uri is not None else None
    except ValueError as exc:
        raise CollectionError("NIST pulse obsahuje URI s neplatným portem.") from exc
    if (
        parsed_uri is None
        or parsed_uri.scheme != "https"
        or parsed_uri.hostname != "beacon.nist.gov"
        or parsed_uri_port not in {None, 443}
        or parsed_uri.username is not None
        or parsed_uri.password is not None
        or parsed_uri.query
        or parsed_uri.fragment
        or not parsed_uri.path.startswith("/beacon/2.0/")
    ):
        raise CollectionError("NIST pulse obsahuje neočekávané URI.")
    return pulse, output


def fetch_nist(request_json: JsonRequest = _json_request) -> dict[str, Any]:
    """Fetch the latest NIST pulse and re-fetch its exact signed package."""
    first = request_json(NIST_LATEST_URL, None)
    pulse, data = _parse_nist_pulse(first)
    repeated = request_json(pulse["uri"], None)
    repeated_pulse, repeated_data = _parse_nist_pulse(repeated)
    fields = ("chainIndex", "pulseIndex", "timeStamp", "uri", "outputValue", "signatureValue")
    if any(pulse.get(field) != repeated_pulse.get(field) for field in fields) or data != repeated_data:
        raise CollectionError("Opakované načtení přesného NIST pulzu se neshoduje.")
    return make_source_record(
        identifier="nist.beacon-v2",
        label="NIST Randomness Beacon 2.0",
        kind="public_beacon",
        visibility="public",
        data=data,
        validation=(
            "HTTPS certificate validation",
            "Exact pulse re-fetch matched",
            "NIST statusCode equals zero",
            "NIST signature retained but not locally verified",
        ),
        metadata={
            "chain_index": pulse["chainIndex"],
            "pulse_index": pulse["pulseIndex"],
            "signature_hex": pulse["signatureValue"].lower(),
            "timestamp": pulse["timeStamp"],
            "uri": pulse["uri"],
        },
    )


def _random_org_rpc(
    method: str,
    params: dict[str, Any],
    request_json: JsonRequest,
) -> dict[str, Any]:
    request_id = int.from_bytes(os.urandom(4), "big")
    response = request_json(
        RANDOM_ORG_URL,
        {"jsonrpc": "2.0", "method": method, "params": params, "id": request_id},
    )
    if not isinstance(response, dict):
        raise CollectionError("RANDOM.ORG odpověď není JSON objekt.")
    if response.get("id") != request_id:
        raise CollectionError("RANDOM.ORG odpověď má jiné ID požadavku.")
    if "error" in response:
        error = response["error"]
        message = error.get("message") if isinstance(error, dict) else None
        raise CollectionError(f"RANDOM.ORG odmítl požadavek: {message or 'neznámá chyba'}.")
    result = response.get("result")
    if not isinstance(result, dict):
        raise CollectionError("RANDOM.ORG odpověď neobsahuje objekt result.")
    return result


def _contains_secret(value: Any, secret: str) -> bool:
    if isinstance(value, str):
        return secret == value or (len(secret) >= 8 and secret in value)
    if isinstance(value, list):
        return any(_contains_secret(item, secret) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_secret(key, secret) or _contains_secret(item, secret)
            for key, item in value.items()
        )
    return False


def fetch_random_org(
    api_key: str,
    request_json: JsonRequest = _json_request,
    byte_count: int = DEFAULT_RANDOM_ORG_BYTES,
) -> dict[str, Any]:
    """Fetch a signed provider-known physical random blob from RANDOM.ORG."""
    key = api_key.strip()
    if not key or len(key) > 128:
        raise CollectionError("Je potřeba platný RANDOM.ORG API klíč.")
    if not 32 <= byte_count <= 131_072:
        raise CollectionError("RANDOM.ORG velikost musí být mezi 32 B a 128 KiB.")

    nonce = os.urandom(16).hex()
    result = _random_org_rpc(
        "generateSignedBlobs",
        {
            "apiKey": key,
            "n": 1,
            "size": byte_count * 8,
            "format": "base64",
            "pregeneratedRandomization": None,
            "licenseData": None,
            "userData": {"application": "EntropyForge 3.3", "requestNonce": nonce},
        },
        request_json,
    )
    random_object = result.get("random")
    signature = result.get("signature")
    if not isinstance(random_object, dict) or not isinstance(signature, str):
        raise CollectionError("RANDOM.ORG Signed API nevrátil podepsaný random objekt.")
    if (
        random_object.get("method") != "generateSignedBlobs"
        or random_object.get("n") != 1
        or random_object.get("size") != byte_count * 8
        or random_object.get("format") != "base64"
        or random_object.get("pregeneratedRandomization") is not None
    ):
        raise CollectionError("RANDOM.ORG random objekt neodpovídá našemu požadavku.")
    user_data = random_object.get("userData")
    if user_data != {"application": "EntropyForge 3.3", "requestNonce": nonce}:
        raise CollectionError("RANDOM.ORG podpis není svázán s tímto požadavkem.")
    if _contains_secret(random_object, key):
        raise CollectionError("RANDOM.ORG odpověď neočekávaně obsahuje nezahashovaný API klíč.")
    data_items = random_object.get("data")
    if not isinstance(data_items, list) or len(data_items) != 1 or not isinstance(data_items[0], str):
        raise CollectionError("RANDOM.ORG nevrátil právě jeden Base64 blok.")
    try:
        data = base64.b64decode(data_items[0], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CollectionError("RANDOM.ORG vrátil neplatný Base64 blok.") from exc
    if len(data) != byte_count or base64.b64encode(data).decode("ascii") != data_items[0]:
        raise CollectionError("RANDOM.ORG blok nemá požadovanou velikost nebo kanonický tvar.")
    if result.get("bitsUsed") != byte_count * 8:
        raise CollectionError("RANDOM.ORG vykázal neočekávaný počet použitých bitů.")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CollectionError("RANDOM.ORG podpis nemá platný Base64 formát.") from exc
    if (
        not signature_bytes
        or base64.b64encode(signature_bytes).decode("ascii") != signature
    ):
        raise CollectionError("RANDOM.ORG podpis nemá kanonický Base64 tvar.")

    verification = _random_org_rpc(
        "verifySignature",
        {"random": random_object, "signature": signature},
        request_json,
    )
    if verification.get("authenticity") is not True:
        raise CollectionError("RANDOM.ORG digitální podpis nebyl ověřen.")

    return make_source_record(
        identifier="random.org.signed",
        label="RANDOM.ORG atmospheric-noise Signed API",
        kind="remote_trng",
        visibility="provider_known",
        data=data,
        validation=(
            "HTTPS certificate validation",
            "Fresh non-pregenerated request",
            "Request nonce bound into signed response",
            "RANDOM.ORG signature verification returned authentic",
            "Provider knows the remote random bytes",
        ),
        metadata={
            "bits_used": result.get("bitsUsed"),
            "completion_time": random_object.get("completionTime"),
            "hashed_api_key": random_object.get("hashedApiKey"),
            "license": random_object.get("license"),
            "serial_number": random_object.get("serialNumber"),
            "signature_base64": signature,
            "signed_random": random_object,
        },
    )


def collect_bundle(
    *,
    include_drand: bool = True,
    include_nist: bool = True,
    random_org_key: str | None = None,
    request_json: JsonRequest = _json_request,
    progress: Callable[[str], None] | None = None,
) -> bytes:
    """Collect selected sources.  One failed optional source aborts the bundle."""
    if not include_drand and not include_nist and not random_org_key:
        raise CollectionError("Vyber alespoň jeden vzdálený zdroj.")
    report = progress or (lambda _message: None)
    jobs: list[tuple[str, Callable[[], dict[str, Any]]]] = []
    if include_drand:
        jobs.append(("drand quicknet", lambda: fetch_drand(request_json)))
    if include_nist:
        jobs.append(("NIST Beacon 2.0", lambda: fetch_nist(request_json)))
    if random_org_key:
        jobs.append(
            (
                "RANDOM.ORG Signed API",
                lambda: fetch_random_org(random_org_key, request_json),
            )
        )
    report("Paralelně načítám a ověřuji vybrané vzdálené zdroje…")
    completed: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = {
            executor.submit(job): (index, label)
            for index, (label, job) in enumerate(jobs)
        }
        for future in as_completed(futures):
            index, label = futures[future]
            completed[index] = future.result()
            report(f"Ověřeno: {label}.")
    sources = [completed[index] for index in range(len(jobs))]
    report("Vytvářím kanonický offline balíček…")
    return build_bundle(sources, collector=COLLECTOR_NAME)


class CollectorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(f"EntropyForge – vzdálený sběrač {APP_VERSION}")
        root.geometry("720x560")
        root.minsize(640, 500)
        root.configure(bg="#080d14")

        self.use_drand = tk.BooleanVar(value=True)
        self.use_nist = tk.BooleanVar(value=True)
        self.use_random_org = tk.BooleanVar(value=False)
        self.api_key = tk.StringVar()
        self.status = tk.StringVar(value="Připraveno. Generátor samotný zůstává zcela offline.")
        self.bundle: bytes | None = None

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TCheckbutton", background="#101925", foreground="#edf5ff")

        outer = tk.Frame(root, bg="#080d14", padx=22, pady=20)
        outer.pack(fill="both", expand=True)
        tk.Label(
            outer,
            text="Vzdálený sběrač entropie",
            bg="#080d14",
            fg="#edf5ff",
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            outer,
            text=(
                "Stáhne vybrané nezávislé zdroje a uloží .efb soubor. Ten potom přidej v EntropyForge "
                "jako externí zdroj. Lokální systémový CSPRNG se tím nikdy nenahrazuje."
            ),
            bg="#080d14",
            fg="#9db0c8",
            justify="left",
            wraplength=660,
            font=("Segoe UI", 10),
        ).pack(anchor="w", fill="x", pady=(5, 15))

        card = tk.Frame(outer, bg="#101925", padx=16, pady=15, highlightthickness=1, highlightbackground="#293a50")
        card.pack(fill="x")
        ttk.Checkbutton(
            card,
            text="drand quicknet – veřejný distribuovaný beacon (bez klíče)",
            variable=self.use_drand,
        ).pack(anchor="w", pady=4)
        ttk.Checkbutton(
            card,
            text="NIST Beacon 2.0 – veřejný podepsaný beacon (bez klíče)",
            variable=self.use_nist,
        ).pack(anchor="w", pady=4)
        ttk.Checkbutton(
            card,
            text="RANDOM.ORG Signed API – atmosférický šum známý poskytovateli",
            variable=self.use_random_org,
            command=self._sync_key_state,
        ).pack(anchor="w", pady=4)
        tk.Label(card, text="RANDOM.ORG API klíč", bg="#101925", fg="#9db0c8").pack(anchor="w", pady=(10, 4))
        self.key_entry = tk.Entry(
            card,
            textvariable=self.api_key,
            show="●",
            bg="#07101a",
            fg="#edf5ff",
            insertbackground="#edf5ff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#293a50",
            highlightcolor="#68d3ff",
        )
        self.key_entry.pack(fill="x", ipady=7)
        self._sync_key_state()

        buttons = tk.Frame(outer, bg="#080d14")
        buttons.pack(fill="x", pady=14)
        self.collect_button = tk.Button(
            buttons,
            text="Stáhnout a vytvořit balíček",
            command=self._start,
            bg="#68d3ff",
            fg="#07131d",
            activebackground="#97f0c1",
            relief="flat",
            padx=14,
            pady=9,
            font=("Segoe UI", 10, "bold"),
        )
        self.collect_button.pack(side="left")
        self.save_button = tk.Button(
            buttons,
            text="Uložit znovu…",
            command=self._save,
            state="disabled",
            bg="#162233",
            fg="#edf5ff",
            disabledforeground="#64758b",
            relief="flat",
            padx=14,
            pady=9,
        )
        self.save_button.pack(side="left", padx=8)

        tk.Label(
            outer,
            textvariable=self.status,
            bg="#080d14",
            fg="#97f0c1",
            anchor="w",
            justify="left",
            wraplength=660,
        ).pack(fill="x", pady=(0, 8))
        self.log = tk.Text(
            outer,
            height=10,
            state="disabled",
            bg="#050a10",
            fg="#c9daee",
            insertbackground="#edf5ff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#293a50",
            padx=10,
            pady=9,
            font=("Consolas", 9),
        )
        self.log.pack(fill="both", expand=True)
        self._append(
            "Veřejné drand/NIST hodnoty přidávají nezávislost a auditovatelnost, ale po zveřejnění "
            "nejsou tajnou entropií.\nRANDOM.ORG data putují soukromě přes TLS, poskytovatel je však zná. "
            ".efb s RANDOM.ORG není šifrovaný; chraň jej jako citlivý soubor."
        )

    def _sync_key_state(self) -> None:
        self.key_entry.configure(state="normal" if self.use_random_org.get() else "disabled")

    def _append(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _progress(self, message: str) -> None:
        self.root.after(0, lambda: (self.status.set(message), self._append(message)))

    def _start(self) -> None:
        key = self.api_key.get().strip() if self.use_random_org.get() else None
        if self.use_random_org.get() and not key:
            messagebox.showerror("EntropyForge", "Pro RANDOM.ORG zadej API klíč.")
            return
        if self.use_random_org.get():
            self.api_key.set("")
        self.collect_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.bundle = None
        thread = threading.Thread(
            target=self._worker,
            kwargs={
                "include_drand": self.use_drand.get(),
                "include_nist": self.use_nist.get(),
                "random_org_key": key,
            },
            daemon=True,
        )
        thread.start()

    def _worker(self, **options: Any) -> None:
        try:
            bundle = collect_bundle(progress=self._progress, **options)
        except Exception as exc:
            self.root.after(0, lambda error=exc: self._failed(error))
            return
        self.root.after(0, lambda: self._ready(bundle))

    def _failed(self, error: Exception) -> None:
        self.collect_button.configure(state="normal")
        self.status.set(f"Chyba: {error}")
        self._append(f"CHYBA: {error}")
        messagebox.showerror("EntropyForge", str(error))

    def _ready(self, bundle: bytes) -> None:
        self.bundle = bundle
        self.collect_button.configure(state="normal")
        self.save_button.configure(state="normal")
        self.status.set("Balíček byl vytvořen. Vyber místo pro uložení.")
        self._append(f"Hotovo: {len(bundle):,} B kanonického .efb souboru.".replace(",", " "))
        self._save()

    def _save(self) -> None:
        if self.bundle is None:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Uložit EntropyForge vzdálený balíček",
            defaultextension=".efb",
            initialfile=f"EntropyForge_remote_{stamp}.efb",
            filetypes=(("EntropyForge bundle", "*.efb"), ("Všechny soubory", "*.*")),
        )
        if not path:
            return
        Path(path).write_bytes(self.bundle)
        self.status.set(f"Uloženo: {path}")
        self._append(f"Uloženo: {path}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", action="store_true", help="neotevírat grafické rozhraní")
    parser.add_argument("--no-drand", action="store_true", help="vynechat veřejný drand beacon")
    parser.add_argument("--no-nist", action="store_true", help="vynechat veřejný NIST beacon")
    parser.add_argument("--random-org", action="store_true", help="přidat RANDOM.ORG Signed API")
    parser.add_argument(
        "--api-key-env",
        default="RANDOM_ORG_API_KEY",
        help="proměnná prostředí s RANDOM.ORG API klíčem",
    )
    parser.add_argument("-o", "--output", help="výstupní .efb soubor")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if not args.cli and not args.output and len(sys.argv if argv is None else argv) <= 1:
        root = tk.Tk()
        CollectorApp(root)
        root.mainloop()
        return 0

    key = os.environ.get(args.api_key_env, "").strip() if args.random_org else None
    if args.random_org:
        os.environ.pop(args.api_key_env, None)
    if args.random_org and not key:
        raise SystemExit(f"Proměnná {args.api_key_env} neobsahuje RANDOM.ORG API klíč.")
    output = Path(args.output or "EntropyForge_remote_bundle.efb")
    try:
        bundle = collect_bundle(
            include_drand=not args.no_drand,
            include_nist=not args.no_nist,
            random_org_key=key,
            progress=lambda message: print(message, flush=True),
        )
        output.write_bytes(bundle)
    except (CollectionError, BundleError, OSError) as exc:
        print(f"CHYBA: {exc}", file=sys.stderr, flush=True)
        return 1
    print(f"Uloženo: {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
