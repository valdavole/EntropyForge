# EntropyForge 3.3

[Čeština](README.md) | [English](README.en.md)

A local generator for cryptographically secure numbers, random choices,
passwords, tokens, and UUIDs with matching Python and HTML interfaces.

Both interfaces can be switched completely between Czech and English at
runtime. The language preference is stored locally only and does not alter
the cryptographic construction, entered data, or generated output.

EntropyForge uses the operating system or browser CSPRNG as the foundation
for its standard modes. It can optionally add domain-separated
diversification, external sources, and a separate strict Windows CNG
profile.

> [!IMPORTANT]
> EntropyForge is not a FIPS, NIST, EUCC, or Common Criteria certified
> product. The strict profile uses a Windows cryptographic module, but
> certification of the underlying module is not certification of this
> application.

## Highlights

- Python 3.10+ with no third-party runtime packages.
- Standalone HTML edition using Web Crypto.
- Complete Czech and English UI, including errors, diagnostics, and reports.
- Direct strict `BCryptGenRandom` profile on Windows.
- Fail-closed behavior with no silent fallback.
- Uniform range mapping through rejection sampling.
- Unique selections through a partial Fisher–Yates algorithm.
- Passwords, Hex/Base64 URL tokens, and UUID v4.
- Up to eight local files or imported `.efb` bundles.
- Separate collector for drand, NIST Beacon, and optional RANDOM.ORG Signed API.
- Shared known-answer vectors for Python and HTML.
- Automated Linux and Windows tests plus CodeQL analysis.

## Quick start

### Python on Windows

1. Install Python 3.10 or newer.
2. Download and extract the latest package from GitHub Releases.
3. Run `run_windows.bat`.

Alternatively:

```powershell
py -3 entropy_forge.py
```

### Standalone HTML

Open `EntropyForge.html` in a modern browser. This edition remains offline
and uses `crypto.getRandomValues()`. The strict Windows CNG profile is not
available when the file is opened directly.

### HTML with the strict Windows CNG profile

```text
run_validated_html.bat
```

The script starts a loopback server on a random `127.0.0.1` port. The bridge
checks Host, Origin, and a session cookie, does not provide CORS, and does
not log generated values.

Check profile readiness without generating output:

```text
check_validated_profile.bat
```

Run a live Windows CNG test:

```text
run_windows_cng_live_test.bat
```

## Modes

| Mode | Output foundation | Supplementary inputs |
| --- | --- | --- |
| Strict Windows CNG | `BCryptGenRandom` | none; the custom mixer is excluded |
| System CSPRNG | `os.urandom()` / Web Crypto | none |
| Diversified software | system CSPRNG | HMAC-SHA-512 and event timing |
| Multi-source | system CSPRNG | HMAC, timing, and up to eight external sources |

Mouse and keyboard timing is actively mixed as bonus diversification in
diversified modes. It is not assigned a specific number of min-entropy bits,
and security does not depend on it.

## Requirements

- Python 3.10 or newer.
- Tkinter for the Python GUI.
- A modern browser with Web Crypto for HTML.
- Node.js 24 for development tests only.
- Windows for the direct CNG profile.

Normal use does not require packages from PyPI or npm.

## Tests

On Windows:

```text
run_tests.bat
```

On any supported platform:

```bash
python tests/run_all.py
```

The suite covers unit and integration tests, known-answer vectors, simulated
HTML UI behavior, language switching, CSP, the strict backend, the loopback
bridge, external formats, and remote bundles.

Extended statistical campaign:

```bash
python tests/statistical_campaign.py
```

Statistical tests are implementation diagnostics, not proof of
unpredictability or source certification.

## Editing the HTML edition

The inline JavaScript is locked by a SHA-256 value in the Content Security
Policy. After every change to the `<script>` content, run:

```bash
python tools/update_html_csp.py
python tools/update_html_csp.py --check
```

Without the updated hash, the browser will block the script.

## Repository structure

| Path | Purpose |
| --- | --- |
| `entropy_forge.py` | Python GUI and generator |
| `EntropyForge.html` | standalone HTML edition |
| `validated_backend.py` | direct Windows CNG API and FIPS policy check |
| `validated_bridge.py` | secured loopback bridge for HTML |
| `entropy_bundle.py` | `.efb` parser and validation |
| `remote_entropy_collector.py` | separate network collector |
| `tests/` | automated and statistical tests |
| `certification/` | working material for audit and laboratory review |
| `tools/` | development and maintenance utilities |
| `.github/` | CI, CodeQL, Dependabot, and contribution templates |

The detailed Czech user guide is in `README.txt`. The construction and its
limitations are documented in `SECURITY_MODEL.txt`.

## Security

Do not report vulnerabilities through a public issue. Follow
[`SECURITY.md`](SECURITY.md). The exact threat model and claim limitations
are documented in `SECURITY_MODEL.txt`.

## Contributing

Pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
run the complete test suite first. Changes to the cryptographic construction
must include tests, a security-impact explanation, and updated documentation.

## License

Copyright © 2026 Filip Novák.

Released under the [MIT License](LICENSE). The license permits use,
modification, and redistribution while retaining the copyright and license
notice.
