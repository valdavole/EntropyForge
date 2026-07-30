#!/usr/bin/env python3
"""Run the Python suite and, when available, the HTML/Node suite."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent


def run(command: list[str]) -> None:
    print(f"\n> {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=TEST_DIR, check=True)


def main() -> int:
    run([sys.executable, "-m", "unittest", "discover", "-v", "-p", "test_*.py"])
    node = shutil.which("node")
    if node:
        run([node, "test_html_core.mjs"])
    else:
        print("\nNode.js nebyl nalezen; HTML core test byl přeskočen.")
    print("\nVšechny dostupné testy prošly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
