"""Fail unless a standalone SDK checkout vendors exactly this kernel's vectors.

The Go and Rust verifier SDKs live in their own repositories
(github.com/Actenon/sdk-go, github.com/Actenon/sdk-rust) and vendor the
kernel's conformance vectors under ``fixtures/``. Each SDK's own CI checks
those copies against the kernel at the commit in ``fixtures/KERNEL_PIN``.
This script is the reverse direction, run by the kernel's CI against the
SDK commits pinned in ``sdk/standalone-sdk-pins.json``: if this kernel
changes a vector, the check fails until the SDK vendors the new bytes and
the pin moves. Neither side can drift silently.

Checks:
1. ``fixtures/kernel_vector_lock.json`` is byte-identical to this tree's
   ``conformance/vector-lock.json`` (the lock hashes every locked vector).
2. Every pair listed in ``fixtures/KERNEL_UNLOCKED`` (vendored files the
   lock does not cover) is byte-identical to this tree's file.
The SDK's own lock test (run separately with ACTENON_KERNEL_VECTOR_LOCK
pointing at this tree's lock) then checks each vendored file's sha256.

Usage: python scripts/check_standalone_sdk_fixtures.py <sdk checkout dir>
"""

from __future__ import annotations

import sys
from pathlib import Path

KERNEL_ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    sdk_root = Path(argv[1]).resolve()
    fixtures = sdk_root / "fixtures"
    failures: list[str] = []
    checked = 0

    vendored_lock = fixtures / "kernel_vector_lock.json"
    kernel_lock = KERNEL_ROOT / "conformance" / "vector-lock.json"
    if not vendored_lock.is_file():
        failures.append(f"missing {vendored_lock}")
    elif vendored_lock.read_bytes() != kernel_lock.read_bytes():
        failures.append(
            "fixtures/kernel_vector_lock.json differs from this kernel's conformance/vector-lock.json"
        )
    else:
        checked += 1
        print("ok   fixtures/kernel_vector_lock.json == conformance/vector-lock.json")

    unlocked = fixtures / "KERNEL_UNLOCKED"
    if not unlocked.is_file():
        failures.append(f"missing {unlocked}")
    else:
        for line in unlocked.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                failures.append(f"malformed KERNEL_UNLOCKED line: {line!r}")
                continue
            vendored_rel, kernel_rel = parts
            vendored = fixtures / vendored_rel
            kernel_file = KERNEL_ROOT / kernel_rel
            if not kernel_file.is_file():
                failures.append(f"{kernel_rel} listed in KERNEL_UNLOCKED does not exist in this kernel")
            elif not vendored.is_file():
                failures.append(f"fixtures/{vendored_rel} is listed in KERNEL_UNLOCKED but missing")
            elif vendored.read_bytes() != kernel_file.read_bytes():
                failures.append(f"fixtures/{vendored_rel} != {kernel_rel}")
            else:
                checked += 1
                print(f"ok   fixtures/{vendored_rel} == {kernel_rel}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(
            f"{sdk_root.name}: vendored kernel vectors do not match this kernel; "
            "update the SDK's fixtures and move its pin in sdk/standalone-sdk-pins.json",
            file=sys.stderr,
        )
        return 1
    if checked == 0:
        print("FAIL nothing was checked", file=sys.stderr)
        return 1
    print(f"{sdk_root.name}: {checked} vendored kernel files match this kernel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
