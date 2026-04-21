from __future__ import annotations

import csv
import sys
from pathlib import Path


REQUIRED_SYMBOLS = {
    "Function": {
        "furi_hal_usb_set_config",
        "furi_hal_usb_get_config",
        "furi_hal_hid_u2f_set_callback",
        "furi_hal_hid_u2f_get_request",
        "furi_hal_hid_u2f_send_response",
        "furi_hal_crypto_enclave_ensure_key",
        "furi_hal_crypto_enclave_load_key",
        "furi_hal_crypto_enclave_unload_key",
    },
    "Variable": {
        "usb_hid_u2f",
    },
}


def load_symbols(api_symbols: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {"Function": set(), "Variable": set()}
    with api_symbols.open(newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 3:
                continue
            kind, exported, name = row[:3]
            if exported != "+":
                continue
            if kind in found:
                found[kind].add(name)
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_symbol_gate.py <flipperzero-firmware-root>")
        return 2

    root = Path(sys.argv[1])
    api_symbols = root / "targets" / "f7" / "api_symbols.csv"
    if not api_symbols.exists():
        print(f"missing {api_symbols}")
        return 2

    found = load_symbols(api_symbols)
    missing: list[str] = []
    for kind, names in REQUIRED_SYMBOLS.items():
        for name in sorted(names):
            if name not in found[kind]:
                missing.append(f"{kind}: {name}")

    if missing:
        print("symbol gate failed")
        for item in missing:
            print(f"  - {item}")
        return 1

    print("symbol gate passed")
    print(f"checked {api_symbols}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

