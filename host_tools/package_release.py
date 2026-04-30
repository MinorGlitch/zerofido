"""Build and validate a release FAP with the symbol-budget gate applied.

The script optionally invokes UFBT, then delegates the actual export stripping
and budget checks to check_symbol_gate so CI and manual release packaging use
the same policy.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import check_symbol_gate


ROOT = Path(__file__).resolve().parents[1]


def _root_relative(path: Path) -> Path:
    """Resolve CLI paths relative to the repository root unless already absolute."""
    return path if path.is_absolute() else ROOT / path


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse release packaging options without touching the filesystem."""
    parser = argparse.ArgumentParser(description="Build and package the stripped ZeroFIDO release FAP")
    parser.add_argument(
        "--fap",
        type=Path,
        default=Path("dist/zerofido.fap"),
        help="UFBT output FAP to package",
    )
    parser.add_argument(
        "--output-fap",
        type=Path,
        default=check_symbol_gate.FAP_DEFAULT_OUTPUT,
        help="stripped release FAP path",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="package the existing --fap without running UFBT first",
    )
    return parser.parse_args(argv)


def run_ufbt() -> None:
    """Run the normal UFBT build in the repository root."""
    env = os.environ.copy()
    env["ZEROFIDO_DEV_ATTESTATION"] = "0"
    env["ZEROFIDO_RELEASE_DIAGNOSTICS"] = "0"
    subprocess.run([sys.executable, "-m", "ufbt"], cwd=ROOT, check=True, env=env)


def package_release(fap: Path, output_fap: Path, *, skip_build: bool) -> int:
    """Build if requested, then enforce the release FAP symbol budget."""
    if not skip_build:
        run_ufbt()

    return check_symbol_gate.check_fap_symbol_budget(
        _root_relative(fap),
        fix=False,
        output_fap=_root_relative(output_fap),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by tests and manual packaging."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return package_release(args.fap, args.output_fap, skip_build=args.skip_build)


if __name__ == "__main__":
    raise SystemExit(main())
