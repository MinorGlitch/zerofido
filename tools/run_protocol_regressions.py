"""Compile and run the host-native protocol regression binaries.

The script builds the CTAP/PIN/store regression suite and the transport/U2F
suite with the same fake Flipper headers used by CI, then executes both binaries.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "tests" / "native" / "protocol" / "runner.c"
NATIVE_TRANSPORT_SOURCE = ROOT / "tests" / "native" / "transport_u2f" / "runner.c"
NATIVE_INCLUDE = ROOT / "tests" / "native" / "include"
NATIVE_BINARY = ROOT / ".tmp" / "native_protocol_regressions"
NATIVE_TRANSPORT_BINARY = ROOT / ".tmp" / "native_transport_u2f_regressions"
POLICY_SOURCE = ROOT / "src" / "ctap" / "policy.c"


def run(cmd: list[str]) -> None:
    """Echo and run one compiler or test command in the repository root."""
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> None:
    """Build both native regression binaries and fail on the first error."""
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("missing host C compiler")

    policy = POLICY_SOURCE.read_text()
    if "zf_ctap_request_uses_allow_list" not in policy:
        raise SystemExit("policy is missing allowList semantics helper")

    NATIVE_BINARY.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DZF_HOST_TEST",
            "-DZF_RELEASE_DIAGNOSTICS=1",
            "-I",
            str(NATIVE_INCLUDE),
            "-I",
            str(ROOT / "src"),
            str(NATIVE_SOURCE),
            "-o",
            str(NATIVE_BINARY),
        ]
    )
    run([str(NATIVE_BINARY)])
    run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DZF_HOST_TEST",
            "-DZF_RELEASE_DIAGNOSTICS=1",
            "-I",
            str(NATIVE_INCLUDE),
            "-I",
            str(ROOT / "src"),
            str(NATIVE_TRANSPORT_SOURCE),
            "-o",
            str(NATIVE_TRANSPORT_BINARY),
        ]
    )
    run([str(NATIVE_TRANSPORT_BINARY)])


if __name__ == "__main__":
    main()
