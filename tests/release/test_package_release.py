"""Tests for the release packaging CLI's orchestration behavior."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from tests.harness import ROOT, load_module

HOST_TOOLS = ROOT / "host_tools"
if str(HOST_TOOLS) not in sys.path:
    sys.path.insert(0, str(HOST_TOOLS))

package_release = load_module("package_release", HOST_TOOLS / "package_release.py")


class PackageReleaseTests(unittest.TestCase):
    def test_default_command_builds_then_packages_release_fap(self) -> None:
        with (
            mock.patch.object(package_release, "run_ufbt") as run_ufbt,
            mock.patch.object(
                package_release.check_symbol_gate, "check_fap_symbol_budget", return_value=0
            ) as check_fap,
            mock.patch.object(package_release, "validate_release_payload", return_value=[]) as validate,
        ):
            status = package_release.main([])

        self.assertEqual(status, 0)
        run_ufbt.assert_called_once_with()
        check_fap.assert_called_once_with(
            ROOT / "dist/zerofido.fap",
            fix=False,
            output_fap=ROOT / "dist/zerofido-release.fap",
        )
        validate.assert_called_once_with(ROOT / "dist/zerofido-release.fap")

    def test_skip_build_only_packages_existing_fap(self) -> None:
        with (
            mock.patch.object(package_release, "run_ufbt") as run_ufbt,
            mock.patch.object(
                package_release.check_symbol_gate, "check_fap_symbol_budget", return_value=0
            ) as check_fap,
            mock.patch.object(package_release, "validate_release_payload", return_value=[]) as validate,
        ):
            status = package_release.main(["--skip-build"])

        self.assertEqual(status, 0)
        run_ufbt.assert_not_called()
        check_fap.assert_called_once()
        validate.assert_called_once_with(ROOT / "dist/zerofido-release.fap")

    def test_release_payload_gate_rejects_diagnostics_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            release_fap = Path(temp_dir) / "zerofido-release.fap"
            release_fap.write_bytes(b"header\x00ZeroFIDO:CTAP\x00cmd=CP-GA status=OK")

            violations = package_release.validate_release_payload(release_fap)

        self.assertTrue(any("CTAP diagnostics" in item for item in violations))
        self.assertTrue(any("diagnostic command" in item for item in violations))
        self.assertTrue(any("ClientPIN diagnostic" in item for item in violations))

    def test_run_ufbt_forces_release_safe_flags(self) -> None:
        with mock.patch.object(package_release.subprocess, "run") as run:
            package_release.run_ufbt()

        run.assert_called_once()
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["ZEROFIDO_RELEASE_DIAGNOSTICS"], "0")


if __name__ == "__main__":
    unittest.main()
