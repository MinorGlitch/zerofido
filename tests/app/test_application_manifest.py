"""Tests for build-profile defaults in application.fam."""

from __future__ import annotations

import runpy
import unittest
from unittest import mock

from tests.harness import ROOT

MANIFEST = ROOT / "application.fam"


class ManifestProfileTests(unittest.TestCase):
    def load_manifest(self, env: dict[str, str] | None = None) -> dict[str, object]:
        captured: dict[str, object] = {}

        def app_stub(**kwargs: object) -> None:
            captured.update(kwargs)

        class AppTypeStub:
            EXTERNAL = "external"

        with mock.patch.dict("os.environ", env or {}, clear=True):
            runpy.run_path(
                str(MANIFEST),
                init_globals={
                    "App": app_stub,
                    "FlipperAppType": AppTypeStub,
                },
            )

        return captured

    def test_default_build_is_nfc_release_safe(self) -> None:
        app = self.load_manifest()

        self.assertIn("ZF_NFC_ONLY", app["cdefines"])
        self.assertIn("ZF_RELEASE_DIAGNOSTICS=0", app["cdefines"])
        self.assertIn("ZF_DEV_ATTESTATION=0", app["cdefines"])
        self.assertIn("ZF_AUTO_ACCEPT_REQUESTS=0", app["cdefines"])
        self.assertIn("ZF_DEV_SCREENSHOT=0", app["cdefines"])
        self.assertIn("ZF_DEV_FIDO2_1=0", app["cdefines"])
        self.assertIn("!nfc_trace.c", app["sources"])
        self.assertIn("!.tmp", app["sources"])
        self.assertIn("!.venv", app["sources"])
        self.assertIn("!*_debug.c", app["sources"])
        self.assertIn("!debug_*.c", app["sources"])
        self.assertIn("!*_test.c", app["sources"])

    def test_development_flags_are_explicit_opt_in(self) -> None:
        app = self.load_manifest(
            {
                "ZEROFIDO_PROFILE": "usb",
                "ZEROFIDO_RELEASE_DIAGNOSTICS": "1",
                "ZEROFIDO_DEV_ATTESTATION": "true",
                "ZEROFIDO_AUTO_ACCEPT_REQUESTS": "on",
                "ZEROFIDO_DEV_SCREENSHOT": "yes",
                "ZEROFIDO_DEV_FIDO2_1": "1",
            }
        )

        self.assertIn("ZF_USB_ONLY", app["cdefines"])
        self.assertIn("ZF_RELEASE_DIAGNOSTICS=1", app["cdefines"])
        self.assertIn("ZF_DEV_ATTESTATION=1", app["cdefines"])
        self.assertIn("ZF_AUTO_ACCEPT_REQUESTS=1", app["cdefines"])
        self.assertIn("ZF_DEV_SCREENSHOT=1", app["cdefines"])
        self.assertIn("ZF_DEV_FIDO2_1=1", app["cdefines"])
        self.assertNotIn("!nfc_trace.c", app["sources"])

    def test_invalid_boolean_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ZEROFIDO_RELEASE_DIAGNOSTICS"):
            self.load_manifest({"ZEROFIDO_RELEASE_DIAGNOSTICS": "maybe"})


if __name__ == "__main__":
    unittest.main()
