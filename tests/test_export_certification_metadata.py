from __future__ import annotations

import json
import unittest
from pathlib import Path

from host_tools.export_certification_metadata import (
    ICON_DATA_URL,
    MDS3_LEGAL_HEADER,
    build_certification_metadata,
)


class ExportCertificationMetadataTests(unittest.TestCase):
    def test_build_certification_metadata_preserves_ctap21_legal_header_and_upv(self) -> None:
        root = Path(__file__).resolve().parents[1]
        statement = json.loads((root / "docs" / "12-metadata-statement.json").read_text())

        exported = build_certification_metadata(statement)

        self.assertEqual(exported["legalHeader"], MDS3_LEGAL_HEADER)
        self.assertIn({"major": 1, "minor": 1}, exported["upv"])

    def test_build_certification_metadata_normalizes_stale_ctap21_metadata_fields(self) -> None:
        statement = {
            "legalHeader": "https://fidoalliance.org/metadata/metadata-statement-legal-header/",
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "upv": [{"major": 1, "minor": 0}],
            "authenticatorGetInfo": {
                "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "versions": ["FIDO_2_0", "U2F_V2", "FIDO_2_0"],
            },
            "userVerificationDetails": [[{"userVerificationMethod": "presence_internal"}]],
        }

        exported = build_certification_metadata(statement)

        self.assertEqual(exported["legalHeader"], MDS3_LEGAL_HEADER)
        self.assertEqual(exported["upv"], [{"major": 1, "minor": 1}, {"major": 1, "minor": 0}])
        self.assertEqual(
            exported["authenticatorGetInfo"]["versions"],
            ["FIDO_2_1", "FIDO_2_0", "U2F_V2"],
        )

    def test_build_certification_metadata_normalizes_statement_aaguids(self) -> None:
        root = Path(__file__).resolve().parents[1]
        statement = json.loads((root / "docs" / "12-metadata-statement.json").read_text())

        exported = build_certification_metadata(statement)

        self.assertEqual(exported["aaguid"], "b51a976a-0b02-40aa-9d8a-36c8b91bbd1a")
        self.assertEqual(
            exported["authenticatorGetInfo"]["aaguid"],
            "b51a976a0b0240aa9d8a36c8b91bbd1a",
        )
        self.assertEqual(exported["authenticationAlgorithms"], ["secp256r1_ecdsa_sha256_raw"])
        self.assertEqual(exported["matcherProtection"], ["software"])
        self.assertEqual(exported["icon"], ICON_DATA_URL)
        self.assertNotIn("friendlyNames", exported)
        self.assertNotIn("attestationCertificateKeyIdentifiers", exported)
        self.assertNotIn("isSecondFactorOnly", exported)

    def test_build_certification_metadata_prefers_live_get_info(self) -> None:
        statement = {
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "authenticatorGetInfo": {
                "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "versions": ["FIDO_2_1", "FIDO_2_0"],
            },
            "userVerificationDetails": [[{"userVerificationMethod": "presence_internal"}]],
        }
        live_get_info = {
            1: ["FIDO_2_1", "FIDO_2_0", "U2F_V2"],
            3: bytes.fromhex("b51a976a0b0240aa9d8a36c8b91bbd1a"),
            4: {"rk": True, "up": True, "plat": False, "clientPin": False},
            5: 1024,
            6: [1],
            9: ["usb"],
            10: [{"alg": -7, "type": "public-key"}],
            13: 4,
            14: 10000,
        }

        exported = build_certification_metadata(statement, live_get_info=live_get_info)

        self.assertEqual(exported["aaguid"], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        self.assertEqual(
            exported["authenticatorGetInfo"]["aaguid"],
            "b51a976a0b0240aa9d8a36c8b91bbd1a",
        )
        self.assertEqual(
            exported["authenticatorGetInfo"]["versions"],
            ["FIDO_2_1", "FIDO_2_0", "U2F_V2"],
        )
        self.assertEqual(exported["userVerificationDetails"], [[{"userVerificationMethod": "presence_internal"}]])

    def test_build_certification_metadata_u2f_profile_removes_fido2_only_fields(self) -> None:
        root = Path(__file__).resolve().parents[1]
        statement = json.loads((root / "docs" / "12-metadata-statement.json").read_text())

        exported = build_certification_metadata(statement, profile="u2f")

        self.assertEqual(exported["protocolFamily"], "u2f")
        self.assertEqual(exported["upv"], [{"major": 1, "minor": 2}])
        self.assertEqual(exported["publicKeyAlgAndEncodings"], ["ecc_x962_raw"])
        self.assertEqual(exported["matcherProtection"], ["software"])
        self.assertEqual(exported["icon"], ICON_DATA_URL)
        self.assertEqual(exported["userVerificationDetails"], [[{"userVerificationMethod": "presence_internal"}]])
        self.assertNotIn("aaguid", exported)
        self.assertNotIn("aaid", exported)
        self.assertNotIn("authenticatorGetInfo", exported)
        self.assertNotIn("isSecondFactorOnly", exported)
        self.assertNotIn("friendlyNames", exported)


if __name__ == "__main__":
    unittest.main()
