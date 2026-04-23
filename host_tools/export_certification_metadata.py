from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

import cbor2

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATEMENT_PATH = ROOT / "docs" / "12-metadata-statement.json"
MDS3_LEGAL_HEADER = (
    "Submission of this statement and retrieval and use of this statement indicates acceptance "
    "of the appropriate agreement located at "
    "https://fidoalliance.org/metadata/metadata-legal-terms/."
)
CTAP21_VERSION = {"major": 1, "minor": 1}
FIDO21_VERSION_STRING = "FIDO_2_1"
ICON_DATA_URL = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+tm2cAAAAASUVORK5CYII="
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from host_tools import ctaphid_probe


def compact_aaguid(value: str) -> str:
    return value.replace("-", "").lower()


def normalize_aaguid(value: str) -> str:
    compact = compact_aaguid(value)
    if len(compact) != 32:
        return compact
    return (
        f"{compact[0:8]}-{compact[8:12]}-{compact[12:16]}-"
        f"{compact[16:20]}-{compact[20:32]}"
    )


def normalize_live_get_info(decoded: dict[Any, Any]) -> dict[str, Any]:
    exported: dict[str, Any] = {}
    if 1 in decoded:
        exported["versions"] = decoded[1]
    if 2 in decoded:
        exported["extensions"] = decoded[2]
    if 3 in decoded and isinstance(decoded[3], (bytes, bytearray)):
        exported["aaguid"] = compact_aaguid(bytes(decoded[3]).hex())
    if 4 in decoded:
        exported["options"] = decoded[4]
    if 5 in decoded:
        exported["maxMsgSize"] = decoded[5]
    if 6 in decoded:
        exported["pinUvAuthProtocols"] = decoded[6]
    if 7 in decoded:
        exported["maxCredentialCountList"] = decoded[7]
    if 8 in decoded:
        exported["maxCredentialIdLength"] = decoded[8]
    if 9 in decoded:
        exported["transports"] = decoded[9]
    if 10 in decoded:
        exported["algorithms"] = decoded[10]
    if 11 in decoded:
        exported["maxSerializedLargeBlobArray"] = decoded[11]
    if 12 in decoded:
        exported["forcePINChange"] = decoded[12]
    if 13 in decoded:
        exported["minPINLength"] = decoded[13]
    if 14 in decoded:
        exported["firmwareVersion"] = decoded[14]
    if 15 in decoded:
        exported["maxCredBlobLength"] = decoded[15]
    if 16 in decoded:
        exported["maxRPIDsForSetMinPINLength"] = decoded[16]
    if 17 in decoded:
        exported["preferredPlatformUvAttempts"] = decoded[17]
    if 18 in decoded:
        exported["uvModality"] = decoded[18]
    if 19 in decoded:
        exported["certifications"] = decoded[19]
    if 20 in decoded:
        exported["remainingDiscoverableCredentials"] = decoded[20]
    if 21 in decoded:
        exported["vendorPrototypeConfigCommands"] = decoded[21]
    return exported


def normalize_upv(value: Any) -> list[dict[str, int]]:
    versions: list[dict[str, int]] = []
    seen: set[tuple[int, int]] = set()

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            major = item.get("major")
            minor = item.get("minor")
            if not isinstance(major, int) or not isinstance(minor, int):
                continue
            key = (major, minor)
            if key in seen:
                continue
            seen.add(key)
            versions.append({"major": major, "minor": minor})

    if (CTAP21_VERSION["major"], CTAP21_VERSION["minor"]) not in seen:
        versions.insert(0, dict(CTAP21_VERSION))
    return versions


def normalize_statement_get_info(get_info: Any) -> dict[str, Any]:
    normalized = copy.deepcopy(get_info) if isinstance(get_info, dict) else {}
    versions = normalized.get("versions")
    if isinstance(versions, list):
        deduped_versions: list[str] = []
        seen_versions: set[str] = set()
        for item in versions:
            if not isinstance(item, str) or item in seen_versions:
                continue
            seen_versions.add(item)
            deduped_versions.append(item)
        if FIDO21_VERSION_STRING not in seen_versions:
            deduped_versions.insert(0, FIDO21_VERSION_STRING)
        normalized["versions"] = deduped_versions
    else:
        normalized["versions"] = [FIDO21_VERSION_STRING]

    if "aaguid" in normalized and isinstance(normalized["aaguid"], str):
        normalized["aaguid"] = compact_aaguid(normalized["aaguid"])
    return normalized


def build_u2f_metadata(statement: dict[str, Any]) -> dict[str, Any]:
    exported = copy.deepcopy(statement)
    exported.pop("aaguid", None)
    exported.pop("aaid", None)
    exported.pop("authenticatorGetInfo", None)
    exported.pop("isSecondFactorOnly", None)
    exported.pop("friendlyNames", None)
    exported["protocolFamily"] = "u2f"
    exported["upv"] = [{"major": 1, "minor": 2}]
    exported["publicKeyAlgAndEncodings"] = ["ecc_x962_raw"]
    exported["userVerificationDetails"] = [[{"userVerificationMethod": "presence_internal"}]]
    exported["matcherProtection"] = ["software"]
    exported["icon"] = ICON_DATA_URL
    return exported


def build_certification_metadata(
    statement: dict[str, Any],
    live_get_info: dict[Any, Any] | None = None,
    profile: str = "fido2",
) -> dict[str, Any]:
    if profile == "u2f":
        return build_u2f_metadata(statement)

    exported = copy.deepcopy(statement)
    exported["legalHeader"] = MDS3_LEGAL_HEADER
    exported["upv"] = normalize_upv(exported.get("upv"))
    if "aaguid" in exported and isinstance(exported["aaguid"], str):
        exported["aaguid"] = normalize_aaguid(exported["aaguid"])
    exported.pop("friendlyNames", None)
    exported.pop("aaid", None)
    exported.pop("attestationCertificateKeyIdentifiers", None)
    exported.pop("supportedExtensions", None)
    exported.pop("assertionScheme", None)
    exported.pop("authenticationAlgorithm", None)
    exported.pop("publicKeyAlgAndEncoding", None)
    exported.pop("operatingEnv", None)
    exported.pop("isSecondFactorOnly", None)
    exported["matcherProtection"] = ["software"]
    exported["icon"] = ICON_DATA_URL

    get_info = normalize_statement_get_info(exported.get("authenticatorGetInfo", {}))
    if live_get_info is not None:
        get_info = normalize_live_get_info(live_get_info)

    exported["authenticatorGetInfo"] = get_info
    return exported


def query_live_get_info(args: argparse.Namespace) -> dict[Any, Any]:
    device = ctaphid_probe.open_device(args)
    try:
        nonce = os.urandom(8)
        _, _, init_payload = ctaphid_probe.transact(
            device, ctaphid_probe.BROADCAST_CID, ctaphid_probe.INIT, nonce, args.timeout_ms, args.verbose
        )
        cid = ctaphid_probe.expect_init_response(
            ctaphid_probe.BROADCAST_CID, ctaphid_probe.INIT, init_payload, nonce
        )
        response_cid, response_cmd, response_payload = ctaphid_probe.transact(
            device,
            cid,
            ctaphid_probe.CBOR,
            bytes([ctaphid_probe.CTAP_GET_INFO]),
            args.timeout_ms,
            args.verbose,
        )
        if response_cmd == ctaphid_probe.ERROR:
            raise RuntimeError(f"CTAPHID error during GetInfo transport: 0x{response_payload[0]:02x}")
        if response_cmd != ctaphid_probe.CBOR:
            raise RuntimeError(f"unexpected CBOR response cmd 0x{response_cmd:02x}")
        if response_cid != cid:
            raise RuntimeError(f"unexpected CBOR response cid 0x{response_cid:08x}")
        if not response_payload:
            raise RuntimeError("empty GetInfo response")
        if response_payload[0] != 0x00:
            raise RuntimeError(f"GetInfo returned CTAP status 0x{response_payload[0]:02x}")
        decoded = cbor2.loads(response_payload[1:])
        if not isinstance(decoded, dict):
            raise RuntimeError("GetInfo did not decode to a CBOR map")
        return decoded
    finally:
        device.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export certification-tool metadata by combining the canonical statement with live GetInfo."
    )
    parser.add_argument(
        "--statement",
        default=str(DEFAULT_STATEMENT_PATH),
        help="Path to the canonical metadata statement JSON",
    )
    parser.add_argument(
        "--output",
        default="metadata.json",
        help="Path to write the certification metadata JSON",
    )
    parser.add_argument(
        "--from-device",
        action="store_true",
        help="Query the attached authenticator and replace authenticatorGetInfo with live GetInfo output",
    )
    parser.add_argument(
        "--profile",
        choices=("fido2", "u2f"),
        default="fido2",
        help="Metadata profile to export for certification tooling",
    )
    parser.add_argument("--path", help="Explicit hidapi path to open instead of auto-selecting a matching device")
    parser.add_argument("--timeout-ms", type=int, default=3000, help="Read timeout for each packet")
    parser.add_argument("--verbose", action="store_true", help="Print TX/RX packets during the live query")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    statement_path = Path(args.statement)
    output_path = Path(args.output)

    statement = json.loads(statement_path.read_text())
    live_get_info = query_live_get_info(args) if args.from_device and args.profile == "fido2" else None
    exported = build_certification_metadata(
        statement, live_get_info=live_get_info, profile=args.profile
    )
    output_path.write_text(json.dumps(exported, indent=2) + "\n")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
