# ZeroFIDO

![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue)
![Platform: Flipper Zero](https://img.shields.io/badge/platform-Flipper%20Zero-orange)
![Protocols: FIDO2 + U2F](https://img.shields.io/badge/protocols-FIDO2%20%2B%20U2F-green)

ZeroFIDO turns a Flipper Zero into a passkey and security-key app. Install the `.fap`, open the app,
and approve sign-ins on services that support FIDO2/WebAuthn or legacy U2F.

The app stores credentials on the Flipper, asks for local approval, supports `ClientPIN`, and speaks
the CTAP2/FIDO2 protocol used by browsers and security keys. USB HID works as the main transport.
NFC remains in development, with working iOS flows.

ZeroFIDO runs on general-purpose Flipper hardware. Treat it as a useful authenticator app with
software-stored credentials, local approval, and local software attestation. For certified
hardware-backed security, use a certified security key.

## Supported

| Capability | Status |
| --- | --- |
| USB HID | Supported |
| NFC | In development; works with iOS flows |
| U2F V2 | Supported |
| FIDO2.0 / CTAP2.0 | Supported |
| FIDO2.1 / CTAP2.1 | Experimental profile |
| `ClientPIN` | Supported |
| Discoverable credentials | Supported |
| Attestation | Per-install software attestation |

ZeroFIDO targets stock Flipper Zero firmware `1.4.3` and builds as an external `.fap` in the Tools
category.

## Install

Download a release `.fap` when one is published, then copy it to your Flipper SD card under the
Tools apps folder. You can also install it through qFlipper or Flipper Lab by choosing the `.fap`
file.

To build and launch from source:

```bash
uv sync
uv run python -m ufbt launch
```

## How To Use

1. Open ZeroFIDO on the Flipper.
2. Choose USB HID for normal desktop browser use.
3. Use NFC for iOS flows while NFC support matures.
4. Register the Flipper as a passkey or security key on a site that supports WebAuthn/FIDO2.
5. Approve credential creation or sign-in on the Flipper screen.

For older services, use the same app through the legacy U2F flow.

## Features

- WebAuthn/FIDO2 registration and sign-in
- Legacy U2F register, authenticate, and version handling
- Local approval for credential creation and assertions
- `ClientPIN`, retry state, and PIN token flow
- Discoverable credentials for resident-key/passkey-style use
- Runtime profile selection for FIDO2.0 and experimental FIDO2.1 metadata
- USB HID transport and NFC transport work in the app runtime

## Build From Source

The project uses `uv` for Python tooling and `ufbt` for Flipper builds.

```bash
uv sync
uv run python -m ufbt
```

Build and launch on a connected Flipper:

```bash
uv run python -m ufbt launch
```

The Python toolchain declares Python `3.14+` in `pyproject.toml`. C validation expects
`clang-format`, `clang-tidy`, `cppcheck`, and a host C compiler.

On macOS:

```bash
brew install llvm cppcheck
```

## Validation

Run the Python tests:

```bash
uv run python -m unittest discover tests
```

Run C formatting and analyzers:

```bash
uv run python tools/check_c.py format
uv run python tools/check_c.py tidy
uv run python tools/check_c.py cppcheck
uv run python tools/check_c.py all
```

Run native protocol regressions:

```bash
uv run python tools/run_protocol_regressions.py
```

Check SDK symbols against a local Flipper firmware checkout:

```bash
uv run python host_tools/check_symbol_gate.py <flipper-firmware-checkout>
```

## Developer Tools

Probe a FIDO HID device during development:

```bash
uv run python host_tools/ctaphid_probe.py --cmd list
uv run python host_tools/ctaphid_probe.py --cmd getinfo
uv run python host_tools/ctaphid_probe.py --cmd makecredential
uv run python host_tools/ctaphid_probe.py --cmd getassertion
```

Capture NFC trace lines from the Flipper USB CDC console:

```bash
uv run python host_tools/nfc_trace_console.py --port <serial-port>
```

## Release Packaging

Build a release `.fap` and verify that only the app entry point remains exported:

```bash
uv run python host_tools/package_release.py
```

Package an existing `dist/zerofido.fap` without rebuilding:

```bash
uv run python host_tools/package_release.py --skip-build
```

The packaged artifact lands at `dist/zerofido-release.fap`.

## Metadata And Attestation

ZeroFIDO generates local attestation material on the device. Public builds do not provide
hardware-backed vendor provenance, enterprise attestation, or a FIDO Metadata Service trust path.
Private relying parties can pin a local certificate when that fits their test setup.

Export metadata for certification tools:

Create `metadata/statement.json` from the authenticator you are testing. The `metadata/`
directory is ignored because these files are local certification artifacts.

```bash
uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile fido2-2.0 \
  --client-pin-state unset \
  --output metadata/metadata-ctap20.json

uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile fido2-2.1-experimental \
  --client-pin-state unset \
  --output metadata/metadata-ctap21-experimental.json
```

For U2F, export metadata from the same device certificate returned by U2F Register:

```bash
uv run python host_tools/ctaphid_probe.py --cmd u2fregister --u2f-cert-out metadata/u2f-attestation.der
uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile u2f \
  --u2f-attestation-cert metadata/u2f-attestation.der \
  --output metadata/metadata-u2f.json
```

## Security Notes

- Flipper Zero hardware does not give this app a secure element for credential keys.
- Software attestation proves a local app install identity, not vendor hardware provenance.
- Physical access to the device changes the threat model.
- Diagnostic and conformance builds may log protocol data. Review build flags before release use.

## License

ZeroFIDO uses the GNU General Public License, version 3 only. See [`LICENSE`](LICENSE).

Dependency and provenance notes live in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
