# ZeroFIDO

![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue)
![Platform: Flipper Zero](https://img.shields.io/badge/platform-Flipper%20Zero-orange)
![Protocols: FIDO2 + U2F](https://img.shields.io/badge/protocols-FIDO2%20%2B%20U2F-green)

ZeroFIDO turns a Flipper Zero into a passkey and security-key app. Install the `.fap`,
open the app, and approve sign-ins on services that support FIDO2/WebAuthn or legacy U2F.

The app stores credentials on the Flipper, asks for local approval, supports `ClientPIN`,
and speaks the CTAP2/FIDO2 protocol used by browsers and security keys. USB HID is the
desktop browser transport. NFC builds are used for phone flows and conformance work.

ZeroFIDO runs on general-purpose Flipper hardware. Treat it as a useful authenticator app
with software-stored credentials, local approval, and local software attestation. For
certified hardware-backed security, use a certified security key.

## Supported

| Capability | Status |
| --- | --- |
| USB HID | Supported in the `usb` and `full` build profiles |
| NFC | Supported in the default `nfc` build profile |
| U2F V2 | Supported |
| FIDO2.0 / CTAP2.0 | Supported |
| FIDO2.1 / CTAP2.1 | Experimental metadata profile |
| `ClientPIN` | Supported |
| Discoverable credentials | Supported |
| Attestation | Local software attestation, optional per relying-party request |

ZeroFIDO builds as an external `.fap` in the Flipper Tools category.

## Install

Download a release `.fap` when one is published, then copy it to your Flipper SD card under
the Tools apps folder. You can also install it through qFlipper or Flipper Lab by choosing
the `.fap` file.

To build from source, install `uv`, then sync the Python tools:

```bash
uv sync
```

## Build Profiles

The app manifest reads `ZEROFIDO_PROFILE` at build time. The default is `nfc`.
Release builds also default to `ZEROFIDO_RELEASE_DIAGNOSTICS=0` and
`ZEROFIDO_DEV_ATTESTATION=0`.

| Profile | Build flag | Use |
| --- | --- | --- |
| NFC only | `ZEROFIDO_PROFILE=nfc` | Phone and NFC conformance work. This is the default. |
| USB HID only | `ZEROFIDO_PROFILE=usb` | Desktop browser WebAuthn and U2F testing. |
| Full | `ZEROFIDO_PROFILE=full` | Builds both transports and lets the app choose at runtime. |

Release-default builds do not compile the NFC trace implementation and do not compile the bundled
development attestation chain. Diagnostic and private-trust builds must opt in explicitly:

```bash
ZEROFIDO_PROFILE=nfc ZEROFIDO_RELEASE_DIAGNOSTICS=1 uv run python -m ufbt
ZEROFIDO_PROFILE=usb ZEROFIDO_DEV_ATTESTATION=1 uv run python -m ufbt
```

Build the profile you want:

```bash
ZEROFIDO_PROFILE=nfc uv run python -m ufbt
ZEROFIDO_PROFILE=usb uv run python -m ufbt
ZEROFIDO_PROFILE=full uv run python -m ufbt
```

Build and launch on a connected Flipper:

```bash
ZEROFIDO_PROFILE=usb uv run python -m ufbt launch
```

The normal build output is `dist/zerofido.fap`.

The Python toolchain declares Python `3.14+` in `pyproject.toml`. C validation expects
`clang-format`, `clang-tidy`, `cppcheck`, and a host C compiler.

On macOS:

```bash
brew install llvm cppcheck
```

## How To Use

1. Build or install the profile that matches the transport you need.
2. Open ZeroFIDO on the Flipper.
3. Register the Flipper as a passkey or security key on a site that supports WebAuthn/FIDO2.
4. Approve credential creation or sign-in on the Flipper screen.

For older services, use the same app through the legacy U2F flow.

## Features

- WebAuthn/FIDO2 registration and sign-in
- Legacy U2F register, authenticate, and version handling
- Local approval for credential creation and assertions
- `ClientPIN`, retry state, and PIN token flow
- Discoverable credentials for resident-key/passkey-style use
- Build-time transport profiles for USB HID, NFC, and full builds
- Metadata exports for FIDO2.0, experimental FIDO2.1, and U2F certification tooling

## Validation

Run the maintained host-tool tests:

```bash
uv run python -m unittest \
  tests.test_ctaphid_probe \
  tests.test_export_certification_metadata \
  tests.test_conformance_suite \
  tests.test_symbol_gate
```

Run native protocol regressions:

```bash
uv run python tools/run_protocol_regressions.py
```

Those native regressions cover packed attestation, runtime `Attest: none`, explicit
`attestationFormats: ["none"]`, and the no-downgrade behavior when packed attestation is
required.

Run C formatting and analyzers:

```bash
uv run python tools/check_c.py format
uv run python tools/check_c.py format --fix
uv run python tools/check_c.py tidy
uv run python tools/check_c.py cppcheck
uv run python tools/check_c.py native
uv run python tools/check_c.py all
```

Check SDK symbols against a local Flipper firmware checkout:

```bash
uv run python host_tools/check_symbol_gate.py --sdk-root <flipper-firmware-checkout>
```

Check and package a built `.fap` with the release export gate:

```bash
uv run python host_tools/check_symbol_gate.py \
  --fap dist/zerofido.fap \
  --output-fap dist/zerofido-release.fap
```

## Host Tools

List and probe FIDO HID devices:

```bash
uv run python host_tools/ctaphid_probe.py --cmd list
uv run python host_tools/ctaphid_probe.py --cmd init
uv run python host_tools/ctaphid_probe.py --cmd getinfo
uv run python host_tools/ctaphid_probe.py --cmd makecredential
uv run python host_tools/ctaphid_probe.py --cmd getassertion
```

Run U2F transport probes:

```bash
uv run python host_tools/ctaphid_probe.py --cmd u2fversion
uv run python host_tools/ctaphid_probe.py --cmd u2fregister --u2f-cert-out metadata/u2f-attestation.der
uv run python host_tools/ctaphid_probe.py --cmd u2finvalidcla
uv run python host_tools/ctaphid_probe.py --cmd u2fversiondata
uv run python host_tools/ctaphid_probe.py --cmd u2fauthinvalid
```

Capture a FIDO2 attestation leaf certificate from `MakeCredential`:

```bash
uv run python host_tools/ctaphid_probe.py \
  --cmd makecredential \
  --fido2-cert-out metadata/fido2-attestation.der
```

Capture NFC trace lines from the Flipper USB CDC console:

```bash
uv run python host_tools/nfc_trace_console.py --port auto
uv run python host_tools/nfc_trace_console.py --port <serial-port> --level info --output .tmp/nfc-trace.log
```

Capture reconnecting crash logs from the same CDC console:

```bash
uv run python tools/flipper_crash_log.py --port auto --output .tmp/flipper-crash.log
```

Print firmware footprint data after building:

```bash
uv run python host_tools/size_ledger.py --artifact dist/zerofido.fap --artifact dist/zerofido-release.fap
```

## Release Packaging

Build a release `.fap` for the selected profile and verify that only the app entry point
remains exported:

```bash
ZEROFIDO_PROFILE=usb \
ZEROFIDO_RELEASE_DIAGNOSTICS=0 \
ZEROFIDO_DEV_ATTESTATION=0 \
uv run python host_tools/package_release.py
```

Package an existing `dist/zerofido.fap` without rebuilding:

```bash
uv run python host_tools/package_release.py \
  --skip-build \
  --fap dist/zerofido.fap \
  --output-fap dist/zerofido-release.fap
```

The packaged artifact lands at `dist/zerofido-release.fap` by default.

## GitHub Releases

The `Build profiles` workflow verifies every push and pull request. The `Release`
workflow publishes GitHub Releases from existing `v*` tags.

Create and push a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow rebuilds the `nfc`, `usb`, and `full` profiles with
`ZEROFIDO_RELEASE_DIAGNOSTICS=0` and `ZEROFIDO_DEV_ATTESTATION=0`, packages only the stripped
`*-release.fap` artifacts, and uploads `SHA256SUMS`.

You can also run the workflow manually from GitHub Actions with an existing tag such as `v1.0.0`.

## Metadata And Attestation

ZeroFIDO generates local attestation material on the device. Public builds do not provide
hardware-backed vendor provenance, enterprise attestation, or a FIDO Metadata Service trust
path. Private relying parties can pin a local certificate when that fits their test setup.

Attestation is a provenance signal, not the credential itself. A relying party that requests
`attestation: "none"` gets a WebAuthn registration response with `fmt: "none"` and an empty
attestation statement. In that mode ZeroFIDO still creates the credential keypair, but it does
not expose the local attestation certificate chain and does not sign the registration with the
local attestation key. If the relying party requests direct attestation, ZeroFIDO returns packed
attestation from the local software attestation material for that install.

The on-device Settings screen also has an attestation mode. `Attest: none` makes `fmt: "none"`
the default MakeCredential response unless the CTAP request explicitly lists a supported
attestation format preference. `Attest: packed` allows local software packed attestation when
requested.

Metadata and captured attestation certificates are local certification artifacts. Keep them
under `metadata/`, which is ignored by git.

Create `metadata/statement.json` from the authenticator you are testing, then export a profile:

```bash
mkdir -p metadata

uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile fido2-2.0 \
  --client-pin-state unset

uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile fido2-2.1-experimental \
  --client-pin-state unset
```

The default outputs are:

- `metadata/metadata-ctap20.json`
- `metadata/metadata-ctap21-experimental.json`

For FIDO2 packed attestation chain checks, export metadata with the certificate returned by
the same device:

```bash
uv run python host_tools/ctaphid_probe.py \
  --cmd makecredential \
  --fido2-cert-out metadata/fido2-attestation.der

uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile fido2-2.0 \
  --fido2-attestation-cert metadata/fido2-attestation.der
```

For U2F, export metadata from the certificate returned by U2F Register:

```bash
uv run python host_tools/ctaphid_probe.py \
  --cmd u2fregister \
  --u2f-cert-out metadata/u2f-attestation.der

uv run python host_tools/export_certification_metadata.py \
  --statement metadata/statement.json \
  --profile u2f \
  --u2f-attestation-cert metadata/u2f-attestation.der
```

If the conformance tool changes the PIN state, regenerate metadata with the matching
`--client-pin-state` value before rerunning that profile.

## Security Notes

- Flipper Zero hardware does not give this app a secure element for credential keys.
- Software attestation proves a local app install identity, not FIDO-certified vendor hardware
  provenance.
- `attestation: "none"` suppresses the local attestation certificate and attestation signature;
  it does not weaken the generated credential keypair used later for assertions.
- Physical access to the device changes the threat model.
- Diagnostic and conformance builds may log protocol data. Release-default builds set
  `ZF_RELEASE_DIAGNOSTICS=0`.

## License

ZeroFIDO uses the GNU General Public License, version 3 only. See [`LICENSE`](LICENSE).

Dependency and provenance notes live in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
