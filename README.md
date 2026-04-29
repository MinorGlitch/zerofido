![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)
![Platform: Flipper Zero](https://img.shields.io/badge/platform-Flipper%20Zero-orange)
![Protocols: FIDO2 + U2F](https://img.shields.io/badge/protocols-FIDO2%20%2B%20U2F-green)

![ZeroFIDO banner: FIDO2 for Flipper Zero](docs/assets/zerofido-banner.png)

ZeroFIDO turns a Flipper Zero into a passkey and security-key app. Install the `.fap`,
open ZeroFIDO, and approve sign-ins on services that support FIDO2/WebAuthn or legacy U2F.

The app stores credentials on the Flipper, asks for local approval, supports `ClientPIN`,
and speaks the CTAP2/FIDO2 protocol used by browsers and security keys. USB HID handles
desktop browser flows. NFC builds handle phone flows.

NFC has been tested on iPhone. Android NFC support is next. In the meantime, connect the
Flipper to the phone over USB when the phone accepts USB security keys.

U2F and FIDO2.0 pass their respective tests in the current FIDO Conformance Tools suite. FIDO2.1
support is in development. Bug reports, feature requests, and pull requests are welcome.

## Quick Start

1. Download a release `.fap` from [GitHub Releases](https://github.com/MinorGlitch/zerofido/releases).
2. Copy it to your Flipper SD card under the Tools apps folder, or install it through qFlipper
   or Flipper Lab.
3. Open ZeroFIDO on the Flipper.
4. Register it as a passkey or security key on a site that supports WebAuthn/FIDO2.
5. Approve registration and sign-in prompts on the Flipper screen.

## What Works

| Capability | Status |
| --- | --- |
| USB HID | Supported in the `usb` and `full` release profiles |
| NFC | Supported in the `nfc` and `full` release profiles |
| U2F V2 | Supported |
| FIDO2.0 / CTAP2.0 | Supported |
| FIDO2.1 / CTAP2.1 | Experimental profile |
| `ClientPIN` | Supported |
| Discoverable credentials | Supported |
| Attestation | Local software attestation when requested |

ZeroFIDO builds as an external `.fap` in the Flipper Tools category.

## Daily Use

### Register A Passkey

1. Open ZeroFIDO on the Flipper.
2. Start passkey or security-key registration on the website or app.
3. Choose the ZeroFIDO transport you installed: USB for desktop, NFC for phone.
4. Approve the registration prompt on the Flipper.

### Sign In

1. Start sign-in on the website or app.
2. Connect over USB or hold the Flipper near the phone NFC reader.
3. Approve the sign-in prompt on the Flipper.

### Use A PIN

Some sites request `ClientPIN`. Set the PIN when your browser or phone prompts for it.
ZeroFIDO stores PIN retry state on the device and uses the standard CTAP PIN token flow.

### Legacy U2F

Older services may ask for a U2F security key instead of a passkey. Use the same ZeroFIDO app.

## Settings

ZeroFIDO includes an on-device Settings screen.

| Setting | Use |
| --- | --- |
| Transport | Choose USB, NFC, or automatic behavior when the build includes both transports. |
| FIDO2 profile | Use FIDO2.0 for normal compatibility. Use FIDO2.1 for experimental testing. |
| Attestation | Choose how MakeCredential answers attestation requests. |
| Auto-accept | Test mode for flows that should not require a touch prompt. Keep it off for normal use. |

## Security Model and Limits

- Flipper Zero gives ZeroFIDO no secure element for credential keys.
- ZeroFIDO generates credential private keys on the device. It wraps each private key with the
  Flipper crypto enclave unique key and a per-record IV before writing the credential record to app
  storage. The record still stores the relying-party ID, user fields, public key, wrapped private
  key, IV, and counters needed to find and use the credential.
- ZeroFIDO wraps key material. It does not encrypt the whole app directory.
- Counter floor files and PIN retry state are sealed with the same Flipper crypto APIs so stale
  files cannot roll counters or retry state backward.
- Physical access to the device changes the risk model. Keep at least one backup sign-in method for
  accounts you care about.
- ZeroFIDO uses local software attestation, not hardware-backed vendor attestation.
- ZeroFIDO has not passed FIDO Alliance certification.
- Release builds set `ZF_RELEASE_DIAGNOSTICS=0`; diagnostic and conformance builds may log
  protocol data.

## Attestation

<details>
<summary>Choosing <code>Attest: none</code> or <code>Attest: packed</code></summary>

ZeroFIDO supports two MakeCredential attestation modes from the on-device Settings screen:

- `Attest: none` returns `fmt: "none"` with an empty attestation statement. The credential is still
  created normally, but ZeroFIDO does not include the local attestation certificate chain or
  attestation signature.
- `Attest: packed` allows local software packed attestation when the relying party requests direct
  attestation. This identifies the ZeroFIDO install, not hardware-backed vendor provenance.

If the CTAP request includes `attestationFormats` and names a supported format, that explicit
preference wins over the saved setting. ZeroFIDO currently supports `none` and `packed`.

</details>

## For Developers

<details>
<summary>Developer setup, builds, validation, releases, and certification metadata</summary>

### Setup

Install `uv`, then sync the Python tools:

```bash
uv sync
```

The Python toolchain declares Python `3.14+` in `pyproject.toml`. C validation expects
`clang-format`, `clang-tidy`, `cppcheck`, and a host C compiler.

On macOS:

```bash
brew install llvm cppcheck
```

### Build Profiles

The app manifest reads `ZEROFIDO_PROFILE` at build time. The default profile is `nfc`.
Release builds default to `ZEROFIDO_RELEASE_DIAGNOSTICS=0` and `ZEROFIDO_DEV_ATTESTATION=0`.

| Profile | Build flag | Use |
| --- | --- | --- |
| NFC only | `ZEROFIDO_PROFILE=nfc` | Phone and NFC conformance work. |
| USB HID only | `ZEROFIDO_PROFILE=usb` | Desktop browser WebAuthn and U2F testing. |
| Full | `ZEROFIDO_PROFILE=full` | Both transports in one app. |

Release-default builds exclude the NFC trace implementation and the bundled development
attestation chain. Diagnostic and private-trust builds must opt in:

```bash
ZEROFIDO_PROFILE=nfc ZEROFIDO_RELEASE_DIAGNOSTICS=1 uv run python -m ufbt
ZEROFIDO_PROFILE=usb ZEROFIDO_DEV_ATTESTATION=1 uv run python -m ufbt
```

Build a profile:

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

### Validation

Run the maintained Python tests:

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

The native harness checks packed attestation, runtime `Attest: none`, explicit
`attestationFormats: ["none"]`, and required packed-attestation failures.

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

### Host Tools

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

### Release Packaging

Build a release `.fap` for the selected profile and verify that the app exports only
`zerofido_main`:

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

### GitHub Releases

The `Build profiles` workflow verifies every push and pull request. The `Release` workflow
publishes GitHub Releases from existing `v*` tags.

Create and push a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow builds the `nfc`, `usb`, and `full` profiles with
`ZEROFIDO_RELEASE_DIAGNOSTICS=0` and `ZEROFIDO_DEV_ATTESTATION=0`, packages the stripped
`*-release.fap` artifacts, and uploads `SHA256SUMS`.

You can also run the workflow from GitHub Actions with an existing tag such as `v1.0.0`.

### Certification Metadata

Metadata and captured attestation certificates belong to your local certification run. Keep them
under `metadata/`; git ignores that directory.

Create `metadata/statement.json` from the authenticator under test, then export a profile:

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

If the conformance tool changes PIN state, regenerate metadata with the matching
`--client-pin-state` before rerunning that profile.

</details>

## Support

ZeroFIDO is built and maintained in spare time. If it helped you, you can support the work here:

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-astoyanov-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=000)](https://buymeacoffee.com/astoyanov)

Support is optional and does not affect releases, issues, or support requests.

## License

ZeroFIDO uses the GNU General Public License, version 3 or later. See [`LICENSE`](LICENSE).

Dependency and provenance notes live in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
