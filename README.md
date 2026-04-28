# Zerofido

`zerofido` is a Flipper Zero external app that exposes a USB CTAP2 authenticator over
`usb_hid_u2f`.

Current target:

- official stock firmware `1.4.3`
- external `.fap`
- USB only
- CTAP2 + U2F compatibility
- ES256 only
- discoverable credentials
- `ClientPIN`
- packed attestation with a stable ZeroFIDO software-attestation certificate

## Layout

- [docs](docs): implementation and release plan
- [src](<repo>/src): app sources
- [host_tools](<repo>/host_tools): host-side verification helpers

## Runtime architecture

The runtime is now split into foldered subsystem owners instead of a few large mixed-purpose
files:

- [src/transport](<repo>/src/transport): transport adapters and HID framing
- [src/ctap](<repo>/src/ctap): CTAP2 protocol adapter ownership
- [src/u2f](<repo>/src/u2f): U2F protocol adapter ownership
- [src/pin](<repo>/src/pin): PIN command, flow, and durable state
- [src/ui](<repo>/src/ui): UI approval, status, and view ownership
- [src/store](<repo>/src/store): credential-store bootstrap, record format, and
  recovery
- [src/app](<repo>/src/app): app lifecycle/composition support

Current transport ownership is deliberately narrow:

- USB HID is one transport adapter.
- CTAP2 and U2F are transport-agnostic protocol adapters.
- Future NFC/BLE support should be additive by introducing new transport adapters plus adapter
  tests, not by rewriting CTAP2, U2F, PIN, UI, or store logic.

The runtime still threads a session identity through protocol handling for approval, cancel, and
continuation-sensitive flows, but HID packet assembly, channel allocation, and USB lifecycle stay
owned by `src/transport/`.

## Build

The workspace uses `uv` for Python tooling.

```bash
uv run python -m ufbt
uv run python -m ufbt launch
```

## Validation

Formatting, lint, and static analysis are wired for the C sources:

```bash
uv run python tools/check_c.py format
uv run python tools/check_c.py tidy
uv run python tools/check_c.py cppcheck
uv run python tools/check_c.py all
```

Tooling expectations:

- `clang-format` is available from Xcode Command Line Tools on macOS
- `clang-tidy` comes from Homebrew `llvm`
- `cppcheck` comes from Homebrew `cppcheck`

Install the analyzer dependencies on macOS with:

```bash
brew install llvm cppcheck
```

## Symbol gate

The pinned firmware reference checkout used during development is expected at:

`<flipper-firmware-checkout>`

To validate the exported external API surface:

```bash
uv run python host_tools/check_symbol_gate.py <flipper-firmware-checkout>
```

## Dev conformance suite

The dev harness is now a full local conformance suite with:

- a helper/orchestrator service
- a live operator dashboard
- raw CTAPHID and U2F probes
- browser-driven WebAuthn scenarios
- row-by-row verdicts against the protocol matrix

Start it with:

```bash
uv run python host_tools/serve_webauthn_debug.py
```

Then open:

`http://localhost:8765/webauthn_debug.html`

The helper auto-detects a matching HID authenticator, but the suite stays idle until you press
`Run Suite` in the dashboard. Set `autostart` to `true` in your local fixture config if you want
the previous auto-run behavior.

Browser-side WebAuthn scenarios now run in the dashboard page you opened yourself. The helper does
not spawn its own Chromium instance anymore.

Local fixture defaults live in:

- example config: [host_tools/fixture_config.example.json](<repo>/host_tools/fixture_config.example.json)
- optional local override: `host_tools/fixture_config.local.json`

The latest persisted suite report is written to:

- `.tmp/conformance_suite/latest.json`

## Attestation

`zerofido` now returns a `packed` attestation statement signed by a stable software attestation
identity carrying the ZeroFIDO AAGUID.

This is an honest software attestation model, not a hardware-backed one:

- the attestation identity is shared across builds of the ZeroFIDO project
- the attestation certificate identifies the ZeroFIDO software authenticator model
- attestation is a project/model branding signal, not proof of an exclusive official binary
- attestation subject fields are part of the shipped ZeroFIDO project identity for explicit private
  trust pinning and should not be treated on their own as public legal-vendor proof
- public sites may still show anonymous provider info when they request `attestation: "none"` or do
  not trust or resolve ZeroFIDO metadata

For relying-party trust and inspection, use:

- root certificate: [docs/11-attestation-root.pem](<repo>/docs/11-attestation-root.pem)
- leaf certificate: [docs/11-attestation-leaf.pem](<repo>/docs/11-attestation-leaf.pem)
- policy note: [docs/11-attestation.md](<repo>/docs/11-attestation.md)

The canonical model metadata statement is in
[docs/12-metadata-statement.json](<repo>/docs/12-metadata-statement.json), with
distribution notes in [docs/12-metadata.md](<repo>/docs/12-metadata.md).

For certification tooling that expects an importable metadata JSON shaped like its own GetInfo
snapshot, generate one from the canonical statement with:

```bash
uv run python host_tools/export_certification_metadata.py --from-device --output metadata.json
```

That export keeps the full static metadata statement fields that CTAP does not expose, while using
the live device GetInfo shape for `authenticatorGetInfo`.

## Protocol audit

The current FIDO protocol coverage and deviation matrix is in
[docs/13-fido-audit-matrix.md](<repo>/docs/13-fido-audit-matrix.md).

The frozen current-state claim inventory that later audit slices extend is in
[docs/16-current-state-claim-inventory.md](<repo>/docs/16-current-state-claim-inventory.md).

This matrix distinguishes:

- protocol-correct behavior
- browser-interoperability considerations
- intentional product choices such as local approval UX and constrained product-scope feature cuts

Important current design note for `ClientPIN`: ZeroFIDO keeps `PIN_AUTH_BLOCKED` in app-owned
durable state and clears it only through an explicit local UI action. This is intentional. Stock
external `.fap` apps do not have an app-owned retained power-session primitive, so the project does
not depend on fragile hidden firmware state to approximate literal CTAP power-cycle semantics.

It should be kept in sync with runtime behavior when CTAP, CTAPHID, U2F, ClientPIN, or metadata
surfaces change.

## License

ZeroFIDO is licensed under the GNU General Public License, version 3 only. See [LICENSE](LICENSE).

Third-party dependency and provenance notes are tracked in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
