# ZeroFIDO Runtime Overview

## Summary

`zerofido` is a stock-firmware Flipper Zero external app that presents as a USB CTAP2
authenticator over `usb_hid_u2f`, with U2F compatibility and app-owned `ClientPIN` support.

The original milestone documents in this folder started as a narrower bring-up plan. The runtime
has since been structurally refactored into foldered subsystem owners so future transport work can
be additive instead of another broad rewrite.

Current target baseline:

- stock Flipper Zero firmware `1.4.3`
- external `.fap` only
- USB only
- CTAP2 with U2F compatibility
- ES256 only
- discoverable credentials supported
- `ClientPIN` supported

The committed app-model AAGUID is:

- `b51a976a-0b02-40aa-9d8a-36c8b91bbd1a`

## Current runtime shape

The runtime is now grouped into explicit ownership folders:

- [src/transport](<repo>/src/transport): transport adapters and framing
- [src/ctap](<repo>/src/ctap): CTAP2 protocol adapter ownership
- [src/u2f](<repo>/src/u2f): U2F protocol adapter ownership
- [src/pin](<repo>/src/pin): PIN command, flow, and durable state
- [src/ui](<repo>/src/ui): UI approval, status, and views
- [src/store](<repo>/src/store): credential-store bootstrap, record format, and
  recovery
- [src/app](<repo>/src/app): app lifecycle/composition support

The top-level runtime boundary is now:

1. `transport adapters`
2. `protocol adapters`
3. `authenticator core and subsystem owners`

USB HID is one transport adapter, not the owner of FIDO2 or U2F behavior. CTAP2 and U2F are
transport-agnostic protocol adapters. Future NFC/BLE work should add new transport adapters plus
adapter tests rather than rewriting CTAP2, U2F, PIN, UI, or store code.

## Runtime contracts

The central runtime contracts that enable later profile and transport work are:

- `ZfRuntimeConfig`
- `ZfResolvedCapabilities`
- `ZfTransportAdapterOps`
- `ZfProtocolDispatchRequest`
- `ZfProtocolDispatchResult`

These let settings and startup resolve protocol exposure and transport capability centrally instead
of scattering transport/version branches through handlers.

## Multi-transport readiness

The current tree is transport-ready in the following sense:

- HID framing, channel allocation, keepalive, cancel, and USB worker lifecycle are isolated under
  `src/transport/`.
- CTAP2 and U2F logic do not own USB lifecycle or HID packet assembly.
- Protocol handling still carries a transport/session identity for approval and continuation flows,
  but that identity is passed through normalized dispatch and transport services instead of raw HID
  framing code leaking into subsystem owners.
- `GetInfo` transport advertisement is capability-driven through `ZfResolvedCapabilities`, so later
  transport exposure can stay centralized.

Future NFC/BLE transport support should therefore require:

- a new transport adapter
- adapter-specific tests
- optional capability/profile wiring

It should not require another broad refactor of CTAP2, U2F, PIN, UI, store, or app lifecycle.

## Historical milestone map

These files remain useful as bring-up history and proof anchors:

1. `01-milestone-0-symbol-gate.md`
2. `02-milestone-1-app-shell-and-usb-lifecycle.md`
3. `03-milestone-2-ctaphid-transport.md`
4. `04-milestone-3-getinfo.md`
5. `05-milestone-4-makecredential.md`
6. `06-milestone-5-getassertion.md`
7. `07-milestone-6-storage-and-counters.md`
8. `08-milestone-7-browser-interoperability.md`
9. `09-milestone-8-clientpin.md`
10. `10-release-criteria.md`

The newer runtime-decoupling campaign and handoff state live in
[docs/21-refactor-overview.md](<repo>/docs/21-refactor-overview.md) through
[docs/29-milestone-18-multi-transport-readiness-and-final-gate.md](<repo>/docs/29-milestone-18-multi-transport-readiness-and-final-gate.md).
