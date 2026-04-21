# Milestone 0: Symbol Gate

## Objective

Prove that stock firmware exports every symbol required for a no-firmware-mod external authenticator app.

## Exact Implementation Scope

- Confirm external-app exports for:
  - `usb_hid_u2f`
  - `furi_hal_usb_set_config`
  - `furi_hal_usb_get_config`
  - `furi_hal_hid_u2f_set_callback`
  - `furi_hal_hid_u2f_get_request`
  - `furi_hal_hid_u2f_send_response`
- Confirm external-app exports for slot `11` crypto-enclave use:
  - `furi_hal_crypto_enclave_ensure_key`
  - `furi_hal_crypto_enclave_load_key`
  - `furi_hal_crypto_enclave_unload_key`
  - required encrypt/decrypt support functions used for wrapped private-key storage
- Build a minimal external probe app that references the required symbols but does not implement CTAP2 logic.
- Validate that the probe passes external-app import checks during build.
- Load the probe on a stock device and confirm the loader accepts it.

## Dependencies

- Flipper Zero firmware source tree for `1.4.3`
- working external-app build environment
- physical device running stock firmware for the loader check

## Non-Goals

- no CTAPHID parser
- no CBOR parsing
- no CTAP2 command handling
- no storage design beyond symbol verification

## Exit Criteria

- probe app builds successfully
- build-time import checks show no missing external symbols
- device loads the probe app without unresolved-symbol failure

## Failure Conditions

- any required symbol is absent from the external API surface
- symbol exists in headers but is missing from exported firmware imports
- stock device rejects the probe at load time

## Verification Checklist

- inspect the firmware export table for every required symbol
- compile the probe app against stock headers
- inspect the produced ELF imports to verify expected external linkage
- load the app on an actual stock device
- record exact firmware version used for the loader test

## Review Notes

This milestone is correctly first and remains the only hard no-go gate for the no-firmware-mod path.

The document is intentionally strict about the on-device load test. Build success alone is not enough because the real failure mode is loader rejection on stock firmware.
