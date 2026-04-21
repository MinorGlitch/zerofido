# Milestone 1: App Shell and USB Lifecycle

## Objective

Build the external app shell and own the USB mode lifecycle safely from app entry through shutdown.

## Exact Implementation Scope

- Create the `fido2_zero` external app manifest.
- Link `mbedtls` via `fap_libs`.
- Vendor TinyCBOR via `fap_private_libs`.
- Implement app entry and exit flow.
- Save the previous USB configuration with `furi_hal_usb_get_config()`.
- Switch to `usb_hid_u2f`.
- Register the HID callback.
- Start a dedicated worker thread that owns HID transport state.
- Receive packets at the plumbing level only, without real CTAPHID command logic yet.
- On exit:
  - stop the worker thread
  - unregister the HID callback
  - restore the prior USB configuration

## Dependencies

- Milestone 0 passed
- stock `usb_hid_u2f` exports verified
- basic app manifest and external build path available

## Non-Goals

- no full CTAPHID reassembly
- no CTAP2 command dispatch
- no credential storage
- no user approval flow beyond app open/close behavior

## Exit Criteria

- app launches cleanly
- app exits cleanly
- prior USB mode is always restored
- host connect and disconnect during runtime do not crash the app

## Failure Conditions

- USB mode remains in U2F HID after exit
- worker thread outlives app shutdown
- callback remains registered after exit
- shutdown order allows transport callbacks after USB restoration starts

## Verification Checklist

- open and close the app repeatedly with no host attached
- repeat with the host attached
- verify the worker stops before callback unregister and USB restore
- verify packets can be observed at the raw plumbing layer
- verify no crash when the cable is plugged or unplugged mid-session

## Review Notes

This milestone is the right isolation boundary between app lifecycle bugs and protocol bugs.

The shutdown order is fixed on purpose: stop worker first, then unregister callback, then restore USB mode. That avoids use-after-restore behavior when the transport is still active.
