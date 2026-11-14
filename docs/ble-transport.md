# BLE transport (fork work in progress)

Goal: let ZeroFIDO act as a FIDO2/U2F authenticator over Bluetooth Low Energy,
as a third transport next to USB HID and NFC.

## Done

- `src/transport/ble_framing.{h,c}`: FIDO-over-BLE message framing, free of
  Flipper and GATT dependencies.
  - Reassembly of fidoControlPoint writes (init + continuation fragments,
    sequence checking with 0..127 wrap, CANCEL handling, length and sequence
    errors mapped to the BLE error codes).
  - Fragmentation of responses for fidoStatus notifications at any
    control-point length from 20 to 512 bytes.
  - `zf_ble_classify_msg`: routes an MSG payload to the existing U2F handler
    (first byte 0x00, an APDU CLA) or CTAP2 handler (first byte is a command).
  - ERROR and KEEPALIVE builders.
- `tests/native/ble_framing/runner.c`: host tests, run in CI with
  AddressSanitizer and UBSan.
- `.github/workflows/build-fork.yml`: runs the framing tests, then builds the
  usb, nfc and full profiles with ufbt and uploads the FAPs.

## Not done

These parts need the Flipper SDK and real hardware to write and verify.

1. **GATT service.** The FIDO service (UUID 0xFFFD) needs four characteristics:
   fidoControlPoint (write), fidoStatus (notify), fidoControlPointLength (read)
   and fidoServiceRevisionBitfield (read/write). Open question: whether a FAP
   can register a custom GATT service through the exported firmware API, or
   whether a small firmware-side profile is required (as for the HID and
   serial profiles). Check `api_symbols.csv` of the target firmware first.
2. **Pairing.** The spec requires an encrypted, bonded link before the
   control point is writable. The Flipper needs a numeric-comparison or
   passkey flow plus bond storage.
3. **Adapter.** `ZfTransportAdapterOps` for BLE (`src/transport/ble_worker.c`):
   worker loop, `send_dispatch_result` using `zf_ble_tx_*`,
   `wait_for_interaction`, `poll_cbor_control` (CANCEL), and KEEPALIVE while
   waiting for user presence.
4. **Wiring.** Add `ZfTransportModeBle` to `src/zerofido_runtime_config.h`,
   the persisted record, `zf_app_lifecycle_adapter_for_mode`, the transport
   toggle in `src/ui/views.c`, a `ble` profile in `application.fam`, and
   `advertise_ble_transport` in getInfo's transports list.
5. **Dispatch.** `src/transport/dispatch.c` is compiled for every profile
   except NFC-only and keys off `ZfTransportState`; the BLE adapter should
   reuse `zf_transport_dispatch_complete_message`.

## Running the tests locally

```
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
   -I src/transport tests/native/ble_framing/runner.c \
   src/transport/ble_framing.c -o .tmp/ble_framing_tests
./.tmp/ble_framing_tests
```
