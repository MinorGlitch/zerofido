# BLE transport (fork work in progress)

Goal: let ZeroFIDO act as a FIDO2/U2F authenticator over Bluetooth Low Energy,
as a third transport next to USB HID and NFC.

## Status

Implemented, **compile-checked only by CI, never run on a Flipper**:

- `src/transport/ble_framing.{h,c}`: message framing (host-tested, ASan/UBSan).
- `src/transport/ble_profile.{h,c}`: app-defined Flipper BLE profile. Registers
  the FIDO GATT service (0xFFFD) with fidoControlPoint, fidoStatus,
  fidoControlPointLength and fidoServiceRevisionBitfield through the firmware's
  exported `ble_gatt_*` helpers, so no firmware change is needed. Requires an
  authenticated, bonded link (passkey shown on the Flipper). Bonds are stored
  in `/ext/apps_data/zerofido/ble_keys.bin`.
- `src/transport/ble_worker.{h,c}`: transport adapter. Claims the radio,
  advertises, reassembles control point writes, dispatches U2F / CTAP2 into the
  existing handlers, sends KEEPALIVE while waiting for approval, handles CANCEL
  and fragment timeouts, restores the default Bluetooth profile on exit.
- Wiring: `ZfTransportModeBle`, getInfo `transports` includes `ble`, Settings
  transport toggle cycles USB HID -> NFC -> BLE, `ZF_BLE_ENABLED` and the `bt`
  requirement in the **full** build profile only (usb/nfc profiles exclude
  `ble_*.c`).

## Known limits / to verify on hardware

- Notifications use 20-byte fragments (works at the default ATT MTU, slower
  than a negotiated MTU would allow).
- The firmware's `ble_gatt_characteristic_update` result is not trusted
  (inverted in some versions), so notify failures are silent.
- ACI event layout is parsed by hand (attribute-modified event); verify against
  the target firmware if writes never arrive.
- Not yet FIDO-certified; keep a backup sign-in method on any account you test.

## Running the tests locally

```
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
   -I src/transport tests/native/ble_framing/runner.c \
   src/transport/ble_framing.c -o .tmp/ble_framing_tests
./.tmp/ble_framing_tests
```
