/*
 * ZeroFIDO (BLE transport fork)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <furi_ble/profile_interface.h>

/*
 * App-defined Flipper BLE profile exposing the FIDO GATT service (0xFFFD).
 *
 * It is registered through the firmware's exported GATT helpers, so no firmware
 * change is required. Characteristics follow the FIDO CTAP BLE transport:
 *   fidoControlPoint            write           (client -> authenticator)
 *   fidoStatus                  notify          (authenticator -> client)
 *   fidoControlPointLength      read            (max fragment size)
 *   fidoServiceRevisionBitfield read/write      (supported protocol revisions)
 * All of them require an authenticated (passkey) bonded link.
 */

/* Max bytes per control point write that the profile hands to the callback. */
#define ZF_BLE_PROFILE_WRITE_MAX 64U

/* Fragment size we advertise in fidoControlPointLength and use for notifications. */
#define ZF_BLE_PROFILE_FRAGMENT_SIZE 20U

/*
 * Called from the BLE stack's event thread for every fidoControlPoint write.
 * Must not block: queue the data and return.
 */
typedef void (*ZfBleWriteCallback)(const uint8_t *data, uint16_t len, void *context);

typedef struct {
    ZfBleWriteCallback on_write;
    void *context;
} ZfBleProfileParams;

/* Pass to bt_profile_start() together with a ZfBleProfileParams pointer. */
extern const FuriHalBleProfileTemplate *const zf_ble_profile;

/*
 * Sends one fidoStatus notification (at most ZF_BLE_PROFILE_FRAGMENT_SIZE bytes
 * are guaranteed to fit the default ATT MTU). Fire-and-forget: the firmware
 * helper's result is not reliable across versions, so none is reported.
 */
void zf_ble_profile_notify(FuriHalBleProfileBase *profile, const uint8_t *data, uint16_t len);
