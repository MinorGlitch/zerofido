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

#include "dispatch.h"

typedef struct ZerofidoApp ZerofidoApp;

/*
 * BLE transport adapter entry points (see ZfTransportAdapterOps). The worker
 * owns the Bluetooth profile while running: it claims the radio, advertises the
 * FIDO service, reassembles control point writes with ble_framing, dispatches
 * CTAP2/U2F messages into the shared handlers and notifies responses.
 */
int32_t zf_transport_ble_worker(void *context);
void zf_transport_ble_stop(ZerofidoApp *app);
void zf_transport_ble_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result);
bool zf_transport_ble_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id, bool *approved);
void zf_transport_ble_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_ble_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id);
