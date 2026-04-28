/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
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
#include <stddef.h>
#include <stdint.h>

#include <furi.h>
#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_listener.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>
#include <toolbox/bit_buffer.h>

#include "../zerofido_types.h"
#include "dispatch.h"

#define ZF_NFC_WORKER_EVT_STOP (1U << 0)
#define ZF_NFC_WORKER_EVT_REQUEST (1U << 1)
#define ZF_NFC_LAST_TX_CAPACITY 320U

typedef struct ZerofidoApp ZerofidoApp;
typedef struct ZfNfcIso4Layer ZfNfcIso4Layer;

typedef enum {
    ZfNfcRequestKindNone = 0,
    ZfNfcRequestKindU2f = 1,
    ZfNfcRequestKindCtap2 = 2,
} ZfNfcRequestKind;

typedef enum {
    ZfNfcUiStageWaiting = 0,
    ZfNfcUiStageAppletWaiting = 1,
    ZfNfcUiStageAppletSelected = 2,
} ZfNfcUiStage;

/*
 * NFC worker state tracks both RF-layer state and asynchronous protocol
 * processing. request_generation/session_id guards prevent late worker results
 * from overwriting a newer APDU exchange.
 */
typedef struct {
    Nfc *nfc;
    NfcListener *listener;
    Iso14443_4aListener *iso4_listener;
    ZfNfcIso4Layer *iso4_layer;
    BitBuffer *tx_buffer;
    BitBuffer *iso4_rx_buffer;
    BitBuffer *iso4_frame_buffer;
    Iso14443_4aData *iso14443_4a_data;
    bool listener_active;
    bool stopping;
    bool field_active;
    bool iso4_active;
    bool applet_selected;
    bool request_pending;
    bool processing;
    bool processing_cancel_requested;
    bool response_ready;
    bool response_is_u2f;
    bool response_is_error;
    bool command_chain_active;
    bool ctap_get_response_supported;
    bool iso4_last_tx_valid;
    bool iso4_tx_chain_active;
    bool iso4_tx_chain_completed;
    bool post_success_cooldown_active;
    bool post_success_probe_sleep_active;
    bool iso_cid_present;
    uint8_t iso4_last_tx[ZF_NFC_LAST_TX_CAPACITY];
    const uint8_t *iso4_tx_chain_data;
    uint8_t iso_pcb;
    uint8_t iso_cid;
    uint8_t desfire_probe_frame;
    size_t iso4_last_tx_len;
    size_t iso4_tx_chain_len;
    size_t iso4_tx_chain_offset;
    size_t request_len;
    size_t response_len;
    size_t response_offset;
    uint16_t error_status_word;
    uint16_t iso4_tx_chain_status_word;
    uint8_t pending_status;
    uint8_t last_visible_stage;
    ZfTransportSessionId session_id;
    ZfTransportSessionId processing_session_id;
    ZfTransportSessionId canceled_session_id;
    ZfNfcRequestKind request_kind;
    uint32_t request_generation;
    uint32_t processing_generation;
    uint32_t last_visible_stage_tick;
    uint32_t post_success_cooldown_until_tick;
    uint8_t *arena;
    size_t arena_capacity;
} ZfNfcTransportState;

/* Adapter entry points for the NFC transport implementation. */
int32_t zf_transport_nfc_worker(void *context);
bool zf_transport_nfc_wake_request_worker(ZerofidoApp *app, ZfNfcTransportState *state);
void zf_transport_nfc_stop(ZerofidoApp *app);
void zf_transport_nfc_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result);
bool zf_transport_nfc_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id, bool *approved);
void zf_transport_nfc_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_nfc_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id);
