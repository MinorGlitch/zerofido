#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

typedef struct {
    Nfc *nfc;
    NfcListener *listener;
    Iso14443_4aListener *iso4_listener;
    ZfNfcIso4Layer *iso4_layer;
    BitBuffer *tx_buffer;
    BitBuffer *iso4_rx_buffer;
    BitBuffer *iso4_frame_buffer;
    BitBuffer *iso4_last_tx_buffer;
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
    bool iso4_last_tx_valid;
    bool iso4_tx_chain_active;
    bool iso4_tx_chain_completed;
    bool post_success_cooldown_active;
    bool post_success_probe_sleep_active;
    bool iso_cid_present;
    uint8_t iso4_last_tx[ZF_NFC_LAST_TX_CAPACITY];
    uint8_t iso4_tx_chain[ZF_TRANSPORT_ARENA_SIZE];
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
    uint8_t pending_status;
    uint8_t last_visible_stage;
    ZfTransportSessionId session_id;
    ZfTransportSessionId processing_session_id;
    ZfTransportSessionId canceled_session_id;
    ZfNfcRequestKind request_kind;
    uint32_t last_visible_stage_tick;
    uint32_t post_success_cooldown_until_tick;
    uint8_t *arena;
    size_t arena_capacity;
} ZfNfcTransportState;

int32_t zf_transport_nfc_worker(void *context);
void zf_transport_nfc_stop(ZerofidoApp *app);
void zf_transport_nfc_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result);
bool zf_transport_nfc_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id, bool *approved);
void zf_transport_nfc_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_nfc_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id);
