#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nfc_protocol.h"
#include "nfc_worker.h"

void zf_transport_nfc_attach_arena(ZfNfcTransportState *state, uint8_t *arena,
                                   size_t arena_capacity);
uint8_t *zf_transport_nfc_arena(const ZfNfcTransportState *state);
size_t zf_transport_nfc_arena_capacity(const ZfNfcTransportState *state);
uint32_t zf_transport_nfc_next_session_id(ZfTransportSessionId current);
void zf_transport_nfc_note_ui_stage_locked(ZfNfcTransportState *state, ZfNfcUiStage stage);
void zf_transport_nfc_reset_exchange_locked(ZfNfcTransportState *state);
void zf_transport_nfc_cancel_current_request_locked(ZfNfcTransportState *state);
void zf_transport_nfc_on_disconnect(ZerofidoApp *app);
uint8_t zf_transport_nfc_current_status(const ZerofidoApp *app);
bool zf_transport_nfc_send_get_response(const ZerofidoApp *app, ZfNfcTransportState *state,
                                        const ZfNfcApdu *apdu);
bool zf_transport_nfc_queue_request_locked(ZerofidoApp *app, ZfNfcTransportState *state,
                                           ZfNfcRequestKind request_kind, const uint8_t *request,
                                           size_t request_len);
bool zf_transport_nfc_handle_select(ZfNfcTransportState *state, const ZfNfcApdu *apdu);
void zf_transport_nfc_store_response(ZerofidoApp *app, ZfNfcTransportState *state,
                                     ZfTransportSessionId session_id, const uint8_t *response,
                                     size_t response_len, bool response_is_u2f,
                                     bool response_is_error, uint16_t error_status_word);
