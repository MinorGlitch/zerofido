#include "nfc_session.h"

#include <furi.h>
#include <string.h>

#include "../u2f/adapter.h"
#include "../zerofido_crypto.h"
#include "../zerofido_notify.h"
#include "../zerofido_ui.h"
#include "../zerofido_ui_i.h"
#include "nfc_iso4_backport.h"
#include "nfc_iso_dep.h"

void zf_transport_nfc_attach_arena(ZfNfcTransportState *state, uint8_t *arena,
                                   size_t arena_capacity) {
    if (!state) {
        return;
    }

    state->arena = arena;
    state->arena_capacity = arena_capacity;
}

uint8_t *zf_transport_nfc_arena(const ZfNfcTransportState *state) {
    return state ? state->arena : NULL;
}

size_t zf_transport_nfc_arena_capacity(const ZfNfcTransportState *state) {
    return state ? state->arena_capacity : 0U;
}

uint32_t zf_transport_nfc_next_session_id(ZfTransportSessionId current) {
    current++;
    return current == 0 ? 1U : current;
}

void zf_transport_nfc_note_ui_stage_locked(ZfNfcTransportState *state, ZfNfcUiStage stage) {
    if (!state) {
        return;
    }

    state->last_visible_stage = (uint8_t)stage;
    state->last_visible_stage_tick = furi_get_tick();
}

static void zf_transport_nfc_reset_exchange_internal_locked(ZfNfcTransportState *state) {
    if (!state) {
        return;
    }

    state->request_pending = false;
    state->processing = false;
    state->processing_cancel_requested = false;
    state->response_ready = false;
    state->response_is_u2f = false;
    state->response_is_error = false;
    state->command_chain_active = false;
    zf_transport_nfc_clear_tx_chain(state);
    state->request_len = 0;
    state->response_len = 0;
    state->response_offset = 0;
    state->error_status_word = 0;
    state->pending_status = ZF_NFC_STATUS_PROCESSING;
    state->request_kind = ZfNfcRequestKindNone;
    state->processing_session_id = 0;
    if (state->arena && state->arena_capacity > 0U) {
        zf_crypto_secure_zero(state->arena, state->arena_capacity);
    }
}

void zf_transport_nfc_reset_exchange_locked(ZfNfcTransportState *state) {
    zf_transport_nfc_reset_exchange_internal_locked(state);
}

static void zf_transport_nfc_reset_exchange_preserving_replay_locked(ZfNfcTransportState *state) {
    zf_transport_nfc_reset_exchange_internal_locked(state);
}

void zf_transport_nfc_cancel_current_request_locked(ZfNfcTransportState *state) {
    if (!state) {
        return;
    }

    if (state->processing_session_id != 0) {
        state->canceled_session_id = state->processing_session_id;
    }
    state->processing_cancel_requested = true;
}

void zf_transport_nfc_on_disconnect(ZerofidoApp *app) {
    bool canceled = false;
    ZfNfcTransportState *state = &app->transport_nfc_state_storage;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    state->field_active = false;
    state->iso4_active = false;
    state->applet_selected = false;
    state->desfire_probe_frame = 0U;
    state->iso4_listener = NULL;
    zf_nfc_iso4_layer_reset(state->iso4_layer);
    state->iso_cid_present = false;
    state->iso_cid = 0;
    zf_transport_nfc_cancel_current_request_locked(state);
    if (state->iso4_tx_chain_completed) {
        state->post_success_cooldown_active = true;
        state->post_success_cooldown_until_tick =
            furi_get_tick() + ZF_NFC_POST_SUCCESS_COOLDOWN_MS;
        state->post_success_probe_sleep_active = true;
        state->iso4_tx_chain_completed = false;
    }
    zf_transport_nfc_reset_exchange_locked(state);
    zf_transport_nfc_clear_last_iso_response(state);
    zf_transport_nfc_clear_tx_chain(state);
    state->iso_pcb = ZF_NFC_PCB_BLOCK;
    furi_mutex_release(app->ui_mutex);

    canceled = zerofido_ui_cancel_pending_interaction(app);
    zf_u2f_adapter_set_connected(app, false);
    zerofido_ui_set_transport_connected(app, false);
    zerofido_notify_reset(app);
    zerofido_ui_refresh_status(app);
    if (canceled) {
        zerofido_ui_dispatch_custom_event(app, ZfEventHideApproval);
    }
}

uint8_t zf_transport_nfc_current_status(const ZerofidoApp *app) {
    uint8_t status = ZF_NFC_STATUS_PROCESSING;

    if (!app) {
        return status;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->approval.state == ZfApprovalPending) {
        status = ZF_NFC_STATUS_UPNEEDED;
    }
    furi_mutex_release(app->ui_mutex);
    return status;
}

bool zf_transport_nfc_send_get_response(const ZerofidoApp *app, ZfNfcTransportState *state,
                                        const ZfNfcApdu *apdu) {
    size_t le = zf_transport_nfc_normalize_le(apdu);
    size_t remaining = 0;
    size_t chunk_len = 0;
    uint8_t *arena = zf_transport_nfc_arena(state);
    size_t arena_capacity = zf_transport_nfc_arena_capacity(state);

    if (le > (ZF_NFC_MAX_FRAME_INF_SIZE - 2U)) {
        le = ZF_NFC_MAX_FRAME_INF_SIZE - 2U;
    }

    if (state->processing && !state->response_ready) {
        const uint8_t status = zf_transport_nfc_current_status(app);
        return zf_transport_nfc_send_apdu_payload(state, &status, 1, ZF_NFC_SW_STATUS_UPDATE);
    }

    if (state->response_is_error) {
        const uint16_t error_status =
            state->error_status_word ? state->error_status_word : ZF_NFC_SW_INTERNAL_ERROR;
        zf_transport_nfc_reset_exchange_locked(state);
        return zf_transport_nfc_send_status_word(state, error_status);
    }

    if (!state->response_ready) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_CONDITIONS_NOT_SATISFIED);
    }

    if (!arena || state->response_len > arena_capacity ||
        state->response_offset > state->response_len ||
        (state->response_is_u2f && state->response_len < 2U)) {
        zf_transport_nfc_reset_exchange_locked(state);
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }

    remaining = state->response_len - state->response_offset;
    if (state->response_is_u2f) {
        size_t payload_remaining = 0;

        if (remaining <= 2U) {
            const uint16_t status_word =
                ((uint16_t)arena[state->response_len - 2U] << 8) | arena[state->response_len - 1U];
            zf_transport_nfc_reset_exchange_locked(state);
            return zf_transport_nfc_send_status_word(state, status_word);
        }

        payload_remaining = remaining - 2U;
        if (payload_remaining <= le) {
            chunk_len = payload_remaining;
            const uint16_t status_word =
                ((uint16_t)arena[state->response_len - 2U] << 8) | arena[state->response_len - 1U];
            const bool ok = zf_transport_nfc_send_apdu_payload(
                state, &arena[state->response_offset], chunk_len, status_word);
            zf_transport_nfc_reset_exchange_preserving_replay_locked(state);
            return ok;
        } else {
            chunk_len = le;
        }
    } else if (remaining <= le) {
        const bool ok = zf_transport_nfc_send_apdu_payload(state, &arena[state->response_offset],
                                                           remaining, ZF_NFC_SW_SUCCESS);
        zf_transport_nfc_reset_exchange_preserving_replay_locked(state);
        return ok;
    } else {
        chunk_len = le;
    }

    state->response_offset += chunk_len;
    remaining = state->response_len - state->response_offset;
    return zf_transport_nfc_send_apdu_payload(state, &arena[state->response_offset - chunk_len],
                                              chunk_len,
                                              zf_transport_nfc_status_update_sw(remaining));
}

bool zf_transport_nfc_queue_request_locked(ZerofidoApp *app, ZfNfcTransportState *state,
                                           ZfNfcRequestKind request_kind, const uint8_t *request,
                                           size_t request_len) {
    uint8_t *arena = app ? app->transport_arena : NULL;

    if (state->stopping || request_len == 0 || !arena || request_len > ZF_MAX_MSG_SIZE ||
        state->processing || state->request_pending) {
        state->response_is_error = true;
        state->error_status_word = ZF_NFC_SW_CONDITIONS_NOT_SATISFIED;
        return false;
    }

    zf_transport_nfc_attach_arena(state, arena, ZF_TRANSPORT_ARENA_SIZE);
    if (request != arena) {
        memcpy(arena, request, request_len);
    }
    state->request_len = request_len;
    state->request_kind = request_kind;
    state->request_pending = true;
    state->processing = true;
    state->processing_cancel_requested = false;
    state->canceled_session_id = 0;
    state->processing_session_id = state->session_id;
    state->response_ready = false;
    state->response_is_error = false;
    state->response_offset = 0;
    state->pending_status = ZF_NFC_STATUS_PROCESSING;

    if (app && app->worker_thread) {
        FuriThreadId id = furi_thread_get_id(app->worker_thread);
        if (id) {
            furi_thread_flags_set(id, ZF_NFC_WORKER_EVT_REQUEST);
        }
    }

    return true;
}

bool zf_transport_nfc_handle_select(ZfNfcTransportState *state, const ZfNfcApdu *apdu) {
    if (!zf_transport_nfc_is_fido_select_apdu(apdu)) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_FILE_NOT_FOUND);
    }

    state->applet_selected = true;
    state->post_success_cooldown_active = false;
    state->post_success_probe_sleep_active = false;
    state->post_success_cooldown_until_tick = 0U;
    state->field_active = true;
    state->iso4_active = true;
    state->session_id = zf_transport_nfc_next_session_id(state->session_id);
    state->canceled_session_id = 0;
    zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletSelected);
    zf_transport_nfc_reset_exchange_locked(state);
    zf_transport_nfc_clear_last_iso_response(state);
    zf_transport_nfc_clear_tx_chain(state);
    return zf_transport_nfc_send_apdu_payload(state, zf_transport_nfc_select_response,
                                              sizeof(zf_transport_nfc_select_response),
                                              ZF_NFC_SW_SUCCESS);
}

void zf_transport_nfc_store_response(ZerofidoApp *app, ZfNfcTransportState *state,
                                     ZfTransportSessionId session_id, const uint8_t *response,
                                     size_t response_len, bool response_is_u2f,
                                     bool response_is_error, uint16_t error_status_word) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (state->processing_session_id == session_id && !state->processing_cancel_requested) {
        uint8_t *arena = zf_transport_nfc_arena(state);
        size_t arena_capacity = zf_transport_nfc_arena_capacity(state);

        if (!arena || response_len > arena_capacity ||
            (!response_is_error && response_len > 0U && !response) ||
            (response_is_u2f && !response_is_error && response_len < 2U)) {
            response_len = 0;
            response_is_u2f = false;
            response_is_error = true;
            error_status_word = ZF_NFC_SW_INTERNAL_ERROR;
            if (arena && arena_capacity > 0U) {
                zf_crypto_secure_zero(arena, arena_capacity);
            }
        } else if (response_len > 0 && response && response != arena) {
            memcpy(arena, response, response_len);
        }
        state->response_len = response_len;
        state->response_offset = 0;
        state->response_ready = !response_is_error;
        state->response_is_u2f = response_is_u2f;
        state->response_is_error = response_is_error;
        state->error_status_word = error_status_word;
    }
    state->processing = false;
    state->request_pending = false;
    state->processing_session_id = 0;
    furi_mutex_release(app->ui_mutex);
}
