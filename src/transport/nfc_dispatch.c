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

#include "nfc_dispatch.h"

#include <stdio.h>
#include <string.h>

#include "../zerofido_app_i.h"
#include "../zerofido_attestation.h"
#include "../zerofido_crypto.h"
#include "../zerofido_ctap.h"
#include "../zerofido_pin.h"
#include "../zerofido_runtime_config.h"
#include "../zerofido_ui.h"
#include "../ctap/response.h"
#include "../u2f/apdu.h"
#include "../u2f/adapter.h"
#include "../u2f/common.h"
#include "nfc_iso_dep.h"
#include "nfc_protocol.h"
#include "nfc_session.h"
#include "nfc_trace.h"

#define ZF_NFC_DIAG_EVENT(text) zf_transport_nfc_trace_event((text))

#define ZF_NFC_DESFIRE_SW_MORE 0x91AFU
#define ZF_NFC_DESFIRE_SW_OK 0x9100U

static bool zf_transport_nfc_send_desfire_version_part(ZerofidoApp *app, ZfNfcTransportState *state,
                                                       bool final_frame) {
    static const uint8_t version_part1_or_2[] = {
        0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05,
    };
    static const uint8_t version_part3[] = {
        0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x00, 0x00, 0x00, 0x24, 0x04, 0x26,
    };

    if (!state) {
        return false;
    }

    (void)app;
    ZF_NFC_DIAG_EVENT(final_frame ? "DESFire version done" : "DESFire version");
    if (final_frame) {
        /* Shim-local discovery progress only; do not touch FIDO applet/session state. */
        state->desfire_probe_frame = 0U;
        return zf_transport_nfc_send_apdu_payload_preserving_replay(
            state, version_part3, sizeof(version_part3), ZF_NFC_DESFIRE_SW_OK);
    }

    /* Shim-local discovery progress only; do not touch FIDO applet/session state. */
    state->desfire_probe_frame++;
    return zf_transport_nfc_send_apdu_payload_preserving_replay(
        state, version_part1_or_2, sizeof(version_part1_or_2), ZF_NFC_DESFIRE_SW_MORE);
}

static bool zf_transport_nfc_send_desfire_version_terminal(ZerofidoApp *app,
                                                           ZfNfcTransportState *state) {
    static const uint8_t version_full[] = {
        0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05, 0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05,
        0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x00, 0x00, 0x00, 0x24, 0x04, 0x26,
    };

    if (!state) {
        return false;
    }

    (void)app;
    ZF_NFC_DIAG_EVENT("DESFire version done");
    /* Shim-local discovery progress only; do not touch FIDO applet/session state. */
    state->desfire_probe_frame = 0U;
    return zf_transport_nfc_send_apdu_payload_preserving_replay(
        state, version_full, sizeof(version_full), ZF_NFC_DESFIRE_SW_OK);
}

static bool zf_transport_nfc_exchange_busy(const ZfNfcTransportState *state) {
    return state && (state->processing || state->request_pending || state->response_ready ||
                     state->iso4_tx_chain_active);
}

static bool zf_transport_nfc_ctap_msg_p1p2_valid(const ZfNfcApdu *apdu) {
    return apdu && (apdu->p1 & (uint8_t)~ZF_NFC_CTAP_MSG_P1_GET_RESPONSE) == 0U && apdu->p2 == 0U;
}

static bool zf_transport_nfc_ctap_msg_get_response_supported(const ZfNfcApdu *apdu) {
    return apdu && (apdu->p1 & ZF_NFC_CTAP_MSG_P1_GET_RESPONSE) != 0U;
}

static bool zf_transport_nfc_send_busy_status(ZfNfcTransportState *state) {
    return zf_transport_nfc_send_apdu_payload(state, (const uint8_t[]){ZF_NFC_STATUS_PROCESSING},
                                              1U, ZF_NFC_SW_STATUS_UPDATE);
}

static bool zf_transport_nfc_send_ctap2_immediate(ZerofidoApp *app, ZfNfcTransportState *state,
                                                  const uint8_t *request, size_t request_len,
                                                  bool caller_holds_ui_mutex) {
    uint8_t *response = NULL;
    size_t response_capacity = 0U;
    size_t response_len = 0U;
    bool old_auto_accept = false;

    if (!app || !state || !request || request_len == 0U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }
    response = zf_transport_nfc_arena(state);
    response_capacity = zf_transport_nfc_arena_capacity(state);
    if (!response || response_capacity <= 1U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }

    if (!caller_holds_ui_mutex) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    }
    old_auto_accept = app->transport_auto_accept_transaction;
    app->transport_auto_accept_transaction = true;
    furi_mutex_release(app->ui_mutex);
    response_len = zerofido_handle_ctap2(
        app, state->session_id, request, request_len, response,
        response_capacity > ZF_MAX_MSG_SIZE ? ZF_MAX_MSG_SIZE : response_capacity);
    zerofido_ui_refresh_status(app);
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_auto_accept_transaction = old_auto_accept;
    if (!caller_holds_ui_mutex) {
        furi_mutex_release(app->ui_mutex);
    }

    if (response_len == 0U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }
    if (response_len + 2U <= ZF_NFC_MAX_FRAME_INF_SIZE) {
        return zf_transport_nfc_send_apdu_payload(state, response, response_len, ZF_NFC_SW_SUCCESS);
    }
    return zf_transport_nfc_begin_chained_apdu_payload(state, response, response_len,
                                                       ZF_NFC_SW_SUCCESS);
}

static bool zf_transport_nfc_handle_ndef_apdu(ZerofidoApp *app, ZfNfcTransportState *state,
                                              const ZfNfcApdu *apdu, bool *handled) {
    if (handled) {
        *handled = false;
    }
    if (!app || !state || !apdu || !handled) {
        return false;
    }

    if (apdu->cla == 0x00U && apdu->ins == 0xA4U && apdu->p1 == 0x04U &&
        (apdu->p2 == 0x00U || apdu->p2 == 0x0CU) && apdu->data_len == ZF_NFC_NDEF_AID_LEN &&
        memcmp(apdu->data, zf_transport_nfc_ndef_aid, ZF_NFC_NDEF_AID_LEN) == 0) {
        *handled = true;
        state->applet_selected = false;
        zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
        ZF_NFC_DIAG_EVENT("NDEF reject");
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_FILE_NOT_FOUND);
    }

    return false;
}

static bool zf_transport_nfc_send_ctap2_get_info_immediate(ZerofidoApp *app,
                                                           ZfNfcTransportState *state,
                                                           const ZfNfcApdu *apdu,
                                                           bool caller_holds_ui_mutex,
                                                           bool *handled) {
    ZfResolvedCapabilities capabilities;

    if (handled) {
        *handled = false;
    }
    if (!app || !state || !apdu || !handled) {
        return false;
    }
    if (apdu->cla != 0x80U || apdu->ins != ZF_NFC_INS_CTAP_MSG || apdu->chained ||
        apdu->data_len != 1U || !apdu->data || apdu->data[0] != ZfCtapeCmdGetInfo) {
        return false;
    }

    *handled = true;
    if (!zf_transport_nfc_ctap_msg_p1p2_valid(apdu)) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_P1P2);
    }
    ZF_NFC_DIAG_EVENT("CTAP2 getInfo");
    zf_runtime_get_effective_capabilities(app, &capabilities);
    if (!capabilities.fido2_enabled) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
    }
    if (zf_transport_nfc_exchange_busy(state)) {
        return zf_transport_nfc_send_busy_status(state);
    }

    return zf_transport_nfc_send_ctap2_immediate(app, state, apdu->data, apdu->data_len,
                                                 caller_holds_ui_mutex);
}

static bool zf_transport_nfc_send_u2f_response(const ZerofidoApp *app, ZfNfcTransportState *state,
                                               const ZfNfcApdu *apdu, const uint8_t *response,
                                               size_t response_len) {
    uint16_t status_word = ZF_NFC_SW_INTERNAL_ERROR;
    uint8_t *arena = NULL;
    size_t arena_capacity = 0U;

    if (!app || !state || !apdu || !response || response_len < 2U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }

    status_word = ((uint16_t)response[response_len - 2U] << 8) | response[response_len - 1U];
    if (response_len <= ZF_NFC_MAX_FRAME_INF_SIZE) {
        return zf_transport_nfc_send_apdu_payload(state, response, response_len - 2U, status_word);
    }

    arena = zf_transport_nfc_arena(state);
    arena_capacity = zf_transport_nfc_arena_capacity(state);
    if (!arena || response_len > arena_capacity) {
        zf_transport_nfc_reset_exchange_locked(state);
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }
    if (response != arena) {
        memcpy(arena, response, response_len);
    }

    state->response_len = response_len;
    state->response_offset = 0U;
    state->response_ready = true;
    state->response_is_u2f = true;
    state->response_is_error = false;
    state->error_status_word = 0U;
    state->processing = false;
    state->request_pending = false;
    state->request_kind = ZfNfcRequestKindNone;
    state->processing_session_id = 0U;
    state->command_chain_active = false;
    state->ctap_get_response_supported = false;

    return zf_transport_nfc_send_get_response(app, state, apdu);
}

static bool zf_transport_nfc_send_u2f_immediate(ZerofidoApp *app, ZfNfcTransportState *state,
                                                const ZfNfcApdu *apdu, size_t u2f_request_len,
                                                bool caller_holds_ui_mutex) {
    bool old_auto_accept = false;
    size_t response_len = 0U;

    if (!app || !state || !apdu || u2f_request_len == 0U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }

    if (!caller_holds_ui_mutex) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    }
    old_auto_accept = app->transport_auto_accept_transaction;
    app->transport_auto_accept_transaction = true;
    furi_mutex_release(app->ui_mutex);
    response_len =
        zf_u2f_adapter_handle_msg(app, state->session_id, app->transport_arena, u2f_request_len,
                                  app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    zerofido_ui_refresh_status(app);
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_auto_accept_transaction = old_auto_accept;
    if (!caller_holds_ui_mutex) {
        furi_mutex_release(app->ui_mutex);
    }

    ZF_NFC_DIAG_EVENT(response_len >= 2U ? "U2F immediate" : "U2F error");
    return zf_transport_nfc_send_u2f_response(app, state, apdu, app->transport_arena, response_len);
}

static bool zf_transport_nfc_send_u2f_version_immediate(ZerofidoApp *app,
                                                        ZfNfcTransportState *state,
                                                        const ZfNfcApdu *apdu, bool *handled) {
    size_t u2f_request_len = 0;
    size_t response_len = 0;

    if (handled) {
        *handled = false;
    }
    if (!app || !state || !apdu || !handled) {
        return false;
    }
    if (apdu->cla != 0x00U || apdu->ins != U2F_CMD_VERSION || apdu->chained) {
        return false;
    }

    *handled = true;
    if (zf_transport_nfc_exchange_busy(state)) {
        return zf_transport_nfc_send_busy_status(state);
    }

    const bool fallback = !state->applet_selected;
    if (fallback) {
        state->applet_selected = true;
        state->field_active = true;
        state->iso4_active = true;
        state->session_id = zf_transport_nfc_next_session_id(state->session_id);
        state->canceled_session_id = 0;
        zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletSelected);
        zf_transport_nfc_reset_exchange_locked(state);
    }
    u2f_request_len =
        zf_transport_nfc_encode_u2f_request(apdu, app->transport_arena, ZF_MAX_MSG_SIZE);
    if (u2f_request_len == 0U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }

    response_len =
        zf_u2f_adapter_handle_msg(app, state->session_id, app->transport_arena, u2f_request_len,
                                  app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    ZF_NFC_DIAG_EVENT(response_len >= 2U ? (fallback ? "U2F VERSION fallback" : "U2F VERSION")
                                         : (fallback ? "U2F fallback error" : "U2F error"));
    return zf_transport_nfc_send_u2f_response(app, state, apdu, app->transport_arena, response_len);
}

static bool zf_transport_nfc_send_u2f_immediate_without_presence(ZerofidoApp *app,
                                                                 ZfNfcTransportState *state,
                                                                 const ZfNfcApdu *apdu,
                                                                 bool *handled) {
    const char *operation = NULL;
    size_t u2f_request_len = 0U;
    size_t response_len = 0U;

    if (handled) {
        *handled = false;
    }
    if (!app || !state || !apdu || !handled || apdu->cla != 0x00U || apdu->chained) {
        return false;
    }

    u2f_request_len =
        zf_transport_nfc_encode_u2f_request(apdu, app->transport_arena, ZF_MAX_MSG_SIZE);
    if (u2f_request_len == 0U) {
        *handled = true;
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }

    response_len =
        u2f_validate_request_into_response(app->transport_arena, (uint16_t)u2f_request_len,
                                           app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    if (response_len != 0U) {
        *handled = true;
        ZF_NFC_DIAG_EVENT("U2F invalid");
        return zf_transport_nfc_send_u2f_response(app, state, apdu, app->transport_arena,
                                                  response_len);
    }

    if (u2f_request_needs_user_presence(app->transport_arena, (uint16_t)u2f_request_len,
                                        &operation)) {
        return false;
    }

    *handled = true;
    response_len =
        zf_u2f_adapter_handle_msg(app, state->session_id, app->transport_arena, u2f_request_len,
                                  app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    ZF_NFC_DIAG_EVENT(apdu->ins == U2F_CMD_AUTHENTICATE ? "U2F check-only" : "U2F immediate");
    return zf_transport_nfc_send_u2f_response(app, state, apdu, app->transport_arena, response_len);
}

/*
 * NFC APDU route table:
 * - SELECT FIDO applet selects the FIDO surface.
 * - SELECT NDEF is rejected so the tag surface stays FIDO-only.
 * - CTAP control END clears selected applet/session state.
 * - CTAP2 MSG queues worker processing and may chain large responses.
 * - ISO GET RESPONSE drains pending APDU/chained response data.
 * - CLA=00 U2F APDUs route through the legacy U2F adapter.
 */
static bool zf_transport_nfc_handle_apdu_internal(ZerofidoApp *app, ZfNfcTransportState *state,
                                                  const uint8_t *apdu_bytes, size_t apdu_len,
                                                  bool caller_holds_ui_mutex) {
    ZfNfcApdu apdu;
    ZfResolvedCapabilities capabilities;
    bool ndef_handled = false;
    bool ndef_result = false;
    bool ctap_get_info_handled = false;
    bool u2f_version_handled = false;
    uint8_t raw_cla = 0U;

    if (!app || !state || !apdu_bytes) {
        return false;
    }

    zf_transport_nfc_attach_arena(state, app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    zf_runtime_get_effective_capabilities(app, &capabilities);

    if (!zf_transport_nfc_parse_apdu(apdu_bytes, apdu_len, &apdu)) {
        ZF_NFC_DIAG_EVENT("NFC APDU parse failed");
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }

    raw_cla = apdu_bytes[0];
    ndef_result = zf_transport_nfc_handle_ndef_apdu(app, state, &apdu, &ndef_handled);
    if (ndef_handled) {
        return ndef_result;
    }

    if (apdu.cla == 0x00U && apdu.ins == 0xA4U) {
        const bool valid_select = zf_transport_nfc_is_fido_select_apdu(&apdu);

#if ZF_RELEASE_DIAGNOSTICS
        if (!valid_select) {
            char text[sizeof(app->status_text)];

            snprintf(text, sizeof(text), "SELECT %02X %02X lc=%u", apdu.p1, apdu.p2,
                     (unsigned)apdu.data_len);
            ZF_NFC_DIAG_EVENT(text);
        } else {
            ZF_NFC_DIAG_EVENT("FIDO SELECT");
        }
#else
        (void)valid_select;
#endif
        const bool handled = zf_transport_nfc_handle_select(state, &apdu, &capabilities);
        return handled;
    }

    if (!state->applet_selected && capabilities.u2f_enabled) {
        const bool u2f_version_result =
            zf_transport_nfc_send_u2f_version_immediate(app, state, &apdu, &u2f_version_handled);
        if (u2f_version_handled) {
            return u2f_version_result;
        }
    }

    if (raw_cla == 0x90U && apdu.ins == 0x60U && apdu.p1 == 0x00U && apdu.p2 == 0x00U) {
        zf_transport_nfc_note_ui_stage_locked(
            state, state->applet_selected ? ZfNfcUiStageAppletSelected : ZfNfcUiStageAppletWaiting);
        return zf_transport_nfc_send_desfire_version_terminal(app, state);
    }

    if (!state->applet_selected) {
#if ZF_RELEASE_DIAGNOSTICS
        char text[sizeof(app->status_text)];
#endif

        if (raw_cla == 0x90U && apdu.ins == 0xAFU) {
            state->applet_selected = false;
            zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
            return zf_transport_nfc_send_desfire_version_part(app, state,
                                                              state->desfire_probe_frame >= 2U);
        }

        if (raw_cla == 0x80U && apdu.ins == 0x60U && apdu.p1 == 0x00U && apdu.p2 == 0x00U) {
            ZF_NFC_DIAG_EVENT("APDU 8060 reject");
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
        }
#if ZF_RELEASE_DIAGNOSTICS
        snprintf(text, sizeof(text), "APDU %02X %02X %02X %02X", apdu.cla, apdu.ins, apdu.p1,
                 apdu.p2);
        ZF_NFC_DIAG_EVENT(text);
#endif
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_CONDITIONS_NOT_SATISFIED);
    }

    if (apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_CONTROL && apdu.p1 == 0x01U &&
        apdu.p2 == 0x00U) {
        state->applet_selected = false;
        zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
        zf_transport_nfc_cancel_current_request_locked(state);
        zf_transport_nfc_reset_exchange_locked(state);
        zf_transport_nfc_clear_last_iso_response(state);
        zf_transport_nfc_clear_tx_chain(state);
        zerofido_ui_cancel_pending_interaction_locked(app);
        ZF_NFC_DIAG_EVENT("CTAP control END");
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_SUCCESS);
    }

    const bool ctap_get_info_result = zf_transport_nfc_send_ctap2_get_info_immediate(
        app, state, &apdu, caller_holds_ui_mutex, &ctap_get_info_handled);
    if (ctap_get_info_handled) {
        return ctap_get_info_result;
    }

    if (apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_GET_RESPONSE) {
        if (apdu.p1 != 0x00U || apdu.p2 != 0x00U) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_P1P2);
        }
        return zf_transport_nfc_send_get_response(app, state, &apdu);
    }

    if ((apdu.cla == 0x80U || apdu.cla == 0x00U) && apdu.ins == ZF_NFC_INS_ISO_GET_RESPONSE) {
        return zf_transport_nfc_send_get_response(app, state, &apdu);
    }

    if (apdu.chained && apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_MSG) {
        if (!zf_transport_nfc_ctap_msg_p1p2_valid(&apdu)) {
            zf_transport_nfc_reset_exchange_locked(state);
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_P1P2);
        }
        if (zf_transport_nfc_exchange_busy(state)) {
            return zf_transport_nfc_send_busy_status(state);
        }
        if (state->request_len > ZF_MAX_MSG_SIZE ||
            apdu.data_len > ZF_MAX_MSG_SIZE - state->request_len) {
            zf_transport_nfc_reset_exchange_locked(state);
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
        }

        memmove(&app->transport_arena[state->request_len], apdu.data, apdu.data_len);
        state->request_len += apdu.data_len;
        state->command_chain_active = true;
        state->ctap_get_response_supported =
            state->ctap_get_response_supported ||
            zf_transport_nfc_ctap_msg_get_response_supported(&apdu);
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_SUCCESS);
    }

    if (apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_MSG) {
        bool ctap_get_response_supported = false;

        if (!zf_transport_nfc_ctap_msg_p1p2_valid(&apdu)) {
            zf_transport_nfc_reset_exchange_locked(state);
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_P1P2);
        }
        if (!capabilities.fido2_enabled) {
            ZF_NFC_DIAG_EVENT("CTAP2 disabled");
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
        }
        if (!state->ctap_get_response_supported &&
            (state->response_ready || state->response_is_error)) {
            ZF_NFC_DIAG_EVENT("CTAP2 original response");
            return zf_transport_nfc_send_get_response(app, state, &apdu);
        }
        if (zf_transport_nfc_exchange_busy(state)) {
            return zf_transport_nfc_send_busy_status(state);
        }
        if (state->command_chain_active) {
            if (state->request_len > ZF_MAX_MSG_SIZE ||
                apdu.data_len > ZF_MAX_MSG_SIZE - state->request_len) {
                zf_transport_nfc_reset_exchange_locked(state);
                return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
            }
            memmove(&app->transport_arena[state->request_len], apdu.data, apdu.data_len);
            state->request_len += apdu.data_len;
            ctap_get_response_supported = state->ctap_get_response_supported ||
                                          zf_transport_nfc_ctap_msg_get_response_supported(&apdu);
        } else {
            if (apdu.data_len == 0 || apdu.data_len > ZF_MAX_MSG_SIZE) {
                return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
            }
            memmove(app->transport_arena, apdu.data, apdu.data_len);
            state->request_len = apdu.data_len;
            ctap_get_response_supported = zf_transport_nfc_ctap_msg_get_response_supported(&apdu);
        }

        state->command_chain_active = false;
        state->ctap_get_response_supported = ctap_get_response_supported;
        if (!zf_transport_nfc_queue_request_locked(app, state, ZfNfcRequestKindCtap2,
                                                   app->transport_arena, state->request_len)) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_CONDITIONS_NOT_SATISFIED);
        }
        state->ctap_get_response_supported = ctap_get_response_supported;
        if (!zf_transport_nfc_wake_request_worker(app, state)) {
            zf_transport_nfc_reset_exchange_locked(state);
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_CONDITIONS_NOT_SATISFIED);
        }
        ZF_NFC_DIAG_EVENT("CTAP2 queued");
        return zf_transport_nfc_send_apdu_payload(
            state, (const uint8_t[]){ZF_NFC_STATUS_PROCESSING}, 1U, ZF_NFC_SW_STATUS_UPDATE);
    }

    if (apdu.cla == 0x00U) {
        size_t u2f_request_len = 0;
        bool u2f_immediate_handled = false;
        bool u2f_immediate_result = false;

        if (!capabilities.u2f_enabled) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
        }
        const bool u2f_version_result =
            zf_transport_nfc_send_u2f_version_immediate(app, state, &apdu, &u2f_version_handled);
        if (u2f_version_handled) {
            return u2f_version_result;
        }
        if (apdu.chained) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
        }
        if (zf_transport_nfc_exchange_busy(state)) {
            return zf_transport_nfc_send_busy_status(state);
        }
        u2f_immediate_result = zf_transport_nfc_send_u2f_immediate_without_presence(
            app, state, &apdu, &u2f_immediate_handled);
        if (u2f_immediate_handled) {
            return u2f_immediate_result;
        }
        u2f_request_len =
            zf_transport_nfc_encode_u2f_request(&apdu, app->transport_arena, ZF_MAX_MSG_SIZE);
        if (u2f_request_len == 0) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
        }
        return zf_transport_nfc_send_u2f_immediate(app, state, &apdu, u2f_request_len,
                                                   caller_holds_ui_mutex);
    }

    return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
}

bool zf_transport_nfc_handle_apdu(ZerofidoApp *app, ZfNfcTransportState *state,
                                  const uint8_t *apdu_bytes, size_t apdu_len) {
    return zf_transport_nfc_handle_apdu_internal(app, state, apdu_bytes, apdu_len, false);
}

bool zf_transport_nfc_handle_apdu_locked(ZerofidoApp *app, ZfNfcTransportState *state,
                                         const uint8_t *apdu_bytes, size_t apdu_len) {
    return zf_transport_nfc_handle_apdu_internal(app, state, apdu_bytes, apdu_len, true);
}
