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
#include "../u2f/adapter.h"
#include "../u2f/common.h"
#include "nfc_iso_dep.h"
#include "nfc_protocol.h"
#include "nfc_session.h"

#if ZF_RELEASE_DIAGNOSTICS
#define ZF_NFC_DIAG_STATUS_LOCKED(app, text) zerofido_ui_set_status_locked((app), (text))
#else
#define ZF_NFC_DIAG_STATUS_LOCKED(app, text) ((void)(app))
#endif

#define ZF_NFC_DESFIRE_SW_MORE 0x91AFU
#define ZF_NFC_DESFIRE_SW_OK 0x9100U

static bool zf_transport_nfc_send_desfire_version_part(ZerofidoApp *app,
                                                       ZfNfcTransportState *state,
                                                       bool final_frame) {
    static const uint8_t version_part1_or_2[] = {
        0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05,
    };
    static const uint8_t version_part3[] = {
        0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
        0x00, 0x00, 0x00, 0x00, 0x24, 0x04, 0x26,
    };

    if (!state) {
        return false;
    }

    ZF_NFC_DIAG_STATUS_LOCKED(app, final_frame ? "DESFire version done" : "DESFire version");
    if (final_frame) {
        state->desfire_probe_frame = 0U;
        return zf_transport_nfc_send_apdu_payload(state, version_part3, sizeof(version_part3),
                                                  ZF_NFC_DESFIRE_SW_OK);
    }

    state->desfire_probe_frame++;
    return zf_transport_nfc_send_apdu_payload(state, version_part1_or_2,
                                              sizeof(version_part1_or_2),
                                              ZF_NFC_DESFIRE_SW_MORE);
}

static bool zf_transport_nfc_send_desfire_version_terminal(ZerofidoApp *app,
                                                           ZfNfcTransportState *state) {
    static const uint8_t version_full[] = {
        0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05,
        0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05,
        0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
        0x00, 0x00, 0x00, 0x00, 0x24, 0x04, 0x26,
    };

    if (!state) {
        return false;
    }

    state->desfire_probe_frame = 0U;
    ZF_NFC_DIAG_STATUS_LOCKED(app, "DESFire version done");
    return zf_transport_nfc_send_apdu_payload(state, version_full, sizeof(version_full),
                                              ZF_NFC_DESFIRE_SW_OK);
}

static bool zf_transport_nfc_exchange_busy(const ZfNfcTransportState *state) {
    return state && (state->processing || state->request_pending);
}

static bool zf_transport_nfc_send_busy_status(ZfNfcTransportState *state) {
    return zf_transport_nfc_send_apdu_payload(state, (const uint8_t[]){ZF_NFC_STATUS_PROCESSING},
                                              1U, ZF_NFC_SW_STATUS_UPDATE);
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
        ZF_NFC_DIAG_STATUS_LOCKED(app, "NDEF reject");
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_FILE_NOT_FOUND);
    }

    return false;
}

static bool zf_transport_nfc_send_ctap2_get_info_immediate(ZerofidoApp *app,
                                                           ZfNfcTransportState *state,
                                                           const ZfNfcApdu *apdu, bool *handled) {
    ZfResolvedCapabilities capabilities;
    static const uint8_t nfc_get_info_template[] = {
        ZF_CTAP_SUCCESS,
        0xA6,
        0x01, 0x82, 0x68, 'F',  'I',  'D',  'O',  '_',  '2',  '_',  '0',
        0x66, 'U',  '2',  'F',  '_',  'V',  '2',
        0x03, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0xA3, 0x62, 'r',  'k',  0xF4, 0x62, 'u',  'p',  0xF5,
        0x62, 'u',  'v',  0xF4,
        0x05, 0x19, 0x04, 0x00,
        0x09, 0x81, 0x63, 'n',  'f',  'c',
        0x0A, 0x81, 0xA2, 0x63, 'a',  'l',  'g',  0x26, 0x64, 't',
        'y',  'p',  'e',  0x6A, 'p',  'u',  'b',  'l',  'i',  'c',
        '-',  'k',  'e',  'y',
    };
    uint8_t *arena = zf_transport_nfc_arena(state);
    size_t arena_capacity = zf_transport_nfc_arena_capacity(state);

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
    ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 getInfo");
    zf_runtime_get_effective_capabilities(app, &capabilities);
    if (!capabilities.fido2_enabled) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
    }
    if (zf_transport_nfc_exchange_busy(state)) {
        return zf_transport_nfc_send_busy_status(state);
    }

    capabilities.advertise_fido_2_1 = false;
    capabilities.advertise_usb_transport = false;
    capabilities.advertise_nfc_transport = true;

    if (!arena || arena_capacity < sizeof(nfc_get_info_template)) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }

    memcpy(arena, nfc_get_info_template, sizeof(nfc_get_info_template));
    memcpy(&arena[22], zf_attestation_get_aaguid(), ZF_AAGUID_LEN);
    return zf_transport_nfc_send_apdu_payload(state, arena, sizeof(nfc_get_info_template),
                                              ZF_NFC_SW_SUCCESS);
}

static bool zf_transport_nfc_send_u2f_response(ZfNfcTransportState *state, const uint8_t *response,
                                               size_t response_len) {
    uint16_t status_word = ZF_NFC_SW_INTERNAL_ERROR;

    if (!state || !response || response_len < 2U) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INTERNAL_ERROR);
    }

    status_word = ((uint16_t)response[response_len - 2U] << 8) | response[response_len - 1U];
    return zf_transport_nfc_send_apdu_payload(state, response, response_len - 2U, status_word);
}

static bool zf_transport_nfc_send_ctap2_sync(ZerofidoApp *app, ZfNfcTransportState *state,
                                             const uint8_t *request, size_t request_len) {
    ZfTransportSessionId session_id = 0;
    size_t response_len = 0;
    bool old_auto_accept = false;
    bool sent = false;
    uint8_t command = 0U;
    uint8_t *arena = zf_transport_nfc_arena(state);

    if (!app || !state || !request || request_len == 0U || !arena) {
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
    }

    command = request[0];
    session_id = state->session_id;
    state->request_pending = false;
    state->processing = true;
    state->processing_cancel_requested = false;
    state->processing_session_id = session_id;
    state->response_ready = false;
    state->response_len = 0U;
    state->response_offset = 0U;

    old_auto_accept = app->transport_auto_accept_transaction;
    app->transport_auto_accept_transaction = true;
#if ZF_RELEASE_DIAGNOSTICS
    switch (command) {
    case ZfCtapeCmdMakeCredential:
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 MC sync");
        break;
    case ZfCtapeCmdGetAssertion:
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 GA sync");
        break;
    default:
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 sync");
        break;
    }
#endif
    furi_mutex_release(app->ui_mutex);
    response_len =
        zerofido_handle_ctap2(app, session_id, request, request_len, arena, ZF_MAX_MSG_SIZE);
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_auto_accept_transaction = old_auto_accept;

    state->processing = false;
    state->processing_session_id = 0U;
    state->request_pending = false;
    state->response_ready = false;
    state->response_len = 0U;
    state->response_offset = 0U;

    if (response_len == 0U) {
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 empty");
        return zf_transport_nfc_send_apdu_payload(state, (const uint8_t[]){ZF_CTAP_ERR_OTHER}, 1U,
                                                  ZF_NFC_SW_SUCCESS);
    }

    if (response_len + 2U > ZF_NFC_MAX_FRAME_INF_SIZE) {
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 too large");
        return zf_transport_nfc_send_apdu_payload(state, (const uint8_t[]){ZF_CTAP_ERR_OTHER}, 1U,
                                                  ZF_NFC_SW_SUCCESS);
    }

    sent = zf_transport_nfc_send_apdu_payload(state, arena, response_len, ZF_NFC_SW_SUCCESS);
    if (!sent) {
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 send fail");
    } else {
#if ZF_RELEASE_DIAGNOSTICS
        char text[sizeof(app->status_text)];
        const char *cmd = command == ZfCtapeCmdMakeCredential
                              ? "MC"
                              : (command == ZfCtapeCmdGetAssertion ? "GA" : "CMD");
        snprintf(text, sizeof(text), "CTAP2 %s tx=%u", cmd, (unsigned)(response_len + 2U));
        zerofido_ui_set_status_locked(app, text);
#endif
    }
    return sent;
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
    ZF_NFC_DIAG_STATUS_LOCKED(app, response_len >= 2U
                                       ? (fallback ? "U2F VERSION fallback" : "U2F VERSION")
                                       : (fallback ? "U2F fallback error" : "U2F error"));
    return zf_transport_nfc_send_u2f_response(state, app->transport_arena, response_len);
}

bool zf_transport_nfc_handle_apdu(ZerofidoApp *app, ZfNfcTransportState *state,
                                  const uint8_t *apdu_bytes, size_t apdu_len) {
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
        ZF_NFC_DIAG_STATUS_LOCKED(app, "NFC APDU parse failed");
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
            zerofido_ui_set_status_locked(app, text);
        } else {
            zerofido_ui_set_status_locked(app, "FIDO SELECT");
        }
#else
        (void)valid_select;
#endif
        const bool handled = zf_transport_nfc_handle_select(state, &apdu);
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
            return zf_transport_nfc_send_desfire_version_part(
                app, state, state->desfire_probe_frame >= 2U);
        }

        if (raw_cla == 0x80U && apdu.ins == 0x60U && apdu.p1 == 0x00U && apdu.p2 == 0x00U) {
            ZF_NFC_DIAG_STATUS_LOCKED(app, "APDU 8060 reject");
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
        }
#if ZF_RELEASE_DIAGNOSTICS
        snprintf(text, sizeof(text), "APDU %02X %02X %02X %02X", apdu.cla, apdu.ins, apdu.p1,
                 apdu.p2);
        zerofido_ui_set_status_locked(app, text);
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
        zerofido_ui_cancel_pending_interaction_locked(app);
        ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP control END");
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_SUCCESS);
    }

    const bool ctap_get_info_result =
        zf_transport_nfc_send_ctap2_get_info_immediate(app, state, &apdu, &ctap_get_info_handled);
    if (ctap_get_info_handled) {
        return ctap_get_info_result;
    }

    if (apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_GET_RESPONSE) {
        return zf_transport_nfc_send_get_response(app, state, &apdu);
    }

    if ((apdu.cla == 0x80U || apdu.cla == 0x00U) && apdu.ins == ZF_NFC_INS_ISO_GET_RESPONSE) {
        return zf_transport_nfc_send_get_response(app, state, &apdu);
    }

    if (apdu.chained && apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_MSG) {
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
        return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_SUCCESS);
    }

    if (apdu.cla == 0x80U && apdu.ins == ZF_NFC_INS_CTAP_MSG) {
        if (!capabilities.fido2_enabled) {
            ZF_NFC_DIAG_STATUS_LOCKED(app, "CTAP2 disabled");
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
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
        } else {
            if (apdu.data_len == 0 || apdu.data_len > ZF_MAX_MSG_SIZE) {
                return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
            }
            memmove(app->transport_arena, apdu.data, apdu.data_len);
            state->request_len = apdu.data_len;
        }

        state->command_chain_active = false;
        return zf_transport_nfc_send_ctap2_sync(app, state, app->transport_arena,
                                                state->request_len);
    }

    if (apdu.cla == 0x00U) {
        size_t u2f_request_len = 0;

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
        u2f_request_len =
            zf_transport_nfc_encode_u2f_request(&apdu, app->transport_arena, ZF_MAX_MSG_SIZE);
        if (u2f_request_len == 0) {
            return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
        }
        ZF_NFC_DIAG_STATUS_LOCKED(app, "U2F queued");
        zf_transport_nfc_queue_request_locked(app, state, ZfNfcRequestKindU2f, app->transport_arena,
                                              u2f_request_len);
        return zf_transport_nfc_send_apdu_payload(
            state, (const uint8_t[]){ZF_NFC_STATUS_PROCESSING}, 1, ZF_NFC_SW_STATUS_UPDATE);
    }

    return zf_transport_nfc_send_status_word(state, ZF_NFC_SW_INS_NOT_SUPPORTED);
}
