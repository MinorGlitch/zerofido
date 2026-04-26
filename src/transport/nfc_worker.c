#include "nfc_worker.h"

#include <furi.h>
#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_listener.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>
#include <lib/toolbox/simple_array.h>
#include <stdio.h>
#include <string.h>
#include <toolbox/bit_buffer.h>

#include "../u2f/adapter.h"
#include "../zerofido_app_i.h"
#include "../zerofido_ctap.h"
#include "../zerofido_crypto.h"
#include "../zerofido_ui.h"
#include "nfc_dispatch.h"
#include "nfc_iso4_backport.h"
#include "nfc_iso_dep.h"
#include "nfc_protocol.h"
#include "nfc_session.h"
#include "nfc_trace.h"
#include "usb_hid_session.h"

#define ZF_NFC_DESFIRE_CMD_GET_VERSION 0x60U
#define ZF_NFC_ATS_T0_TA1 0x10U
#define ZF_NFC_ATS_T0_TB1 0x20U
#define ZF_NFC_ATS_T0_TC1 0x40U
#define ZF_NFC_ATS_TC1_NAD 0x01U
#define ZF_NFC_ATS_TC1_CID 0x02U
#define ZF_NFC_RATS_CMD 0xE0U
#define ZF_NFC_REQA_CMD 0x26U
#define ZF_NFC_WUPA_CMD 0x52U
#define ZF_NFC_DESFIRE_CMD_ADDITIONAL_FRAME 0xAFU
#define ZF_NFC_DESFIRE_STATUS_MORE 0xAFU
#define ZF_NFC_DESFIRE_STATUS_OK 0x00U
#define ZF_NFC_PPS_START 0xD0U
#define ZF_NFC_PPS_START_MASK 0xF0U

static ZfNfcTransportState *zf_transport_nfc_state(ZerofidoApp *app) {
    return app ? (ZfNfcTransportState *)app->transport_state : NULL;
}

static void zf_transport_nfc_signal_worker(ZerofidoApp *app, uint32_t flags) {
    FuriThreadId id = 0;

    if (!app || !app->worker_thread) {
        return;
    }

    id = furi_thread_get_id(app->worker_thread);
    if (id) {
        furi_thread_flags_set(id, flags);
    }
}

#if ZF_RELEASE_DIAGNOSTICS
static bool zf_transport_nfc_format_frame_status(char *text, size_t text_len, const char *prefix,
                                                 uint8_t pcb, const uint8_t *payload,
                                                 size_t payload_len) {
    char suffix[32] = {0};
    size_t offset = 0;

    if (!text || text_len == 0U || !prefix) {
        return false;
    }

    for (size_t i = 0; payload && i < payload_len && i < 3U; ++i) {
        int written = snprintf(&suffix[offset], sizeof(suffix) - offset, " %02X", payload[i]);
        if (written <= 0 || (size_t)written >= (sizeof(suffix) - offset)) {
            break;
        }
        offset += (size_t)written;
    }

    snprintf(text, text_len, "%s %02X len=%u%s", prefix, pcb, (unsigned)payload_len, suffix);
    return true;
}

static void zf_transport_nfc_set_frame_status(ZerofidoApp *app, const char *prefix, uint8_t pcb,
                                              const uint8_t *payload, size_t payload_len) {
    char text[64];

    if (!app || !zf_transport_nfc_format_frame_status(text, sizeof(text), prefix, pcb, payload,
                                                      payload_len)) {
        return;
    }

    zerofido_ui_set_status(app, text);
}

static void zf_transport_nfc_set_frame_status_locked(ZerofidoApp *app, const char *prefix,
                                                     uint8_t pcb, const uint8_t *payload,
                                                     size_t payload_len) {
    char text[64];

    if (!app || !zf_transport_nfc_format_frame_status(text, sizeof(text), prefix, pcb, payload,
                                                      payload_len)) {
        return;
    }

    zerofido_ui_set_status_locked(app, text);
}
#else
static inline void zf_transport_nfc_set_frame_status(ZerofidoApp *app, const char *prefix,
                                                     uint8_t pcb, const uint8_t *payload,
                                                     size_t payload_len) {
    (void)app;
    (void)prefix;
    (void)pcb;
    (void)payload;
    (void)payload_len;
}

static inline void zf_transport_nfc_set_frame_status_locked(ZerofidoApp *app, const char *prefix,
                                                            uint8_t pcb, const uint8_t *payload,
                                                            size_t payload_len) {
    (void)app;
    (void)prefix;
    (void)pcb;
    (void)payload;
    (void)payload_len;
}
#endif

static bool zf_transport_nfc_is_bare_apdu(const uint8_t *frame, size_t frame_len) {
    ZfNfcApdu apdu;

    if (!frame || frame_len < 4U) {
        return false;
    }

    if (frame[0] != 0x00U && frame[0] != 0x80U && frame[0] != 0x90U) {
        return false;
    }

    return zf_transport_nfc_parse_apdu(frame, frame_len, &apdu);
}

static bool zf_transport_nfc_is_native_desfire_get_version_payload(const uint8_t *payload,
                                                                   size_t payload_len) {
    return payload && payload_len == 1U && payload[0] == ZF_NFC_DESFIRE_CMD_GET_VERSION;
}

static bool zf_transport_nfc_is_native_desfire_additional_frame(const uint8_t *payload,
                                                               size_t payload_len) {
    return payload && payload_len == 1U && payload[0] == ZF_NFC_DESFIRE_CMD_ADDITIONAL_FRAME;
}

static bool zf_transport_nfc_is_i_block(uint8_t pcb) {
    return (pcb & 0xC2U) == 0x02U;
}

static bool zf_transport_nfc_is_r_block(uint8_t pcb) {
    return (pcb & 0xE2U) == 0xA2U;
}

static bool zf_transport_nfc_is_r_nack_block(uint8_t pcb) {
    return zf_transport_nfc_is_r_block(pcb) && (pcb & 0x10U) != 0U;
}

static bool zf_transport_nfc_is_s_block(uint8_t pcb) {
    return (pcb & 0xC2U) == 0xC2U;
}

static bool zf_transport_nfc_is_s_wtx_block(uint8_t pcb) {
    return zf_transport_nfc_is_s_block(pcb) && (pcb & 0x30U) == 0x30U;
}

static bool zf_transport_nfc_is_s_deselect_block(uint8_t pcb) {
    return zf_transport_nfc_is_s_block(pcb) && !zf_transport_nfc_is_s_wtx_block(pcb);
}

static bool zf_transport_nfc_is_pps_frame(const uint8_t *frame, size_t frame_len) {
    if (!frame || frame_len < 2U) {
        return false;
    }

    return (frame[0] & ZF_NFC_PPS_START_MASK) == ZF_NFC_PPS_START;
}

static bool zf_transport_nfc_send_pps_ack(ZfNfcTransportState *state, uint8_t ppss) {
    return zf_transport_nfc_send_frame(state, &ppss, 1U);
}

static void zf_transport_nfc_sync_response_pcb(ZfNfcTransportState *state, uint8_t request_pcb) {
    if (state) {
        state->iso_pcb = (uint8_t)(ZF_NFC_PCB_BLOCK | (request_pcb & 0x01U));
    }
}

static bool zf_transport_nfc_sync_i_block_header(ZfNfcTransportState *state, const uint8_t *frame,
                                                 size_t frame_len, size_t *payload_offset) {
    size_t offset = 1U;

    if (!state || !frame || !payload_offset || frame_len == 0U) {
        return false;
    }

    zf_transport_nfc_sync_response_pcb(state, frame[0]);
    state->iso_cid_present = (frame[0] & ZF_NFC_PCB_CID) != 0U;
    if (state->iso_cid_present) {
        if (frame_len < 2U) {
            return false;
        }
        state->iso_cid = frame[1];
        offset++;
    } else {
        state->iso_cid = 0U;
    }

    *payload_offset = offset;
    return frame_len >= offset;
}

static void zf_transport_nfc_trace_apdu_after_response(const uint8_t *apdu_bytes, size_t apdu_len) {
    ZfNfcApdu apdu;

    if (zf_transport_nfc_parse_apdu(apdu_bytes, apdu_len, &apdu)) {
        zf_transport_nfc_trace_apdu_header("rx", apdu_bytes[0], apdu.ins, apdu.p1, apdu.p2,
                                           apdu.data_len, apdu.extended, apdu.chained, apdu.has_le,
                                           apdu.le);
    }
    zf_transport_nfc_trace_bytes("apdu-rx", apdu_bytes, apdu_len);
}

static bool zf_transport_nfc_handle_native_desfire_get_version_locked(ZerofidoApp *app,
                                                                      ZfNfcTransportState *state) {
    static const uint8_t version_part1[] = {
        ZF_NFC_DESFIRE_STATUS_MORE, 0x04, 0x01, 0x01,
        0x01,                         0x00, 0x18, 0x05,
    };

    if (!app || !state) {
        return false;
    }

    zf_transport_nfc_note_ui_stage_locked(
        state, state->applet_selected ? ZfNfcUiStageAppletSelected : ZfNfcUiStageAppletWaiting);
#if ZF_RELEASE_DIAGNOSTICS
    zerofido_ui_set_status_locked(app, "DESFire native version");
#else
    (void)app;
#endif
    state->desfire_probe_frame = 1U;
    return zf_transport_nfc_send_iso_response(state, version_part1, sizeof(version_part1), false);
}

static bool zf_transport_nfc_handle_native_desfire_additional_frame_locked(
    ZerofidoApp *app, ZfNfcTransportState *state) {
    static const uint8_t version_part2[] = {
        ZF_NFC_DESFIRE_STATUS_MORE, 0x04, 0x01, 0x01,
        0x01,                         0x00, 0x18, 0x05,
    };
    static const uint8_t version_part3[] = {
        ZF_NFC_DESFIRE_STATUS_OK, 0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
        0x00,                     0x00, 0x00, 0x00, 0x24, 0x04, 0x26,
    };
    const bool final_frame = state && state->desfire_probe_frame >= 2U;

    if (!app || !state) {
        return false;
    }

    zf_transport_nfc_note_ui_stage_locked(
        state, state->applet_selected ? ZfNfcUiStageAppletSelected : ZfNfcUiStageAppletWaiting);
#if ZF_RELEASE_DIAGNOSTICS
    zerofido_ui_set_status_locked(app, final_frame ? "DESFire native done" : "DESFire native more");
#else
    (void)app;
#endif
    if (final_frame) {
        state->desfire_probe_frame = 0U;
        return zf_transport_nfc_send_iso_response(state, version_part3, sizeof(version_part3),
                                                  false);
    }

    state->desfire_probe_frame = 2U;
    return zf_transport_nfc_send_iso_response(state, version_part2, sizeof(version_part2), false);
}

static bool zf_transport_nfc_send_ats(ZfNfcTransportState *state) {
    const Iso14443_4aAtsData *ats = state ? &state->iso14443_4a_data->ats_data : NULL;
    uint8_t response[32];
    size_t response_len = 0;

    if (!state || !ats || ats->tl == 0U || ats->tl > sizeof(response)) {
        return false;
    }

    response[response_len++] = ats->tl;
    if (ats->tl > 1U) {
        response[response_len++] = ats->t0;
        if ((ats->t0 & ZF_NFC_ATS_T0_TA1) != 0U) {
            response[response_len++] = ats->ta_1;
        }
        if ((ats->t0 & ZF_NFC_ATS_T0_TB1) != 0U) {
            response[response_len++] = ats->tb_1;
        }
        if ((ats->t0 & ZF_NFC_ATS_T0_TC1) != 0U) {
            response[response_len++] = ats->tc_1;
        }

        const uint32_t historical_len = simple_array_get_count(ats->t1_tk);
        if (historical_len > 0U && response_len + historical_len <= sizeof(response)) {
            memcpy(&response[response_len], simple_array_cget_data(ats->t1_tk), historical_len);
            response_len += historical_len;
        }
    }

    return response_len == ats->tl && zf_transport_nfc_send_frame(state, response, response_len);
}

static NfcCommand zf_transport_nfc_handle_rats_locked(ZerofidoApp *app, ZfNfcTransportState *state,
                                                      const uint8_t *frame, size_t frame_len) {
    bool sent = false;
    const uint8_t ats_tc1 = state->iso14443_4a_data->ats_data.tc_1;

    state->applet_selected = false;
    state->desfire_probe_frame = 0U;
    zf_transport_nfc_cancel_current_request_locked(state);
    zf_transport_nfc_reset_exchange_locked(state);
    zf_transport_nfc_clear_last_iso_response(state);
    zf_nfc_iso4_layer_reset(state->iso4_layer);
    if ((ats_tc1 & ZF_NFC_ATS_TC1_CID) != 0U) {
        zf_nfc_iso4_layer_set_cid(state->iso4_layer, frame[1] & 0x0FU);
    }
    zf_nfc_iso4_layer_set_nad_supported(state->iso4_layer,
                                        (ats_tc1 & ZF_NFC_ATS_TC1_NAD) != 0U);
    state->iso_pcb = ZF_NFC_PCB_BLOCK;
    state->iso_cid_present = false;
    state->iso_cid = 0U;
    state->iso4_active = true;
    zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
    sent = zf_transport_nfc_send_ats(state);
    zf_transport_nfc_trace_bytes("iso3-rx", frame, frame_len);
    furi_mutex_release(app->ui_mutex);
    zf_transport_nfc_set_frame_status(app, sent ? "NFC RATS" : "NFC RATS fail", frame[0], &frame[1],
                                      frame_len - 1U);
    zerofido_ui_set_transport_connected(app, true);
    zf_u2f_adapter_set_connected(app, true);
    zerofido_ui_refresh_status(app);
    return NfcCommandContinue;
}

static NfcCommand zf_transport_nfc_handle_poll_restart_locked(
    ZerofidoApp *app, ZfNfcTransportState *state, const uint8_t *frame, size_t frame_len) {
    state->applet_selected = false;
    state->desfire_probe_frame = 0U;
    zf_transport_nfc_cancel_current_request_locked(state);
    zf_transport_nfc_reset_exchange_locked(state);
    zf_transport_nfc_clear_last_iso_response(state);
    zf_nfc_iso4_layer_reset(state->iso4_layer);
    state->iso_pcb = ZF_NFC_PCB_BLOCK;
    state->iso_cid_present = false;
    state->iso_cid = 0U;
    state->iso4_active = false;
    zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
    zf_transport_nfc_trace_bytes("iso3-rx", frame, frame_len);
    furi_mutex_release(app->ui_mutex);
    zf_transport_nfc_set_frame_status(app, "NFC poll restart", frame[0], NULL, 0U);
    zerofido_ui_set_transport_connected(app, true);
    zf_u2f_adapter_set_connected(app, true);
    zerofido_ui_refresh_status(app);
    return NfcCommandReset;
}

static NfcCommand zf_transport_nfc_handle_iso4_payload_locked(
    ZerofidoApp *app, ZfNfcTransportState *state, const uint8_t *payload, size_t payload_len,
    uint8_t request_pcb, bool request_chained, bool refresh_status) {
    if (!app) {
        return NfcCommandContinue;
    }

    if (!state || (!payload && payload_len > 0U)) {
        furi_mutex_release(app->ui_mutex);
        return NfcCommandContinue;
    }

    if (!request_chained && !state->command_chain_active && payload_len == 0U) {
        const bool replayed = zf_transport_nfc_replay_last_iso_response(state);
        const bool sent = replayed || zf_transport_nfc_send_r_ack(state, request_pcb);
        zf_transport_nfc_set_frame_status_locked(
            app, replayed ? "NFC I-empty replay" : "NFC I-empty", request_pcb, NULL, 0U);
        furi_mutex_release(app->ui_mutex);
        if (!sent) {
            zf_transport_nfc_set_frame_status(app, "NFC I-empty fail", request_pcb, NULL, 0U);
        }
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        if (refresh_status) {
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (!request_chained && !state->command_chain_active &&
        zf_transport_nfc_is_native_desfire_get_version_payload(payload, payload_len)) {
        zf_transport_nfc_handle_native_desfire_get_version_locked(app, state);
        zf_transport_nfc_trace_bytes("native-rx", payload, payload_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        if (refresh_status) {
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (!request_chained && !state->command_chain_active &&
        zf_transport_nfc_is_native_desfire_additional_frame(payload, payload_len)) {
        zf_transport_nfc_handle_native_desfire_additional_frame_locked(app, state);
        zf_transport_nfc_trace_bytes("native-rx", payload, payload_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        if (refresh_status) {
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (request_chained) {
        if (state->request_len > ZF_MAX_MSG_SIZE ||
            payload_len > ZF_MAX_MSG_SIZE - state->request_len) {
            zf_transport_nfc_reset_exchange_locked(state);
            furi_mutex_release(app->ui_mutex);
            zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
            zerofido_ui_set_transport_connected(app, true);
            zf_u2f_adapter_set_connected(app, true);
            if (refresh_status) {
                zerofido_ui_refresh_status(app);
            }
            return NfcCommandContinue;
        }

        if (payload_len > 0U) {
            memcpy(&app->transport_arena[state->request_len], payload, payload_len);
        }
        state->request_len += payload_len;
        state->command_chain_active = true;
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(app, "NFC I-chain", request_pcb, payload, payload_len);
        zf_transport_nfc_send_r_ack(state, request_pcb);
        zerofido_ui_set_transport_connected(app, true);
        zf_u2f_adapter_set_connected(app, true);
        if (refresh_status) {
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (state->command_chain_active) {
        const uint8_t *assembled_frame = NULL;
        size_t assembled_len = 0U;

        if (state->request_len > ZF_MAX_MSG_SIZE ||
            payload_len > ZF_MAX_MSG_SIZE - state->request_len) {
            zf_transport_nfc_reset_exchange_locked(state);
            furi_mutex_release(app->ui_mutex);
            zf_transport_nfc_send_status_word(state, ZF_NFC_SW_WRONG_LENGTH);
            zerofido_ui_set_transport_connected(app, true);
            zf_u2f_adapter_set_connected(app, true);
            if (refresh_status) {
                zerofido_ui_refresh_status(app);
            }
            return NfcCommandContinue;
        }

        if (payload_len > 0U) {
            memcpy(&app->transport_arena[state->request_len], payload, payload_len);
        }
        state->request_len += payload_len;
        assembled_frame = app->transport_arena;
        assembled_len = state->request_len;
        state->command_chain_active = false;
        state->request_len = 0U;

        zf_transport_nfc_set_frame_status_locked(app, "NFC I-block", request_pcb, assembled_frame,
                                                 assembled_len);
        zf_transport_nfc_handle_apdu(app, state, assembled_frame, assembled_len);
        zf_transport_nfc_trace_apdu_after_response(assembled_frame, assembled_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        zerofido_ui_refresh_status(app);
        return NfcCommandContinue;
    }

    zf_transport_nfc_set_frame_status_locked(app, "NFC I-block", request_pcb, payload, payload_len);
    zf_transport_nfc_handle_apdu(app, state, payload, payload_len);
    zf_transport_nfc_trace_apdu_after_response(payload, payload_len);
    furi_mutex_release(app->ui_mutex);
    zf_u2f_adapter_set_connected(app, true);
    zerofido_ui_set_transport_connected(app, true);
    zerofido_ui_refresh_status(app);
    return NfcCommandContinue;
}

static NfcCommand zf_transport_nfc_event_callback(NfcGenericEvent event, void *context) {
    ZerofidoApp *app = context;
    ZfNfcTransportState *state = app ? &app->transport_nfc_state_storage : NULL;
    const Iso14443_3aListenerEvent *iso3_event = NULL;
    const Iso14443_4aListenerEvent *iso4_event = NULL;
    const BitBuffer *rx_buffer = NULL;
    const uint8_t *frame = NULL;
    size_t frame_len = 0;
    size_t payload_offset = 1U;
    bool refresh_status = false;
    bool protocol_3a = false;
    bool protocol_4a = false;
    bool standard_frame = false;

    if (!app || !state || !event.event_data) {
        return NfcCommandStop;
    }

    if (event.protocol == NfcProtocolIso14443_3a) {
        protocol_3a = true;
        iso3_event = event.event_data;
    } else if (event.protocol == NfcProtocolIso14443_4a) {
        protocol_4a = true;
        iso4_event = event.event_data;
    } else {
        return NfcCommandStop;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    const bool callback_allowed = state->listener_active && !state->stopping;
    furi_mutex_release(app->ui_mutex);
    if (!callback_allowed) {
        return NfcCommandStop;
    }

    if (protocol_3a) {
        switch (iso3_event->type) {
        case Iso14443_3aListenerEventTypeReceivedStandardFrame:
            standard_frame = true;
            if (iso3_event->data) {
                rx_buffer = iso3_event->data->buffer;
            }
            break;
        case Iso14443_3aListenerEventTypeReceivedData:
            if (iso3_event->data) {
                rx_buffer = iso3_event->data->buffer;
            }
            break;
        case Iso14443_3aListenerEventTypeHalted:
            zf_transport_nfc_trace_event("iso3-halted");
            zf_transport_nfc_on_disconnect(app);
            return NfcCommandSleep;
        case Iso14443_3aListenerEventTypeFieldOff:
            zf_transport_nfc_trace_event("iso3-field-off");
            zf_transport_nfc_on_disconnect(app);
            return NfcCommandSleep;
        default:
            return NfcCommandContinue;
        }
    } else {
        switch (iso4_event->type) {
        case Iso14443_4aListenerEventTypeReceivedData:
            if (iso4_event->data) {
                rx_buffer = iso4_event->data->buffer;
            }
            break;
        case Iso14443_4aListenerEventTypeHalted:
            zf_transport_nfc_trace_event("iso4-halted");
            zf_transport_nfc_on_disconnect(app);
            return NfcCommandSleep;
        case Iso14443_4aListenerEventTypeFieldOff:
            zf_transport_nfc_trace_event("iso4-field-off");
            zf_transport_nfc_on_disconnect(app);
            return NfcCommandSleep;
        default:
            return NfcCommandContinue;
        }
    }

    if (!rx_buffer) {
        return NfcCommandContinue;
    }

    frame_len = bit_buffer_get_size_bytes(rx_buffer);
    if (frame_len == 0 || frame_len > (2U + ZF_NFC_MAX_FRAME_INF_SIZE)) {
        return NfcCommandContinue;
    }
    frame = bit_buffer_get_data(rx_buffer);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (protocol_4a && event.instance) {
        state->iso4_listener = (Iso14443_4aListener *)event.instance;
    } else if (protocol_3a) {
        state->iso4_listener = NULL;
    }
    refresh_status = !state->field_active || !state->iso4_active;
    state->field_active = true;

    if (protocol_3a && frame_len == 1U &&
        (frame[0] == ZF_NFC_REQA_CMD || frame[0] == ZF_NFC_WUPA_CMD)) {
        return zf_transport_nfc_handle_poll_restart_locked(app, state, frame, frame_len);
    }

    if (protocol_3a && standard_frame && frame_len == 2U && frame[0] == ZF_NFC_RATS_CMD) {
        return zf_transport_nfc_handle_rats_locked(app, state, frame, frame_len);
    }

    if (protocol_3a && !state->iso4_active) {
        furi_mutex_release(app->ui_mutex);
        return NfcCommandContinue;
    }

    state->iso4_active = true;
    if (state->applet_selected) {
        if (state->last_visible_stage != ZfNfcUiStageAppletSelected) {
            zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletSelected);
            refresh_status = true;
        }
    } else if (state->last_visible_stage != ZfNfcUiStageAppletWaiting) {
        zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
        refresh_status = true;
    }
    if (frame_len == 1U && frame[0] == ZF_NFC_DESFIRE_CMD_GET_VERSION) {
        zf_transport_nfc_handle_native_desfire_get_version_locked(app, state);
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        zerofido_ui_refresh_status(app);
        return NfcCommandContinue;
    }

    if (frame_len == 1U && frame[0] == ZF_NFC_DESFIRE_CMD_ADDITIONAL_FRAME) {
        zf_transport_nfc_handle_native_desfire_additional_frame_locked(app, state);
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        zerofido_ui_refresh_status(app);
        return NfcCommandContinue;
    }

    if (zf_transport_nfc_is_bare_apdu(frame, frame_len)) {
        state->iso_cid_present = false;
        zf_transport_nfc_handle_apdu(app, state, frame, frame_len);
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        zf_transport_nfc_trace_apdu_after_response(frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_set_transport_connected(app, true);
        zerofido_ui_refresh_status(app);
        return NfcCommandContinue;
    }

    if (zf_transport_nfc_is_r_block(frame[0])) {
        const bool r_nack = zf_transport_nfc_is_r_nack_block(frame[0]);
        bool sent = false;

        if (r_nack) {
            sent = zf_transport_nfc_replay_last_iso_response(state);
        }
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(
            app, r_nack ? (sent ? "NFC R-NAK replay" : "NFC R-NAK") : "NFC R-ACK", frame[0],
            &frame[1], frame_len - 1U);
        zerofido_ui_set_transport_connected(app, true);
        zf_u2f_adapter_set_connected(app, true);
        if (refresh_status) {
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (state->iso4_layer) {
        ZfNfcIso4LayerResult iso4_result = ZfNfcIso4LayerResultSkip;
        const uint8_t request_pcb = frame[0];
        bool sent = false;

        state->iso_cid_present = false;
        state->iso_cid = 0U;
        bit_buffer_reset(state->iso4_rx_buffer);
        iso4_result =
            zf_nfc_iso4_layer_decode_command(state->iso4_layer, rx_buffer, state->iso4_rx_buffer);

        if ((iso4_result & ZfNfcIso4LayerResultSend) != 0U) {
            sent = zf_transport_nfc_send_frame(state, bit_buffer_get_data(state->iso4_rx_buffer),
                                               bit_buffer_get_size_bytes(state->iso4_rx_buffer));
        }

        if ((iso4_result & ZfNfcIso4LayerResultHalt) != 0U) {
            state->applet_selected = false;
            zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
            zf_transport_nfc_cancel_current_request_locked(state);
            zf_transport_nfc_reset_exchange_locked(state);
            zf_nfc_iso4_layer_reset(state->iso4_layer);
            zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
            furi_mutex_release(app->ui_mutex);
            zerofido_ui_cancel_pending_interaction(app);
            zerofido_ui_set_transport_connected(app, false);
            zf_u2f_adapter_set_connected(app, false);
            zerofido_ui_refresh_status(app);
            return NfcCommandSleep;
        }

        if ((iso4_result & ZfNfcIso4LayerResultData) == 0U) {
            const bool pps_frame = zf_transport_nfc_is_pps_frame(frame, frame_len);

            if (!sent && pps_frame) {
                sent = zf_transport_nfc_send_pps_ack(state, frame[0]);
            }
            zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
            furi_mutex_release(app->ui_mutex);
            zf_transport_nfc_set_frame_status(
                app, sent ? (pps_frame ? "NFC PPS ack" : "NFC ISO4 ctl") : "NFC block", frame[0],
                &frame[1], frame_len - 1U);
            zerofido_ui_set_transport_connected(app, true);
            zf_u2f_adapter_set_connected(app, true);
            if (refresh_status) {
                zerofido_ui_refresh_status(app);
            }
            return NfcCommandContinue;
        }

        if (!zf_transport_nfc_sync_i_block_header(state, frame, frame_len, &payload_offset)) {
            zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
            furi_mutex_release(app->ui_mutex);
            zf_transport_nfc_set_frame_status(app, "NFC I malformed", frame[0], NULL, 0U);
            return NfcCommandContinue;
        }
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        frame = bit_buffer_get_data(state->iso4_rx_buffer);
        frame_len = bit_buffer_get_size_bytes(state->iso4_rx_buffer);
        return zf_transport_nfc_handle_iso4_payload_locked(
            app, state, frame, frame_len, request_pcb, (request_pcb & ZF_NFC_PCB_CHAIN) != 0U,
            refresh_status);
    }

    if (zf_transport_nfc_is_r_block(frame[0])) {
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(app, "NFC R-block", frame[0], &frame[1], frame_len - 1U);
        if (refresh_status) {
            zerofido_ui_set_transport_connected(app, true);
            zf_u2f_adapter_set_connected(app, true);
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (zf_transport_nfc_is_s_block(frame[0])) {
        const bool s_deselect = zf_transport_nfc_is_s_deselect_block(frame[0]);

        if (s_deselect) {
            state->applet_selected = false;
            zf_transport_nfc_note_ui_stage_locked(state, ZfNfcUiStageAppletWaiting);
            zf_transport_nfc_cancel_current_request_locked(state);
            zf_transport_nfc_reset_exchange_locked(state);
            state->iso_pcb = ZF_NFC_PCB_BLOCK;
            zf_transport_nfc_send_frame(state, (const uint8_t[]){0xC2U}, 1U);
        }
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(app, s_deselect ? "NFC S-deselect" : "NFC S-block",
                                          frame[0], &frame[1], frame_len - 1U);
        if (s_deselect) {
            zerofido_ui_cancel_pending_interaction(app);
        }
        zerofido_ui_set_transport_connected(app, true);
        zf_u2f_adapter_set_connected(app, true);
        zerofido_ui_refresh_status(app);
        return NfcCommandContinue;
    }

    if (!zf_transport_nfc_is_i_block(frame[0])) {
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(app, "NFC block", frame[0], &frame[1], frame_len - 1U);
        if (refresh_status) {
            zerofido_ui_set_transport_connected(app, true);
            zf_u2f_adapter_set_connected(app, true);
            zerofido_ui_refresh_status(app);
        }
        return NfcCommandContinue;
    }

    if (!zf_transport_nfc_sync_i_block_header(state, frame, frame_len, &payload_offset)) {
        zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
        furi_mutex_release(app->ui_mutex);
        zf_transport_nfc_set_frame_status(app, "NFC I malformed", frame[0], NULL, 0U);
        return NfcCommandContinue;
    }
    zf_transport_nfc_trace_bytes("iso-rx", frame, frame_len);
    return zf_transport_nfc_handle_iso4_payload_locked(
        app, state, &frame[payload_offset], frame_len - payload_offset, frame[0],
        (frame[0] & ZF_NFC_PCB_CHAIN) != 0U, refresh_status);
}

static void zf_transport_nfc_process_request(ZerofidoApp *app) {
    ZfNfcTransportState *state = &app->transport_nfc_state_storage;
    size_t request_len = 0;
    size_t response_len = 0;
    ZfTransportSessionId session_id = 0;
    ZfNfcRequestKind request_kind = ZfNfcRequestKindNone;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!state->request_pending) {
        furi_mutex_release(app->ui_mutex);
        return;
    }

    request_len = state->request_len;
    session_id = state->processing_session_id;
    request_kind = state->request_kind;
    furi_mutex_release(app->ui_mutex);

    switch (request_kind) {
    case ZfNfcRequestKindCtap2:
        response_len = zerofido_handle_ctap2(app, session_id, app->transport_arena, request_len,
                                             app->transport_arena, ZF_MAX_MSG_SIZE);
        zf_transport_nfc_store_response(
            app, state, session_id, app->transport_arena, response_len, false, response_len == 0,
            response_len == 0 ? ZF_NFC_SW_INTERNAL_ERROR : ZF_NFC_SW_SUCCESS);
        break;
    case ZfNfcRequestKindU2f:
        response_len = zf_u2f_adapter_handle_msg(app, session_id, app->transport_arena, request_len,
                                                 app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
        zf_transport_nfc_store_response(
            app, state, session_id, app->transport_arena, response_len, true, response_len == 0,
            response_len == 0 ? ZF_NFC_SW_INTERNAL_ERROR : ZF_NFC_SW_SUCCESS);
        break;
    case ZfNfcRequestKindNone:
    default:
        zf_transport_nfc_store_response(app, state, session_id, NULL, 0, false, true,
                                        ZF_NFC_SW_INTERNAL_ERROR);
        break;
    }
    (void)request_len;
}

int32_t zf_transport_nfc_worker(void *context) {
    ZerofidoApp *app = context;
    ZfNfcTransportState *state = &app->transport_nfc_state_storage;

    memset(state, 0, sizeof(*state));
    zf_transport_nfc_attach_arena(state, app->transport_arena, ZF_TRANSPORT_ARENA_SIZE);
    state->nfc = nfc_alloc();
    state->tx_buffer = bit_buffer_alloc(320U);
    state->iso4_rx_buffer = bit_buffer_alloc(320U);
    state->iso4_frame_buffer = bit_buffer_alloc(320U);
    state->iso4_last_tx_buffer = bit_buffer_alloc(320U);
    state->iso4_layer = zf_nfc_iso4_layer_alloc();
    state->iso14443_4a_data = iso14443_4a_alloc();
    if (!state->nfc || !state->tx_buffer || !state->iso4_rx_buffer || !state->iso4_frame_buffer ||
        !state->iso4_last_tx_buffer || !state->iso4_layer || !state->iso14443_4a_data) {
        zerofido_ui_set_status(app, "NFC init failed");
        if (state->iso14443_4a_data) {
            iso14443_4a_free(state->iso14443_4a_data);
        }
        if (state->iso4_layer) {
            zf_nfc_iso4_layer_free(state->iso4_layer);
        }
        if (state->iso4_frame_buffer) {
            bit_buffer_free(state->iso4_frame_buffer);
        }
        if (state->iso4_last_tx_buffer) {
            bit_buffer_free(state->iso4_last_tx_buffer);
        }
        if (state->iso4_rx_buffer) {
            bit_buffer_free(state->iso4_rx_buffer);
        }
        if (state->tx_buffer) {
            bit_buffer_free(state->tx_buffer);
        }
        if (state->nfc) {
            nfc_free(state->nfc);
        }
        memset(state, 0, sizeof(*state));
        return 0;
    }

    zf_transport_nfc_prepare_listener(state);
    state->listener = nfc_listener_alloc(state->nfc, NfcProtocolIso14443_3a,
                                         iso14443_4a_get_base_data(state->iso14443_4a_data));
    if (!state->listener) {
        zerofido_ui_set_status(app, "NFC listener failed");
        iso14443_4a_free(state->iso14443_4a_data);
        zf_nfc_iso4_layer_free(state->iso4_layer);
        bit_buffer_free(state->iso4_frame_buffer);
        bit_buffer_free(state->iso4_last_tx_buffer);
        bit_buffer_free(state->iso4_rx_buffer);
        bit_buffer_free(state->tx_buffer);
        nfc_free(state->nfc);
        memset(state, 0, sizeof(*state));
        return 0;
    }

    app->transport_state = state;
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    state->listener_active = true;
    state->field_active = false;
    state->iso4_active = false;
    state->applet_selected = false;
    state->iso_pcb = ZF_NFC_PCB_BLOCK;
    state->last_visible_stage = ZfNfcUiStageWaiting;
    state->last_visible_stage_tick = furi_get_tick();
    furi_mutex_release(app->ui_mutex);
    nfc_listener_start(state->listener, zf_transport_nfc_event_callback, app);
    zerofido_ui_refresh_status(app);

    while (true) {
        uint32_t flags = furi_thread_flags_wait(ZF_NFC_WORKER_EVT_STOP | ZF_NFC_WORKER_EVT_REQUEST,
                                                FuriFlagWaitAny, FuriWaitForever);
        if ((flags & FuriFlagError) != 0) {
            if (flags == FuriFlagErrorTimeout) {
                continue;
            }
            break;
        }
        if ((flags & ZF_NFC_WORKER_EVT_STOP) != 0U) {
            break;
        }
        if ((flags & ZF_NFC_WORKER_EVT_REQUEST) != 0U) {
            zf_transport_nfc_process_request(app);
        }
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    state->stopping = true;
    zf_transport_nfc_cancel_current_request_locked(state);
    state->listener_active = false;
    furi_mutex_release(app->ui_mutex);
    furi_semaphore_release(app->approval.done);
    nfc_listener_stop(state->listener);
    zf_transport_nfc_on_disconnect(app);
    app->transport_state = NULL;
    nfc_listener_free(state->listener);
    iso14443_4a_free(state->iso14443_4a_data);
    zf_nfc_iso4_layer_free(state->iso4_layer);
    bit_buffer_free(state->iso4_frame_buffer);
    bit_buffer_free(state->iso4_last_tx_buffer);
    bit_buffer_free(state->iso4_rx_buffer);
    bit_buffer_free(state->tx_buffer);
    nfc_free(state->nfc);
    zf_crypto_secure_zero(app->transport_arena, sizeof(app->transport_arena));
    memset(state, 0, sizeof(*state));
    return 0;
}

void zf_transport_nfc_stop(ZerofidoApp *app) {
    if (app) {
        ZfNfcTransportState *state = &app->transport_nfc_state_storage;

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        state->stopping = true;
        zf_transport_nfc_cancel_current_request_locked(state);
        furi_mutex_release(app->ui_mutex);
        if (app->approval.done) {
            furi_semaphore_release(app->approval.done);
        }
    }
    zf_transport_nfc_signal_worker(app, ZF_NFC_WORKER_EVT_STOP);
}

void zf_transport_nfc_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result) {
    ZfNfcTransportState *state = zf_transport_nfc_state(app);
    uint16_t error_status_word = ZF_NFC_SW_INTERNAL_ERROR;

    if (!state || !request || !result) {
        return;
    }

    switch (result->transport_error) {
    case ZF_HID_ERR_INVALID_CMD:
        error_status_word = ZF_NFC_SW_INS_NOT_SUPPORTED;
        break;
    case ZF_HID_ERR_INVALID_LEN:
        error_status_word = ZF_NFC_SW_WRONG_LENGTH;
        break;
    case ZF_HID_ERR_INVALID_PAR:
        error_status_word = ZF_NFC_SW_WRONG_DATA;
        break;
    default:
        error_status_word = ZF_NFC_SW_INTERNAL_ERROR;
        break;
    }

    zf_transport_nfc_store_response(app, state, request->session_id, result->response,
                                    result->response_len,
                                    request->protocol == ZfTransportProtocolKindU2f,
                                    result->send_transport_error, error_status_word);
}

bool zf_transport_nfc_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id,
                                           bool *approved) {
    const ZfNfcTransportState *state = zf_transport_nfc_state(app);

    if (!app || !state || !approved) {
        return false;
    }

    while (true) {
        if (furi_semaphore_acquire(app->approval.done, ZF_KEEPALIVE_INTERVAL_MS) == FuriStatusOk) {
            break;
        }

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (state->stopping || state->processing_cancel_requested ||
            state->processing_session_id != current_session_id) {
            furi_mutex_release(app->ui_mutex);
            return false;
        }
        furi_mutex_release(app->ui_mutex);
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (state->stopping || state->processing_cancel_requested ||
        state->processing_session_id != current_session_id) {
        furi_mutex_release(app->ui_mutex);
        return false;
    }
    *approved = (app->approval.state == ZfApprovalApproved);
    furi_mutex_release(app->ui_mutex);
    return true;
}

void zf_transport_nfc_notify_interaction_changed(ZerofidoApp *app) {
    UNUSED(app);
}

uint8_t zf_transport_nfc_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id) {
    const ZfNfcTransportState *state = zf_transport_nfc_state(app);

    if (!state) {
        return ZF_CTAP_SUCCESS;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (state->stopping ||
        (state->processing_cancel_requested &&
         state->processing_session_id == current_session_id) ||
        state->canceled_session_id == current_session_id) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    }
    furi_mutex_release(app->ui_mutex);
    return ZF_CTAP_SUCCESS;
}
