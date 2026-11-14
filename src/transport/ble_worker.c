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

#include "../zerofido_types.h"

#if ZF_BLE_ACTIVE

#include "ble_worker.h"

#include <bt/bt_service/bt.h>
#include <furi.h>
#include <furi_hal_bt.h>
#include <stdlib.h>
#include <string.h>

#include "ble_framing.h"
#include "ble_profile.h"
#include "../u2f/adapter.h"
#include "../zerofido_app_i.h"
#include "../zerofido_crypto.h"
#include "../zerofido_ctap.h"
#include "../zerofido_notify.h"
#include "../zerofido_runtime_config.h"
#include "../zerofido_telemetry.h"
#include "../zerofido_ui.h"
#include "../zerofido_ui_i.h"

#define ZF_BLE_EVT_STOP (1U << 0)
#define ZF_BLE_EVT_CONNECT (1U << 1)
#define ZF_BLE_EVT_DISCONNECT (1U << 2)
#define ZF_BLE_EVT_WRITE (1U << 3)
#define ZF_BLE_EVT_APPROVAL (1U << 4)
#define ZF_BLE_EVT_ALL                                                                             \
    (ZF_BLE_EVT_STOP | ZF_BLE_EVT_CONNECT | ZF_BLE_EVT_DISCONNECT | ZF_BLE_EVT_WRITE |           \
     ZF_BLE_EVT_APPROVAL)

#define ZF_BLE_POLL_MS 50U
#define ZF_BLE_FRAGMENT_TIMEOUT_MS 3000U
#define ZF_BLE_RX_QUEUE_DEPTH 12U
#define ZF_BLE_SESSION_ID 1U
#define ZF_BLE_KEYS_PATH ZF_APP_DATA_DIR "/ble_keys.bin"
#define ZF_BLE_RADIO_SETTLE_MS 200U

typedef struct {
    uint8_t len;
    uint8_t data[ZF_BLE_PROFILE_WRITE_MAX];
} ZfBleRxItem;

typedef struct {
    FuriThreadId worker_id;
    FuriMessageQueue *rx_queue;
    ZfBleRx rx;
    Bt *bt;
    FuriHalBleProfileBase *profile;
    volatile bool link_up;
    bool stopping;
    bool processing;
    bool processing_cancel_requested;
    bool message_is_ctap2;
    uint32_t last_fragment_tick;
} ZfBleState;

static ZfBleState *zf_ble_state(const ZerofidoApp *app) {
    return app ? (ZfBleState *)app->transport_state : NULL;
}

static void zf_ble_signal(const ZfBleState *state, uint32_t flags) {
    if (state && state->worker_id) {
        furi_thread_flags_set(state->worker_id, flags);
    }
}

static bool zf_ble_stop_requested(const ZfBleState *state) {
    return state && state->stopping;
}

/* ---- BLE stack callbacks (not the worker thread: keep them tiny) ---- */

static void zf_ble_on_write(const uint8_t *data, uint16_t len, void *context) {
    ZfBleState *state = context;
    ZfBleRxItem item;

    if (!state || !data || len == 0U || len > sizeof(item.data)) {
        return;
    }
    item.len = (uint8_t)len;
    memcpy(item.data, data, len);
    if (furi_message_queue_put(state->rx_queue, &item, 0) == FuriStatusOk) {
        zf_ble_signal(state, ZF_BLE_EVT_WRITE);
    }
}

static void zf_ble_status_changed(BtStatus status, void *context) {
    ZfBleState *state = context;

    if (!state) {
        return;
    }
    if (status == BtStatusConnected) {
        if (!state->link_up) {
            state->link_up = true;
            zf_ble_signal(state, ZF_BLE_EVT_CONNECT);
        }
    } else if (state->link_up) {
        state->link_up = false;
        zf_ble_signal(state, ZF_BLE_EVT_DISCONNECT);
    }
}

/* ---- Sending ---- */

static void zf_ble_send_message(ZfBleState *state, uint8_t cmd, const uint8_t *data, size_t len) {
    ZfBleTx tx;
    uint8_t fragment[ZF_BLE_PROFILE_FRAGMENT_SIZE];
    size_t n;

    if (!state || !state->profile || !state->link_up) {
        return;
    }
    if (!zf_ble_tx_init(&tx, cmd, data, len, ZF_BLE_PROFILE_FRAGMENT_SIZE)) {
        return;
    }
    while ((n = zf_ble_tx_next(&tx, fragment, sizeof(fragment))) > 0U) {
        zf_ble_profile_notify(state->profile, fragment, (uint16_t)n);
        if (!state->link_up) {
            break;
        }
    }
}

static void zf_ble_send_error(ZfBleState *state, uint8_t error_code) {
    uint8_t message[4];
    size_t n = zf_ble_build_error(error_code, message, sizeof(message));

    if (n > 0U && state && state->profile && state->link_up) {
        zf_ble_profile_notify(state->profile, message, (uint16_t)n);
    }
}

static void zf_ble_send_keepalive(ZfBleState *state, uint8_t status) {
    uint8_t message[4];
    size_t n = zf_ble_build_keepalive(status, message, sizeof(message));

    if (n > 0U && state && state->profile && state->link_up) {
        zf_ble_profile_notify(state->profile, message, (uint16_t)n);
    }
}

/* ---- UI / session helpers ---- */

static void zf_ble_cancel_pending_ui(ZerofidoApp *app) {
    const ViewDispatcher *dispatcher = NULL;

    if (!zerofido_ui_cancel_pending_interaction(app)) {
        return;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->ui_events_enabled) {
        dispatcher = app->view_dispatcher;
    }
    furi_mutex_release(app->ui_mutex);
    if (dispatcher) {
        zerofido_ui_dispatch_custom_event(app, ZfEventHideApproval);
    }
}

static bool zf_ble_ui_connected(const ZerofidoApp *app) {
    bool connected;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    connected = app->transport_connected;
    furi_mutex_release(app->ui_mutex);
    return connected;
}

static void zf_ble_on_connect(ZerofidoApp *app, ZfBleState *state) {
    if (zf_ble_ui_connected(app)) {
        return;
    }
    zf_ble_rx_reset(&state->rx);
    zf_u2f_adapter_set_connected(app, true);
    zerofido_ui_set_transport_connected(app, true);
}

static void zf_ble_on_disconnect(ZerofidoApp *app, ZfBleState *state) {
    zf_ble_cancel_pending_ui(app);
    zf_ble_rx_reset(&state->rx);
    if (state->processing) {
        state->processing_cancel_requested = true;
    }
    zf_u2f_adapter_set_connected(app, false);
    zerofido_ui_set_transport_connected(app, false);
    zerofido_notify_reset(app);
}

/* While a command waits for the user, only CANCEL is meaningful; drop the rest. */
static void zf_ble_drain_control(ZerofidoApp *app, ZfBleState *state) {
    ZfBleRxItem item;

    while (furi_message_queue_get(state->rx_queue, &item, 0) == FuriStatusOk) {
        if (item.len > 0U && item.data[0] == ZF_BLE_CMD_CANCEL) {
            state->processing_cancel_requested = true;
            zf_ble_cancel_pending_ui(app);
        }
    }
}

/* ---- Message dispatch ---- */

void zf_transport_ble_send_dispatch_result(ZerofidoApp *app,
                                           const ZfProtocolDispatchRequest *request,
                                           const ZfProtocolDispatchResult *result) {
    ZfBleState *state = zf_ble_state(app);
    uint8_t command = ZF_BLE_CMD_MSG;

    if (!state || !request || !result) {
        return;
    }

    if (result->send_transport_error) {
        zf_ble_send_error(state, result->transport_error);
        zf_app_transport_arena_wipe(app);
        return;
    }

    switch (request->protocol) {
    case ZfTransportProtocolKindPing:
        command = ZF_BLE_CMD_PING;
        break;
    case ZfTransportProtocolKindU2f:
    case ZfTransportProtocolKindCtap2:
        command = ZF_BLE_CMD_MSG;
        break;
    default:
        zf_ble_send_error(state, ZF_BLE_ERR_INVALID_CMD);
        zf_app_transport_arena_wipe(app);
        return;
    }

    if (result->response_len == 0U) {
        zf_ble_send_error(state, ZF_BLE_ERR_OTHER);
    } else {
        zf_ble_send_message(state, command, result->response, result->response_len);
    }
    zf_app_transport_arena_wipe(app);
}

static void zf_ble_handle_message(ZerofidoApp *app, ZfBleState *state) {
    ZfResolvedCapabilities capabilities;
    ZfProtocolDispatchRequest request = {
        .session_id = ZF_BLE_SESSION_ID,
        .payload = state->rx.buf,
        .payload_len = state->rx.len,
    };
    ZfProtocolDispatchResult result = {0};

    if (state->rx.cmd == ZF_BLE_CMD_PING) {
        request.protocol = ZfTransportProtocolKindPing;
    } else {
        switch (zf_ble_classify_msg(state->rx.buf, state->rx.len)) {
        case ZfBleMessageKindU2f:
            request.protocol = ZfTransportProtocolKindU2f;
            break;
        case ZfBleMessageKindCtap2:
            request.protocol = ZfTransportProtocolKindCtap2;
            break;
        default:
            zf_ble_send_error(state, ZF_BLE_ERR_INVALID_LEN);
            return;
        }
    }

    result.response = app->transport_arena;
    result.response_capacity = ZF_MAX_MSG_SIZE;
    zf_runtime_get_effective_capabilities(app, &capabilities);

    state->processing = true;
    state->processing_cancel_requested = false;
    state->message_is_ctap2 = request.protocol == ZfTransportProtocolKindCtap2;

    switch (request.protocol) {
    case ZfTransportProtocolKindPing:
        result.response_len = request.payload_len; /* payload and response share the arena */
        break;
    case ZfTransportProtocolKindU2f:
        if (!capabilities.u2f_enabled) {
            zerofido_notify_error(app);
            result.send_transport_error = true;
            result.transport_error = ZF_BLE_ERR_INVALID_CMD;
            break;
        }
        result.response_len =
            zf_u2f_adapter_handle_msg(app, request.session_id, request.payload,
                                      request.payload_len, result.response,
                                      result.response_capacity);
        break;
    case ZfTransportProtocolKindCtap2:
        if (!capabilities.fido2_enabled) {
            zerofido_notify_error(app);
            result.send_transport_error = true;
            result.transport_error = ZF_BLE_ERR_INVALID_CMD;
            break;
        }
        zf_telemetry_log("ble ctap before");
        result.response_len =
            zerofido_handle_ctap2(app, request.session_id, request.payload, request.payload_len,
                                  result.response, result.response_capacity);
        zf_telemetry_log("ble ctap after");
        break;
    default:
        break;
    }

    if (request.protocol == ZfTransportProtocolKindCtap2 &&
        state->processing_cancel_requested && !result.send_transport_error) {
        result.response[0] = ZF_CTAP_ERR_KEEPALIVE_CANCEL;
        result.response_len = 1U;
    }

    state->processing = false;
    zf_transport_ble_send_dispatch_result(app, &request, &result);
    if (request.protocol == ZfTransportProtocolKindCtap2) {
        zerofido_ui_refresh_status(app);
    }
}

static void zf_ble_process_fragments(ZerofidoApp *app, ZfBleState *state) {
    ZfBleRxItem item;

    while (!zf_ble_stop_requested(state) &&
           furi_message_queue_get(state->rx_queue, &item, 0) == FuriStatusOk) {
        state->last_fragment_tick = furi_get_tick();
        zf_ble_on_connect(app, state);

        switch (zf_ble_rx_feed(&state->rx, item.data, item.len)) {
        case ZfBleRxComplete:
            zf_ble_handle_message(app, state);
            break;
        case ZfBleRxCancel:
            zf_ble_cancel_pending_ui(app);
            break;
        case ZfBleRxError:
            zf_ble_send_error(state, state->rx.error_code);
            break;
        case ZfBleRxIncomplete:
        default:
            break;
        }
    }
}

static void zf_ble_check_fragment_timeout(ZfBleState *state) {
    if (state->rx.active &&
        (furi_get_tick() - state->last_fragment_tick) > ZF_BLE_FRAGMENT_TIMEOUT_MS) {
        zf_ble_rx_reset(&state->rx);
        zf_ble_send_error(state, ZF_BLE_ERR_REQ_TIMEOUT);
    }
}

/* ---- Adapter hooks used by CTAP command code ---- */

uint8_t zf_transport_ble_poll_cbor_control(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id) {
    ZfBleState *state = zf_ble_state(app);

    UNUSED(current_session_id);
    if (!state || !state->processing || !state->message_is_ctap2) {
        return ZF_CTAP_SUCCESS;
    }
    if (zf_ble_stop_requested(state) || state->processing_cancel_requested) {
        state->processing_cancel_requested = true;
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    }
    if (furi_message_queue_get_count(state->rx_queue) > 0U) {
        zf_ble_drain_control(app, state);
    }
    if (zf_ble_stop_requested(state) || state->processing_cancel_requested) {
        state->processing_cancel_requested = true;
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    }
    return ZF_CTAP_SUCCESS;
}

bool zf_transport_ble_wait_for_interaction(ZerofidoApp *app,
                                           ZfTransportSessionId current_session_id,
                                           bool *approved) {
    ZfBleState *state = zf_ble_state(app);
    const bool send_keepalive = state && state->message_is_ctap2;
    bool sent_keepalive = false;

    UNUSED(current_session_id);
    if (!state) {
        return false;
    }

    while (true) {
        if (furi_semaphore_acquire(app->approval.done, 0) == FuriStatusOk) {
            break;
        }
        if (send_keepalive && !sent_keepalive) {
            zf_ble_send_keepalive(state, ZF_BLE_KEEPALIVE_USER_PRESENCE_NEEDED);
            sent_keepalive = true;
        }

        uint32_t flags = furi_thread_flags_wait(ZF_BLE_EVT_ALL, FuriFlagWaitAny,
                                                ZF_KEEPALIVE_INTERVAL_MS);
        if ((flags & FuriFlagError) != 0U) {
            if (flags != FuriFlagErrorTimeout) {
                return false;
            }
            if (send_keepalive) {
                zf_ble_send_keepalive(state, ZF_BLE_KEEPALIVE_USER_PRESENCE_NEEDED);
            }
            zf_ble_drain_control(app, state);
        } else {
            if (flags & ZF_BLE_EVT_STOP) {
                return false;
            }
            if (flags & ZF_BLE_EVT_DISCONNECT) {
                zf_ble_on_disconnect(app, state);
                return false;
            }
            if (flags & ZF_BLE_EVT_WRITE) {
                zf_ble_drain_control(app, state);
            }
        }

        if (zf_ble_stop_requested(state) || state->processing_cancel_requested) {
            state->processing_cancel_requested = true;
            return false;
        }
    }

    if (furi_mutex_acquire(app->ui_mutex, FuriWaitForever) != FuriStatusOk) {
        return false;
    }
    *approved = (app->approval.state == ZfApprovalApproved);
    furi_mutex_release(app->ui_mutex);
    return true;
}

void zf_transport_ble_notify_interaction_changed(ZerofidoApp *app) {
    zf_ble_signal(zf_ble_state(app), ZF_BLE_EVT_APPROVAL);
}

void zf_transport_ble_stop(ZerofidoApp *app) {
    ZfBleState *state;
    FuriSemaphore *approval_done;

    if (!app) {
        return;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    state = zf_ble_state(app);
    approval_done = app->approval.done;
    if (state) {
        state->stopping = true;
        state->processing_cancel_requested = true;
    }
    furi_mutex_release(app->ui_mutex);
    if (approval_done) {
        furi_semaphore_release(approval_done);
    }
    zf_ble_signal(state, ZF_BLE_EVT_STOP);
}

/* ---- Worker lifecycle ---- */

static bool zf_ble_radio_start(ZerofidoApp *app, ZfBleState *state) {
    ZfBleProfileParams params = {.on_write = zf_ble_on_write, .context = state};

    if (!furi_hal_bt_is_gatt_gap_supported()) {
        zerofido_ui_set_status(app, "BLE unavailable");
        return false;
    }

    state->bt = furi_record_open(RECORD_BT);
    bt_disconnect(state->bt);
    furi_delay_ms(ZF_BLE_RADIO_SETTLE_MS);
    bt_keys_storage_set_storage_path(state->bt, ZF_BLE_KEYS_PATH);

    state->profile = bt_profile_start(state->bt, zf_ble_profile, &params);
    if (!state->profile) {
        zerofido_ui_set_status(app, "BLE init failed");
        bt_keys_storage_set_default_path(state->bt);
        furi_record_close(RECORD_BT);
        state->bt = NULL;
        return false;
    }

    furi_hal_bt_start_advertising();
    bt_set_status_changed_callback(state->bt, zf_ble_status_changed, state);
    return true;
}

static void zf_ble_radio_stop(ZfBleState *state) {
    if (!state->bt) {
        return;
    }
    bt_set_status_changed_callback(state->bt, NULL, NULL);
    bt_disconnect(state->bt);
    furi_delay_ms(ZF_BLE_RADIO_SETTLE_MS);
    bt_keys_storage_set_default_path(state->bt);
    bt_profile_restore_default(state->bt);
    furi_record_close(RECORD_BT);
    state->bt = NULL;
    state->profile = NULL;
}

int32_t zf_transport_ble_worker(void *context) {
    ZerofidoApp *app = context;
    ZfBleState *state = calloc(1, sizeof(ZfBleState));
    bool radio_up = false;

    zf_telemetry_log("ble worker start");
    if (!state) {
        zerofido_ui_set_transport_connected(app, false);
        return 0;
    }
    state->worker_id = furi_thread_get_current_id();
    state->rx_queue = furi_message_queue_alloc(ZF_BLE_RX_QUEUE_DEPTH, sizeof(ZfBleRxItem));
    if (!zf_app_transport_arena_acquire(app)) {
        zf_telemetry_log_oom("ble transport arena", ZF_TRANSPORT_ARENA_SIZE);
        furi_message_queue_free(state->rx_queue);
        free(state);
        zerofido_ui_set_transport_connected(app, false);
        return 0;
    }
    zf_ble_rx_init(&state->rx, app->transport_arena, ZF_MAX_MSG_SIZE);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_state = state;
    furi_mutex_release(app->ui_mutex);

    radio_up = zf_ble_radio_start(app, state);
    if (radio_up) {
        zerofido_ui_set_status(app, "BLE: pair to connect");
    }

    while (radio_up) {
        uint32_t flags = furi_thread_flags_wait(ZF_BLE_EVT_ALL, FuriFlagWaitAny, ZF_BLE_POLL_MS);

        if ((flags & FuriFlagError) != 0U) {
            if (flags == FuriFlagErrorTimeout) {
                flags = 0U;
            } else {
                break;
            }
        }
        if ((flags & ZF_BLE_EVT_STOP) != 0U || zf_ble_stop_requested(state)) {
            break;
        }
        if ((flags & ZF_BLE_EVT_CONNECT) != 0U) {
            zf_ble_on_connect(app, state);
        }
        if ((flags & ZF_BLE_EVT_DISCONNECT) != 0U) {
            zf_ble_on_disconnect(app, state);
        }
        zf_ble_process_fragments(app, state);
        zf_ble_check_fragment_timeout(state);
    }

    zf_ble_on_disconnect(app, state);
    zf_ble_radio_stop(state);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_state = NULL;
    furi_mutex_release(app->ui_mutex);

    zf_crypto_secure_zero(&state->rx, sizeof(state->rx));
    furi_message_queue_free(state->rx_queue);
    free(state);
    zf_app_transport_arena_release(app);
    zerofido_notify_reset(app);
    zf_telemetry_log("ble worker stop");
    return 0;
}

#endif /* ZF_BLE_ACTIVE */
