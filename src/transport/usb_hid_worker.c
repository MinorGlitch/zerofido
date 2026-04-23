#include "usb_hid_worker.h"

#include <furi_hal_usb_hid_u2f.h>
#include <string.h>

#include "usb_hid_session.h"
#include "../u2f/adapter.h"
#include "../zerofido_app_i.h"
#include "../zerofido_notify.h"
#include "../zerofido_ui.h"
#include "../zerofido_ui_i.h"

#define ZF_WORKER_EVT_STOP (1 << 0)
#define ZF_WORKER_EVT_CONNECT (1 << 1)
#define ZF_WORKER_EVT_DISCONNECT (1 << 2)
#define ZF_WORKER_EVT_REQUEST (1 << 3)
#define ZF_WORKER_EVT_APPROVAL (1 << 4)
#define ZF_WORKER_POLL_MS 50U

static bool zf_transport_worker_is_connected(const ZerofidoApp *app) {
    bool connected = false;

    if (!app) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    connected = app->transport_connected;
    furi_mutex_release(app->ui_mutex);
    return connected;
}

static uint32_t zf_transport_worker_wait(uint32_t timeout_ms) {
    return furi_thread_flags_wait(ZF_WORKER_EVT_STOP | ZF_WORKER_EVT_CONNECT |
                                      ZF_WORKER_EVT_DISCONNECT | ZF_WORKER_EVT_REQUEST |
                                      ZF_WORKER_EVT_APPROVAL,
                                  FuriFlagWaitAny, timeout_ms);
}

static void zf_transport_signal_worker(ZerofidoApp *app, uint32_t flags) {
    if (!app || !app->worker_thread) {
        return;
    }

    FuriThreadId id = furi_thread_get_id(app->worker_thread);
    if (id) {
        furi_thread_flags_set(id, flags);
    }
}

static void zf_transport_event_callback(HidU2fEvent ev, void *context) {
    ZerofidoApp *app = context;

    furi_assert(app);
    if (!app->worker_thread) {
        return;
    }

    switch (ev) {
    case HidU2fConnected:
        zf_transport_signal_worker(app, ZF_WORKER_EVT_CONNECT);
        break;
    case HidU2fDisconnected:
        zf_transport_signal_worker(app, ZF_WORKER_EVT_DISCONNECT);
        break;
    case HidU2fRequest:
        zf_transport_signal_worker(app, ZF_WORKER_EVT_REQUEST);
        break;
    }
}

static bool zf_transport_enable_usb(ZerofidoApp *app) {
    app->previous_usb = furi_hal_usb_get_config();
    if (furi_hal_usb_set_config(&usb_hid_u2f, NULL)) {
        return true;
    }

    zerofido_ui_set_status(app, "USB HID init failed");
    return false;
}

static void zf_transport_restore_usb(ZerofidoApp *app) {
    furi_hal_hid_u2f_set_callback(NULL, NULL);
    if (app->previous_usb) {
        furi_hal_usb_set_config(app->previous_usb, NULL);
    }
}

static void zf_transport_worker_hide_interaction_if_needed(ZerofidoApp *app, bool canceled) {
    const ViewDispatcher *dispatcher = NULL;

    if (!canceled) {
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

static void zf_transport_worker_apply_actions(ZerofidoApp *app, uint32_t actions) {
    bool canceled = false;

    if ((actions & ZF_TRANSPORT_ACTION_CANCEL_PENDING_INTERACTION) == 0) {
        return;
    }

    canceled = zerofido_ui_cancel_pending_interaction(app);
    zf_transport_worker_hide_interaction_if_needed(app, canceled);
}

static void zf_transport_worker_on_connect(ZerofidoApp *app, ZfTransportState *transport) {
    if (zf_transport_worker_is_connected(app)) {
        return;
    }

    zf_transport_session_reset(transport);
    zf_transport_session_expire_lock(transport);
    zf_u2f_adapter_set_connected(app, true);
    zerofido_ui_set_transport_connected(app, true);
}

static void zf_transport_worker_on_disconnect(ZerofidoApp *app, ZfTransportState *transport) {
    bool canceled = zerofido_ui_cancel_pending_interaction(app);

    zf_transport_session_reset(transport);
    zf_transport_session_expire_lock(transport);
    zf_u2f_adapter_set_connected(app, false);
    zerofido_ui_set_transport_connected(app, false);
    zerofido_notify_reset(app);
    zf_transport_worker_hide_interaction_if_needed(app, canceled);
}

static void zf_transport_handle_worker_flags(ZerofidoApp *app, ZfTransportState *transport,
                                             uint32_t flags) {
    if (flags & ZF_WORKER_EVT_CONNECT) {
        zf_transport_worker_on_connect(app, transport);
    }
    if (flags & ZF_WORKER_EVT_DISCONNECT) {
        zf_transport_worker_on_disconnect(app, transport);
    }
}

static bool zf_transport_read_request(uint8_t *packet, size_t *packet_len) {
    *packet_len = furi_hal_hid_u2f_get_request(packet);
    return *packet_len > 0;
}

static void zf_transport_tick(ZfTransportState *transport) {
    zf_transport_session_tick(transport, furi_get_tick());
}

static void zf_transport_drain_processing_control_requests(ZerofidoApp *app,
                                                           ZfTransportState *transport) {
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE];

    while (true) {
        uint32_t actions = 0;
        size_t packet_len = 0;

        if (!zf_transport_read_request(packet, &packet_len)) {
            return;
        }

        uint8_t status = zf_transport_session_handle_processing_control(
            app, transport, packet, packet_len, &actions);
        zf_transport_worker_apply_actions(app, actions);
        if (status != ZF_CTAP_SUCCESS) {
            return;
        }
    }
}

static void zf_transport_handle_request(ZerofidoApp *app, ZfTransportState *transport,
                                        uint32_t flags, uint8_t *packet) {
    uint32_t actions = 0;
    size_t packet_len = 0;

    if ((flags & ZF_WORKER_EVT_REQUEST) == 0 && !zf_transport_read_request(packet, &packet_len)) {
        return;
    }

    while (true) {
        if (packet_len == 0 && !zf_transport_read_request(packet, &packet_len)) {
            return;
        }

        zf_transport_worker_on_connect(app, transport);
        zf_transport_session_handle_packet(app, transport, packet, packet_len, &actions);
        zf_transport_worker_apply_actions(app, actions);
        packet_len = 0;
    }
}

uint8_t zf_transport_usb_hid_poll_cbor_control(ZerofidoApp *app, uint32_t current_cid) {
    ZfTransportState *transport = app ? app->transport_state : NULL;

    if (!transport || !transport->processing || transport->cmd != ZF_CTAPHID_CBOR ||
        transport->cid != current_cid) {
        return ZF_CTAP_SUCCESS;
    }
    if (transport->processing_cancel_requested) {
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    }

    if ((furi_thread_flags_get() & ZF_WORKER_EVT_REQUEST) != 0) {
        furi_thread_flags_clear(ZF_WORKER_EVT_REQUEST);
    }
    zf_transport_drain_processing_control_requests(app, transport);
    zf_transport_tick(transport);
    return ZF_CTAP_SUCCESS;
}

bool zf_transport_usb_hid_wait_for_interaction(ZerofidoApp *app, uint32_t current_cid,
                                               bool *approved) {
    ZfTransportState *transport = app ? app->transport_state : NULL;
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE];
    bool sent_keepalive = false;

    if (!transport) {
        return false;
    }

    while (true) {
        if (furi_semaphore_acquire(app->approval.done, 0) == FuriStatusOk) {
            break;
        }

        if (!sent_keepalive) {
            zf_transport_usb_hid_send_keepalive(current_cid, ZF_KEEPALIVE_UPNEEDED);
            sent_keepalive = true;
        }

        uint32_t flags = zf_transport_worker_wait(ZF_KEEPALIVE_INTERVAL_MS);
        if ((flags & FuriFlagErrorTimeout) != 0) {
            zf_transport_handle_request(app, transport, 0, packet);
            if (transport->processing_cancel_requested) {
                return false;
            }
            zf_transport_usb_hid_send_keepalive(current_cid, ZF_KEEPALIVE_UPNEEDED);
            zf_transport_tick(transport);
            continue;
        }
        if ((flags & FuriFlagError) != 0) {
            return false;
        }
        if (flags & ZF_WORKER_EVT_STOP) {
            return false;
        }

        zf_transport_handle_worker_flags(app, transport, flags);
        zf_transport_handle_request(app, transport, flags, packet);
        zf_transport_tick(transport);
    }

    if (furi_mutex_acquire(app->ui_mutex, FuriWaitForever) != FuriStatusOk) {
        return false;
    }
    *approved = (app->approval.state == ZfApprovalApproved);
    furi_mutex_release(app->ui_mutex);
    return true;
}

int32_t zf_transport_usb_hid_worker(void *context) {
    ZerofidoApp *app = context;
    ZfTransportState *transport = &app->transport_state_storage;
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE];

    memset(transport, 0, sizeof(*transport));
    if (!zf_transport_enable_usb(app)) {
        return 0;
    }

    furi_hal_hid_u2f_set_callback(zf_transport_event_callback, app);
    app->transport_state = transport;
    if (furi_hal_hid_u2f_is_connected()) {
        zf_transport_worker_on_connect(app, transport);
    }

    while (true) {
        uint32_t flags = zf_transport_worker_wait(ZF_WORKER_POLL_MS);

        if ((flags & FuriFlagErrorTimeout) != 0) {
            flags = 0;
        } else if ((flags & FuriFlagError) != 0) {
            break;
        }
        if (flags & ZF_WORKER_EVT_STOP) {
            break;
        }

        zf_transport_handle_worker_flags(app, transport, flags);
        zf_transport_handle_request(app, transport, flags, packet);
        zf_transport_tick(transport);
    }

    app->transport_state = NULL;
    zf_transport_restore_usb(app);
    zerofido_notify_reset(app);
    return 0;
}

void zf_transport_usb_hid_stop(ZerofidoApp *app) {
    zf_transport_signal_worker(app, ZF_WORKER_EVT_STOP);
}

void zf_transport_usb_hid_send_keepalive(uint32_t cid, uint8_t status) {
    zf_transport_session_send_frames(cid, ZF_CTAPHID_KEEPALIVE, &status, 1);
}

void zf_transport_usb_hid_notify_interaction_changed(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    zf_transport_signal_worker(app, ZF_WORKER_EVT_APPROVAL);
}
