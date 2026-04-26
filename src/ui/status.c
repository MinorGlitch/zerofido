#include "../zerofido_ui.h"

#include <stdio.h>
#include <string.h>

#include <gui/elements.h>

#include "../zerofido_app_i.h"
#include "status.h"

typedef struct {
    ZfTransportMode transport_mode;
    char status_line[64];
    bool transport_connected;
    bool worker_started;
    bool listener_active;
    bool field_active;
    bool iso4_active;
    bool applet_selected;
    uint8_t last_visible_stage;
    uint32_t last_visible_stage_tick;
} ZfStatusSnapshot;

typedef struct {
    ZerofidoApp *app;
    ZfStatusSnapshot snapshot;
} ZfStatusModel;

#define ZF_NFC_STATUS_LATCH_TICKS 1500U

static void zf_status_snapshot_from_app_locked(ZerofidoApp *app, ZfStatusSnapshot *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->last_visible_stage = ZfNfcUiStageWaiting;

    if (!app) {
        return;
    }

    snapshot->transport_mode = app->runtime_config.transport_mode;
    snapshot->transport_connected = app->transport_connected;
    snapshot->worker_started = app->worker_thread != NULL;
    if (snapshot->transport_mode == ZfTransportModeNfc) {
        snapshot->listener_active = app->transport_nfc_state_storage.listener_active;
        snapshot->field_active = app->transport_nfc_state_storage.field_active;
        snapshot->iso4_active = app->transport_nfc_state_storage.iso4_active;
        snapshot->applet_selected = app->transport_nfc_state_storage.applet_selected;
        snapshot->last_visible_stage = app->transport_nfc_state_storage.last_visible_stage;
        snapshot->last_visible_stage_tick =
            app->transport_nfc_state_storage.last_visible_stage_tick;
    }
    strncpy(snapshot->status_line, app->status_text, sizeof(snapshot->status_line) - 1U);
    snapshot->status_line[sizeof(snapshot->status_line) - 1U] = '\0';
}

static void zf_status_refresh_model(ZerofidoApp *app, bool redraw) {
    ZfStatusSnapshot snapshot;

    if (!app || !app->status_view) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_status_snapshot_from_app_locked(app, &snapshot);
    furi_mutex_release(app->ui_mutex);

    with_view_model(
        app->status_view, ZfStatusModel * model,
        {
            model->app = app;
            model->snapshot = snapshot;
        },
        redraw);
}

static void zf_status_draw_callback(Canvas *canvas, void *model) {
    ZfStatusModel *status = model;
    ZfStatusSnapshot snapshot;
    char transport_line[32] = {0};
    char detail_line[48] = {0};
    const uint32_t now = furi_get_tick();

    furi_assert(status);
    if (!status) {
        return;
    }
    snapshot = status->snapshot;

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 36, 11, "ZeroFIDO");
    canvas_set_font(canvas, FontSecondary);

    snprintf(transport_line, sizeof(transport_line), "Transport: %s",
             snapshot.transport_mode == ZfTransportModeNfc ? "NFC" : "USB HID");

    if (snapshot.transport_mode == ZfTransportModeNfc) {
        if (!snapshot.worker_started) {
            strncpy(detail_line, "NFC listener: stopped", sizeof(detail_line) - 1U);
        } else if (!snapshot.listener_active) {
            strncpy(detail_line, "NFC listener: waiting", sizeof(detail_line) - 1U);
        } else {
            uint8_t display_stage = ZfNfcUiStageWaiting;
            if (snapshot.field_active && snapshot.iso4_active) {
                display_stage = snapshot.applet_selected ? ZfNfcUiStageAppletSelected
                                                         : ZfNfcUiStageAppletWaiting;
            } else if (snapshot.last_visible_stage > ZfNfcUiStageWaiting &&
                       (now - snapshot.last_visible_stage_tick) <= ZF_NFC_STATUS_LATCH_TICKS) {
                display_stage = snapshot.last_visible_stage;
            }

            switch (display_stage) {
            case ZfNfcUiStageAppletSelected:
                strncpy(detail_line, "FIDO applet: selected", sizeof(detail_line) - 1U);
                break;
            case ZfNfcUiStageAppletWaiting:
                strncpy(detail_line, "FIDO applet: waiting", sizeof(detail_line) - 1U);
                break;
            case ZfNfcUiStageWaiting:
            default:
                strncpy(detail_line, "NFC listener: waiting", sizeof(detail_line) - 1U);
                break;
            }
        }
        detail_line[sizeof(detail_line) - 1U] = '\0';
    } else {
        strncpy(detail_line, snapshot.transport_connected ? "USB HID: connected" : "USB HID: idle",
                sizeof(detail_line) - 1U);
        detail_line[sizeof(detail_line) - 1U] = '\0';
    }

    canvas_draw_str(canvas, 4, 25, transport_line);
    canvas_draw_str(canvas, 4, 37, detail_line);
    if (snapshot.status_line[0] != '\0') {
        canvas_draw_str(canvas, 4, 49, snapshot.status_line);
    }
    elements_button_left(canvas, "Exit");
    elements_button_right(canvas, "Settings");
}

void zerofido_ui_status_bind_view(ZerofidoApp *app) {
    view_allocate_model(app->status_view, ViewModelTypeLocking, sizeof(ZfStatusModel));
    view_set_context(app->status_view, app);
    view_set_draw_callback(app->status_view, zf_status_draw_callback);
    zf_status_refresh_model(app, false);
}

void zerofido_ui_refresh_status(ZerofidoApp *app) {
    zf_status_refresh_model(app, true);
}

void zerofido_ui_set_status_locked(ZerofidoApp *app, const char *text) {
    if (!app) {
        return;
    }

    if (text) {
        if (strncmp(app->status_text, text, sizeof(app->status_text)) == 0) {
            return;
        }

        strncpy(app->status_text, text, sizeof(app->status_text) - 1U);
        app->status_text[sizeof(app->status_text) - 1U] = '\0';
    } else {
        if (app->status_text[0] == '\0') {
            return;
        }
        app->status_text[0] = '\0';
    }
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *text) {
    bool changed = false;

    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (text) {
        changed = strncmp(app->status_text, text, sizeof(app->status_text)) != 0;
    } else {
        changed = app->status_text[0] != '\0';
    }
    zerofido_ui_set_status_locked(app, text);
    furi_mutex_release(app->ui_mutex);
    if (changed) {
        zerofido_ui_refresh_status(app);
    }
}

void zerofido_ui_apply_transport_connected(ZerofidoApp *app, bool connected) {
    bool changed = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    changed = app->transport_connected != connected;
    app->transport_connected = connected;
    furi_mutex_release(app->ui_mutex);
    if (changed) {
        zerofido_ui_refresh_status(app);
    }
}

void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected) {
    zerofido_ui_apply_transport_connected(app, connected);
}
