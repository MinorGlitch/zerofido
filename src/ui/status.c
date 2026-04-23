#include "../zerofido_ui.h"

#include <gui/elements.h>

#include "../zerofido_app_i.h"
#include "status.h"

typedef struct {
    ZerofidoApp *app;
} ZfStatusModel;

static void zf_status_draw_callback(Canvas *canvas, void *model) {
    ZfStatusModel *status = model;
    ZerofidoApp *app = status ? status->app : NULL;
    bool startup_reset_available = false;
    bool worker_started = false;

    furi_assert(app);
    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    startup_reset_available = app->startup_reset_available;
    worker_started = app->worker_thread != NULL;
    furi_mutex_release(app->ui_mutex);

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 3, AlignCenter, AlignTop, "ZeroFIDO");
    elements_button_left(canvas, "Exit");
    if (startup_reset_available) {
        elements_button_right(canvas, "Reset");
    } else if (worker_started) {
        elements_button_right(canvas, "Settings");
    }
}

void zerofido_ui_status_bind_view(ZerofidoApp *app) {
    view_allocate_model(app->status_view, ViewModelTypeLocking, sizeof(ZfStatusModel));
    view_set_context(app->status_view, app);
    view_set_draw_callback(app->status_view, zf_status_draw_callback);
    with_view_model(app->status_view, ZfStatusModel * model, { model->app = app; }, false);
}

void zerofido_ui_refresh_status(ZerofidoApp *app) {
    if (app->status_view) {
        with_view_model(app->status_view, ZfStatusModel * model, { UNUSED(model); }, true);
    }
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *text) {
    UNUSED(app);
    UNUSED(text);
}

void zerofido_ui_apply_transport_connected(ZerofidoApp *app, bool connected) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->transport_connected = connected;
    furi_mutex_release(app->ui_mutex);
    zerofido_ui_refresh_status(app);
}

void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected) {
    zerofido_ui_apply_transport_connected(app, connected);
}
