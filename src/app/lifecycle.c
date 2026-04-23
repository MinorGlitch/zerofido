#include "lifecycle.h"

#include <string.h>

#include "../transport/adapter.h"
#include "../u2f/adapter.h"
#include "../zerofido_attestation.h"
#include "../zerofido_crypto.h"
#include "../zerofido_notify.h"
#include "../zerofido_pin.h"
#include "../zerofido_runtime_config.h"
#include "../zerofido_store.h"
#include "../zerofido_ui.h"

typedef enum {
    ZfStorageInitOk = 0,
    ZfStorageInitFailed,
    ZfStorageInitInvalidPinState,
} ZfStorageInitStatus;

static bool zf_app_lifecycle_open_records(ZerofidoApp *app) {
    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->ui_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->approval.done = furi_semaphore_alloc(1, 0);

    if (!(app->gui && app->storage && app->notifications && app->ui_mutex && app->approval.done)) {
        return false;
    }

    return zerofido_notify_init(app);
}

static void zf_app_lifecycle_close_records(ZerofidoApp *app) {
    if (app->approval.done) {
        furi_semaphore_free(app->approval.done);
    }
    if (app->ui_mutex) {
        furi_mutex_free(app->ui_mutex);
    }
    if (app->storage) {
        furi_record_close(RECORD_STORAGE);
    }
    if (app->notifications) {
        zerofido_notify_deinit(app);
        furi_record_close(RECORD_NOTIFICATION);
    }
    if (app->gui) {
        furi_record_close(RECORD_GUI);
    }
}

static ZfStorageInitStatus zf_app_lifecycle_init_storage(ZerofidoApp *app) {
    ZfPinInitResult pin_init = ZfPinInitOk;

    zf_attestation_reset_consistency_cache();
    if (!zf_crypto_ensure_store_key()) {
        return ZfStorageInitFailed;
    }
    if (!zf_store_init(app->storage, &app->store)) {
        return ZfStorageInitFailed;
    }

    pin_init = zerofido_pin_init_with_result(app->storage, &app->pin_state);
    if (pin_init == ZfPinInitInvalidPersistedState) {
        return ZfStorageInitInvalidPinState;
    }

    return pin_init == ZfPinInitOk ? ZfStorageInitOk : ZfStorageInitFailed;
}

static const char *zf_app_lifecycle_backend_status(const ZerofidoApp *app,
                                                   ZfStorageInitStatus storage_status,
                                                   bool u2f_ready) {
    ZfResolvedCapabilities capabilities;
    bool transport_usable = false;

    zf_runtime_get_effective_capabilities(app, &capabilities);
    transport_usable = capabilities.usb_hid_enabled &&
                       (capabilities.fido2_enabled || !capabilities.u2f_enabled || u2f_ready);
    if (storage_status == ZfStorageInitOk && transport_usable) {
        return NULL;
    }
    if (storage_status == ZfStorageInitInvalidPinState) {
        return "PIN state invalid";
    }
    if (!capabilities.usb_hid_enabled) {
        return storage_status == ZfStorageInitOk ? "Transport disabled" : "Storage init failed";
    }
    if (storage_status != ZfStorageInitOk && !u2f_ready) {
        return "Backend init failed";
    }
    return storage_status == ZfStorageInitOk ? "U2F unavailable" : "Storage init failed";
}

static bool zf_app_lifecycle_start_worker(ZerofidoApp *app) {
    app->worker_thread =
        furi_thread_alloc_ex("ZeroFIDOWorker", 8 * 1024, app->transport_adapter->worker, app);
    if (!app->worker_thread) {
        return false;
    }

    furi_thread_set_appid(app->worker_thread, ZF_APP_ID);
    furi_thread_start(app->worker_thread);
    return true;
}

static void zf_app_lifecycle_stop_worker(ZerofidoApp *app) {
    if (!app->worker_thread) {
        return;
    }

    zf_transport_stop(app);
    furi_thread_join(app->worker_thread);
    furi_thread_free(app->worker_thread);
    app->worker_thread = NULL;
}

ZerofidoApp *zf_app_lifecycle_alloc(void) {
    ZerofidoApp *app = malloc(sizeof(ZerofidoApp));
    if (!app) {
        return NULL;
    }

    memset(app, 0, sizeof(*app));
    app->running = true;
    app->ui_events_enabled = true;
    app->transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app->runtime_config);
    zf_runtime_config_apply(app, &app->runtime_config);
    return app;
}

bool zf_app_lifecycle_open(ZerofidoApp *app) {
    return zf_app_lifecycle_open_records(app) && zerofido_ui_init(app);
}

bool zf_app_lifecycle_startup(ZerofidoApp *app) {
    ZfRuntimeConfig runtime_config;
    zf_runtime_config_load(app->storage, &runtime_config);
    zf_runtime_config_apply(app, &runtime_config);

    ZfStorageInitStatus storage_status = zf_app_lifecycle_init_storage(app);
    bool u2f_ready = !app->capabilities.u2f_enabled || zf_u2f_adapter_init(app);
    const char *backend_status = zf_app_lifecycle_backend_status(app, storage_status, u2f_ready);
    bool can_start_worker = storage_status == ZfStorageInitOk && app->capabilities.usb_hid_enabled &&
                            (app->capabilities.fido2_enabled || app->capabilities.u2f_enabled);

    if (backend_status) {
        app->startup_reset_available = storage_status == ZfStorageInitInvalidPinState;
        zerofido_ui_set_status(app, backend_status);
    }

    if (can_start_worker && !zf_app_lifecycle_start_worker(app)) {
        return false;
    }

    return true;
}

void zf_app_lifecycle_shutdown(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->running = false;
    furi_mutex_release(app->ui_mutex);
    zf_app_lifecycle_stop_worker(app);
}

void zf_app_lifecycle_free(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    zf_u2f_adapter_deinit(app);
    zf_store_deinit(&app->store);
    zerofido_ui_deinit(app);
    zf_app_lifecycle_close_records(app);
    free(app);
}
