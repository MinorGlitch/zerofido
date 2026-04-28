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
#include "../zerofido_ui_i.h"

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
    if (!app->store.records) {
        app->store.records = app->store_records;
    }
    if (!zf_store_init_with_buffer(app->storage, &app->store, app->command_scratch.bytes,
                                   sizeof(app->command_scratch.bytes))) {
        return ZfStorageInitFailed;
    }

    pin_init = zerofido_pin_init_with_result(app->storage, &app->pin_state);
    if (pin_init == ZfPinInitInvalidPersistedState) {
        return ZfStorageInitInvalidPinState;
    }

    return pin_init == ZfPinInitOk ? ZfStorageInitOk : ZfStorageInitFailed;
}

static const ZfTransportAdapterOps *zf_app_lifecycle_adapter_for_mode(ZfTransportMode mode) {
#ifdef ZF_NFC_ONLY
    UNUSED(mode);
    return &zf_transport_nfc_adapter;
#else
    switch (mode) {
    case ZfTransportModeNfc:
        return &zf_transport_nfc_adapter;
    case ZfTransportModeUsbHid:
    default:
        return &zf_transport_usb_hid_adapter;
    }
#endif
}

static void zf_app_lifecycle_load_runtime_config(ZerofidoApp *app) {
    ZfRuntimeConfig runtime_config;

    zf_runtime_config_load(app->storage, &runtime_config);
    zf_runtime_config_apply(app, &runtime_config);
    app->transport_adapter = zf_app_lifecycle_adapter_for_mode(app->runtime_config.transport_mode);
}

static const char *zf_app_lifecycle_backend_status(const ZerofidoApp *app,
                                                   ZfStorageInitStatus storage_status,
                                                   bool u2f_ready) {
    ZfResolvedCapabilities capabilities;
    bool transport_usable = false;

    zf_runtime_get_effective_capabilities(app, &capabilities);
    transport_usable = (capabilities.fido2_enabled || !capabilities.u2f_enabled || u2f_ready);
    if (storage_status == ZfStorageInitOk && transport_usable) {
        return NULL;
    }
    if (storage_status == ZfStorageInitInvalidPinState) {
        return "PIN state invalid";
    }
    if (storage_status != ZfStorageInitOk && !u2f_ready) {
        return "Backend init failed";
    }
    return storage_status == ZfStorageInitOk ? "U2F unavailable" : "Storage init failed";
}

static bool zf_app_lifecycle_start_worker(ZerofidoApp *app) {
    FuriThread *thread = NULL;
    size_t worker_stack_size = 8 * 1024;

    if (!app || !app->transport_adapter || !app->transport_adapter->worker) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->worker_thread) {
        furi_mutex_release(app->ui_mutex);
        return true;
    }
    furi_mutex_release(app->ui_mutex);

    if (app->transport_adapter->worker_stack_size > 0) {
        worker_stack_size = app->transport_adapter->worker_stack_size;
    }

    thread = furi_thread_alloc_ex("ZeroFIDOWorker", worker_stack_size,
                                  app->transport_adapter->worker, app);
    if (!thread) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->worker_thread) {
        furi_mutex_release(app->ui_mutex);
        furi_thread_free(thread);
        return true;
    }
    app->worker_thread = thread;
    furi_mutex_release(app->ui_mutex);

    furi_thread_set_appid(thread, ZF_APP_ID);
    furi_thread_start(thread);
    return true;
}

static bool zf_app_lifecycle_is_running(ZerofidoApp *app) {
    bool running = false;

    if (!app || !app->ui_mutex) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    running = app->running;
    furi_mutex_release(app->ui_mutex);
    return running;
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
    app->store.records = app->store_records;
    app->running = true;
    app->ui_events_enabled = true;
    zf_runtime_config_load_defaults(&app->runtime_config);
    app->transport_adapter = zf_app_lifecycle_adapter_for_mode(app->runtime_config.transport_mode);
    zf_runtime_config_apply(app, &app->runtime_config);
    return app;
}

bool zf_app_lifecycle_open(ZerofidoApp *app) {
    if (!zf_app_lifecycle_open_records(app)) {
        return false;
    }

    zf_app_lifecycle_load_runtime_config(app);
    return zerofido_ui_init(app);
}

bool zf_app_lifecycle_startup(ZerofidoApp *app) {
    zf_app_lifecycle_load_runtime_config(app);

    ZfStorageInitStatus storage_status = zf_app_lifecycle_init_storage(app);
    bool u2f_ready = true;
    const char *backend_status = zf_app_lifecycle_backend_status(app, storage_status, u2f_ready);
    bool can_start_worker = storage_status == ZfStorageInitOk &&
                            (app->capabilities.fido2_enabled || app->capabilities.u2f_enabled);

    if (backend_status) {
        app->startup_reset_available = storage_status == ZfStorageInitInvalidPinState;
        zerofido_ui_set_status(app, backend_status);
    } else {
        zerofido_ui_set_status(app, NULL);
    }

    if (can_start_worker && zf_app_lifecycle_is_running(app) &&
        !zf_app_lifecycle_start_worker(app)) {
        return false;
    }

    zerofido_ui_refresh_status(app);
    return true;
}

static int32_t zf_app_lifecycle_startup_worker(void *context) {
    ZerofidoApp *app = context;
    bool ok = zf_app_lifecycle_startup(app);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->startup_ok = ok;
    app->startup_complete = true;
    furi_mutex_release(app->ui_mutex);

    if (!ok) {
        zerofido_ui_set_status(app, "Startup failed");
        zerofido_ui_refresh_status(app);
    }
    return 0;
}

bool zf_app_lifecycle_startup_async(ZerofidoApp *app) {
    if (!app || !app->ui_mutex) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->startup_complete = false;
    app->startup_ok = false;
    furi_mutex_release(app->ui_mutex);

    zerofido_ui_set_status(app, "Starting...");
    app->startup_thread =
        furi_thread_alloc_ex("ZeroFIDOStart", 8 * 1024, zf_app_lifecycle_startup_worker, app);
    if (!app->startup_thread) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        app->startup_ok = false;
        app->startup_complete = true;
        furi_mutex_release(app->ui_mutex);
        zerofido_ui_set_status(app, "Startup failed");
        return false;
    }

    furi_thread_set_appid(app->startup_thread, ZF_APP_ID);
    furi_thread_start(app->startup_thread);
    return true;
}

void zf_app_lifecycle_wait_startup(ZerofidoApp *app) {
    if (!app || !app->startup_thread) {
        return;
    }

    furi_thread_join(app->startup_thread);
    furi_thread_free(app->startup_thread);
    app->startup_thread = NULL;
}

bool zf_app_lifecycle_startup_pending(ZerofidoApp *app) {
    bool pending = false;

    if (!app || !app->ui_mutex) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    pending = app->startup_thread && !app->startup_complete;
    furi_mutex_release(app->ui_mutex);
    return pending;
}

bool zf_app_lifecycle_restart_transport(ZerofidoApp *app) {
    if (!app) {
        return false;
    }
    if (zf_app_lifecycle_startup_pending(app)) {
        return false;
    }

    zf_app_lifecycle_stop_worker(app);
    app->transport_adapter = zf_app_lifecycle_adapter_for_mode(app->runtime_config.transport_mode);
    if (!(app->capabilities.fido2_enabled || app->capabilities.u2f_enabled)) {
        return true;
    }

    return zf_app_lifecycle_start_worker(app);
}

void zf_app_lifecycle_shutdown(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->running = false;
    app->ui_events_enabled = false;
    furi_mutex_release(app->ui_mutex);
    zf_app_lifecycle_wait_startup(app);
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
    zf_crypto_secure_zero(app, sizeof(*app));
    free(app);
}
