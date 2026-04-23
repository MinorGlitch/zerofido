#include "assertion_queue.h"

#include <string.h>

#include "response.h"
#include "../transport/adapter.h"
#include "../zerofido_app_i.h"
#include "../zerofido_notify.h"
#include "../zerofido_store.h"

static bool zf_get_next_sign_count(const ZfCredentialRecord *record, uint32_t *next_sign_count) {
    if (!record || !next_sign_count || record->sign_count == UINT32_MAX) {
        return false;
    }

    *next_sign_count = record->sign_count + 1;
    return true;
}

void zf_ctap_assertion_queue_clear(ZerofidoApp *app) {
    memset(&app->assertion_queue, 0, sizeof(app->assertion_queue));
}

static uint8_t zf_ctap_assertion_queue_release(ZerofidoApp *app, uint8_t status) {
    furi_mutex_release(app->ui_mutex);
    return status;
}

static uint8_t zf_ctap_assertion_queue_clear_release(ZerofidoApp *app, uint8_t status) {
    zf_ctap_assertion_queue_clear(app);
    return zf_ctap_assertion_queue_release(app, status);
}

void zerofido_ctap_invalidate_assertion_queue(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
}

void zf_ctap_assertion_queue_seed(ZerofidoApp *app, uint32_t cid,
                                  const ZfGetAssertionRequest *request, bool uv_verified,
                                  const uint16_t *match_indices, size_t match_count) {
    zf_ctap_assertion_queue_clear(app);
    if (match_count <= 1) {
        return;
    }

    app->assertion_queue.active = true;
    app->assertion_queue.cid = cid;
    app->assertion_queue.uv_verified = uv_verified;
    app->assertion_queue.user_present = !(request->has_up && !request->up);
    app->assertion_queue.count = match_count;
    app->assertion_queue.index = 1;
    app->assertion_queue.expires_at = furi_get_tick() + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strncpy(app->assertion_queue.rp_id, request->rp_id, sizeof(app->assertion_queue.rp_id) - 1);
    memcpy(app->assertion_queue.client_data_hash, request->client_data_hash,
           sizeof(app->assertion_queue.client_data_hash));

    memcpy(app->assertion_queue.record_indices, match_indices,
           sizeof(app->assertion_queue.record_indices[0]) * match_count);
}

uint8_t zf_ctap_assertion_queue_handle_next(ZerofidoApp *app, uint32_t cid, uint8_t *out,
                                            size_t out_capacity, size_t *out_len) {
    uint8_t status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->assertion_queue.active ||
        (int32_t)(furi_get_tick() - app->assertion_queue.expires_at) >= 0 ||
        app->assertion_queue.index >= app->assertion_queue.count) {
        return zf_ctap_assertion_queue_clear_release(app, ZF_CTAP_ERR_NOT_ALLOWED);
    }
    if (cid != app->assertion_queue.cid) {
        return zf_ctap_assertion_queue_release(app, ZF_CTAP_ERR_INVALID_CHANNEL);
    }

    ZfGetAssertionRequest request = {0};
    memcpy(request.client_data_hash, app->assertion_queue.client_data_hash,
           sizeof(request.client_data_hash));
    strncpy(request.rp_id, app->assertion_queue.rp_id, sizeof(request.rp_id) - 1);

    size_t queue_index = app->assertion_queue.index++;
    ZfCredentialRecord record = {0};
    size_t record_index = app->assertion_queue.record_indices[queue_index];
    if (!zf_store_load_record_by_index(app->storage, &app->store, record_index, &record)) {
        return zf_ctap_assertion_queue_clear_release(app, ZF_CTAP_ERR_NOT_ALLOWED);
    }

    uint32_t next_sign_count = 0;
    ZfCredentialRecord updated_record = record;

    if (!zf_get_next_sign_count(&record, &next_sign_count)) {
        return zf_ctap_assertion_queue_clear_release(app, ZF_CTAP_ERR_OTHER);
    }

    status = zf_ctap_build_assertion_response(
        &request, &record, app->assertion_queue.user_present, app->assertion_queue.uv_verified,
        next_sign_count, app->assertion_queue.uv_verified, false, app->assertion_queue.count, out,
        out_capacity, out_len);
    if (status == ZF_CTAP_SUCCESS) {
        furi_mutex_release(app->ui_mutex);
        status = zf_transport_poll_cbor_control(app, cid);
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (status != ZF_CTAP_SUCCESS) {
            return zf_ctap_assertion_queue_clear_release(app, status);
        }
        updated_record.sign_count = next_sign_count;
        if (!zf_store_update_record(app->storage, &app->store, &updated_record)) {
            return zf_ctap_assertion_queue_clear_release(app, ZF_CTAP_ERR_OTHER);
        }
        app->assertion_queue.expires_at = furi_get_tick() + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    }
    if (app->assertion_queue.index >= app->assertion_queue.count) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    if (status == ZF_CTAP_SUCCESS) {
        zerofido_notify_success(app);
    }
    return status;
}
