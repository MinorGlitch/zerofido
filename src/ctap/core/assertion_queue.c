#include "assertion_queue.h"

#include <string.h>

#include "../response.h"
#include "../../transport/adapter.h"
#include "../../zerofido_app_i.h"
#include "../../zerofido_crypto.h"
#include "../../zerofido_notify.h"
#include "../../zerofido_store.h"

static bool zf_get_next_sign_count(const ZfCredentialRecord *record, uint32_t *next_sign_count) {
    if (!record || !next_sign_count || record->sign_count == UINT32_MAX) {
        return false;
    }

    *next_sign_count = record->sign_count + 1;
    return true;
}

static bool zf_ctap_queue_entry_matches_record(const ZfCredentialIndexEntry *entry,
                                               const ZfCredentialRecord *record) {
    return entry && record && entry->in_use && record->in_use &&
           entry->credential_id_len == record->credential_id_len &&
           memcmp(entry->credential_id, record->credential_id, record->credential_id_len) == 0;
}

void zf_ctap_assertion_queue_clear(ZerofidoApp *app) {
    memset(&app->assertion_queue, 0, sizeof(app->assertion_queue));
}

static bool zf_ctap_assertion_queue_begin_maintenance(ZerofidoApp *app) {
    bool acquired = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->maintenance_busy) {
        app->maintenance_busy = true;
        acquired = true;
    }
    furi_mutex_release(app->ui_mutex);
    return acquired;
}

static void zf_ctap_assertion_queue_end_maintenance(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->maintenance_busy = false;
    furi_mutex_release(app->ui_mutex);
}

void zerofido_ctap_invalidate_assertion_queue(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
}

void zf_ctap_assertion_queue_seed(ZerofidoApp *app, ZfTransportSessionId session_id,
                                  const ZfGetAssertionRequest *request, bool uv_verified,
                                  const uint16_t *match_indices, size_t match_count) {
    zf_ctap_assertion_queue_clear(app);
    if (match_count <= 1) {
        return;
    }

    app->assertion_queue.active = true;
    app->assertion_queue.session_id = session_id;
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

static bool zf_ctap_assertion_queue_snapshot_entry_locked(ZerofidoApp *app, size_t record_index,
                                                          ZfCredentialIndexEntry *entry) {
    if (!app->store.records || record_index >= app->store.count ||
        !app->store.records[record_index].in_use) {
        return false;
    }

    *entry = app->store.records[record_index];
    return true;
}

static bool zf_ctap_assertion_queue_still_current_locked(ZerofidoApp *app,
                                                         ZfTransportSessionId session_id,
                                                         size_t queue_index, size_t record_index,
                                                         size_t count, const char *rp_id) {
    return app->assertion_queue.active && session_id == app->assertion_queue.session_id &&
           queue_index == app->assertion_queue.index && count == app->assertion_queue.count &&
           queue_index < app->assertion_queue.count &&
           app->assertion_queue.record_indices[queue_index] == record_index &&
           strcmp(app->assertion_queue.rp_id, rp_id) == 0;
}

static void zf_ctap_assertion_queue_clear_if_current(ZerofidoApp *app,
                                                     ZfTransportSessionId session_id,
                                                     size_t queue_index, size_t record_index,
                                                     size_t count, const char *rp_id) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (zf_ctap_assertion_queue_still_current_locked(app, session_id, queue_index, record_index,
                                                     count, rp_id)) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
}

uint8_t zf_ctap_assertion_queue_handle_next(ZerofidoApp *app, ZfTransportSessionId session_id,
                                            uint8_t *out, size_t out_capacity, size_t *out_len) {
    typedef struct {
        ZfGetAssertionRequest request;
        ZfCredentialIndexEntry entry;
        ZfCredentialRecord record;
        ZfCredentialRecord updated_record;
        ZfAssertionResponseScratch response;
        uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
    } ZfAssertionQueueScratch;

    _Static_assert(sizeof(ZfAssertionQueueScratch) <= ZF_COMMAND_SCRATCH_SIZE,
                   "getNextAssertion scratch exceeds command arena");

    uint8_t status = ZF_CTAP_ERR_OTHER;
    ZfAssertionQueueScratch *scratch = NULL;
    size_t queue_index = 0;
    size_t record_index = 0;
    size_t match_count = 0;
    bool user_present = false;
    bool uv_verified = false;
    uint32_t next_sign_count = 0;
    uint32_t prepared_counter_high_water = 0;
    bool maintenance_acquired = false;

    if (!app) {
        return ZF_CTAP_ERR_OTHER;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        return status;
    }

    if (!zf_ctap_assertion_queue_begin_maintenance(app)) {
        return ZF_CTAP_ERR_NOT_ALLOWED;
    }
    maintenance_acquired = true;

    scratch = zf_app_command_scratch_acquire(app, sizeof(*scratch));
    if (!scratch) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->assertion_queue.active ||
        (int32_t)(furi_get_tick() - app->assertion_queue.expires_at) >= 0 ||
        app->assertion_queue.index >= app->assertion_queue.count) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    if (session_id != app->assertion_queue.session_id) {
        status = ZF_CTAP_ERR_INVALID_CHANNEL;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }

    memcpy(scratch->request.client_data_hash, app->assertion_queue.client_data_hash,
           sizeof(scratch->request.client_data_hash));
    strncpy(scratch->request.rp_id, app->assertion_queue.rp_id,
            sizeof(scratch->request.rp_id) - 1);

    queue_index = app->assertion_queue.index;
    record_index = app->assertion_queue.record_indices[queue_index];
    match_count = app->assertion_queue.count;
    user_present = app->assertion_queue.user_present;
    uv_verified = app->assertion_queue.uv_verified;
    if (!zf_ctap_assertion_queue_snapshot_entry_locked(app, record_index, &scratch->entry)) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    furi_mutex_release(app->ui_mutex);

    if (!zf_store_load_record_with_buffer(app->storage, &scratch->entry, &scratch->record,
                                          scratch->store_io, sizeof(scratch->store_io)) ||
        strcmp(scratch->record.rp_id, scratch->request.rp_id) != 0 ||
        !zf_ctap_queue_entry_matches_record(&scratch->entry, &scratch->record)) {
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }
    scratch->updated_record = scratch->record;

    if (!zf_get_next_sign_count(&scratch->record, &next_sign_count)) {
        status = ZF_CTAP_ERR_OTHER;
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }

    status = zf_ctap_build_assertion_response_with_scratch(
        &scratch->response, &scratch->request, &scratch->record, user_present, uv_verified,
        next_sign_count, uv_verified, false, match_count, false, out, out_capacity, out_len);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        goto cleanup;
    }
    scratch->updated_record.sign_count = next_sign_count;
    if (!zf_store_prepare_counter_advance(app->storage, &scratch->entry,
                                          &scratch->updated_record,
                                          &prepared_counter_high_water)) {
        zf_ctap_assertion_queue_clear_if_current(app, session_id, queue_index, record_index,
                                                 match_count, scratch->request.rp_id);
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    bool queue_current = zf_ctap_assertion_queue_still_current_locked(
        app, session_id, queue_index, record_index, match_count, scratch->request.rp_id);
    bool record_current =
        queue_current && app->store.records && record_index < app->store.count &&
        zf_ctap_queue_entry_matches_record(&app->store.records[record_index], &scratch->record);
    if (!record_current) {
        if (queue_current) {
            zf_ctap_assertion_queue_clear(app);
        }
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    if (!zf_store_publish_counter_advance(&app->store, &scratch->updated_record,
                                          prepared_counter_high_water)) {
        zf_ctap_assertion_queue_clear(app);
        status = ZF_CTAP_ERR_OTHER;
        furi_mutex_release(app->ui_mutex);
        goto cleanup;
    }
    app->assertion_queue.index = queue_index + 1U;
    app->assertion_queue.expires_at = furi_get_tick() + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    if (app->assertion_queue.index >= app->assertion_queue.count) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    zerofido_notify_success(app);

cleanup:
    if (maintenance_acquired) {
        zf_ctap_assertion_queue_end_maintenance(app);
    }
    if (scratch) {
        zf_crypto_secure_zero(scratch, sizeof(*scratch));
    }
    zf_app_command_scratch_release(app);
    return status;
}
