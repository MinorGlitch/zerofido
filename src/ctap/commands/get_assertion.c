#include "get_assertion.h"

#include <string.h>

#include "../core/approval.h"
#include "../core/assertion_queue.h"
#include "../core/internal.h"
#include "../parse.h"
#include "../policy.h"
#include "../response.h"
#include "../../transport/adapter.h"
#include "../../zerofido_app_i.h"
#include "../../zerofido_crypto.h"
#include "../../zerofido_notify.h"
#include "../../zerofido_store.h"

static uint8_t zf_prepare_assertion_response(const ZfGetAssertionRequest *request,
                                             const ZfCredentialRecord *record, bool user_present,
                                             bool uv_verified, bool include_count,
                                             size_t match_count, bool user_selected,
                                             ZfCredentialRecord *updated_record,
                                             ZfAssertionResponseScratch *response_scratch,
                                             uint8_t *out, size_t out_capacity, size_t *out_len) {
    bool include_user_details = uv_verified && !zf_ctap_request_uses_allow_list(request);
    uint32_t next_sign_count = 0;

    if (!record || !updated_record || record->sign_count == UINT32_MAX) {
        return ZF_CTAP_ERR_OTHER;
    }
    next_sign_count = record->sign_count + 1;
    *updated_record = *record;
    updated_record->sign_count = next_sign_count;

    return zf_ctap_build_assertion_response_with_scratch(
        response_scratch, request, record, user_present, uv_verified, next_sign_count,
        include_user_details, include_count, match_count, user_selected, out, out_capacity, out_len);
}

static bool zf_ctap_index_entry_matches_record(const ZfCredentialIndexEntry *entry,
                                               const ZfCredentialRecord *record) {
    return entry && record && entry->in_use && record->in_use &&
           entry->credential_id_len == record->credential_id_len &&
           memcmp(entry->credential_id, record->credential_id, record->credential_id_len) == 0;
}

static bool zf_ctap_snapshot_index_entry_locked(ZerofidoApp *app, size_t record_index,
                                                ZfCredentialIndexEntry *entry) {
    if (!app->store.records || record_index >= app->store.count ||
        !app->store.records[record_index].in_use) {
        return false;
    }

    *entry = app->store.records[record_index];
    return true;
}

static bool zf_ctap_selected_record_still_current_locked(ZerofidoApp *app, size_t record_index,
                                                        const ZfCredentialRecord *record) {
    if (!app->store.records || record_index >= app->store.count) {
        return false;
    }

    return zf_ctap_index_entry_matches_record(&app->store.records[record_index], record);
}

static size_t zf_ctap_resolve_assertion_matches_snapshot(ZerofidoApp *app,
                                                        const ZfGetAssertionRequest *request,
                                                        bool uv_verified, uint16_t *matches) {
    size_t match_count = 0;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    match_count =
        zf_ctap_resolve_assertion_matches(app->storage, &app->store, request, uv_verified, matches);
    furi_mutex_release(app->ui_mutex);
    return match_count;
}

static bool zf_ctap_load_assertion_record(ZerofidoApp *app, size_t record_index, const char *rp_id,
                                          ZfCredentialRecord *record,
                                          ZfCredentialIndexEntry *out_entry, uint8_t *store_io,
                                          size_t store_io_size) {
    ZfCredentialIndexEntry entry = {0};
    bool snapshot_ok = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    snapshot_ok = zf_ctap_snapshot_index_entry_locked(app, record_index, &entry);
    furi_mutex_release(app->ui_mutex);

    if (!snapshot_ok ||
        !zf_store_load_record_with_buffer(app->storage, &entry, record, store_io, store_io_size) ||
        strcmp(record->rp_id, rp_id) != 0) {
        zf_crypto_secure_zero(record, sizeof(*record));
        return false;
    }
    if (!zf_ctap_index_entry_matches_record(&entry, record)) {
        return false;
    }
    if (out_entry) {
        *out_entry = entry;
    }
    return true;
}

uint8_t zf_ctap_handle_get_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
                                     const uint8_t *data, size_t data_len, uint8_t *out,
                                     size_t out_capacity, size_t *out_len) {
    typedef struct {
        ZfGetAssertionRequest request;
        uint16_t matches[ZF_MAX_CREDENTIALS];
        ZfClientPinState pin_state;
        ZfCredentialRecord updated_record;
        ZfCredentialRecord selected_record;
        ZfCredentialIndexEntry selected_entry;
        ZfAssertionResponseScratch response;
        uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
    } ZfGetAssertionScratch;

    _Static_assert(sizeof(ZfGetAssertionScratch) <= ZF_COMMAND_SCRATCH_SIZE,
                   "getAssertion scratch exceeds command arena");

    ZfGetAssertionScratch *scratch = zf_ctap_command_scratch(app, sizeof(*scratch));
    size_t match_count = 0;
    bool uv_verified = false;
    bool uses_allow_list = false;
    bool maintenance_acquired = false;
    uint32_t prepared_counter_high_water = 0;
    uint8_t status = ZF_CTAP_ERR_OTHER;
    ZfGetAssertionRequest *request = NULL;
    uint16_t *matches = NULL;
    ZfCredentialRecord *updated_record = NULL;
    ZfCredentialRecord *selected_record = NULL;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    request = &scratch->request;
    matches = scratch->matches;
    updated_record = &scratch->updated_record;
    selected_record = &scratch->selected_record;

    status = zf_ctap_parse_get_assertion(data, data_len, request);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_ctap_validate_pin_auth_protocol(request->has_pin_auth, request->has_pin_protocol,
                                                request->pin_protocol);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    if (request->has_pin_auth && request->pin_auth_len == 0) {
        status = zf_ctap_handle_empty_pin_auth_probe(app, session_id, "Authenticate",
                                                     request->rp_id, "Touch required");
        goto cleanup;
    }
    if (zf_ctap_effective_uv_requested(request->has_pin_auth, request->has_uv, request->uv)) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    uses_allow_list = zf_ctap_request_uses_allow_list(request);
    status = zf_ctap_require_pin_auth_with_state(
        app, &scratch->pin_state, request->has_uv && request->uv, request->has_pin_auth,
        request->client_data_hash, request->pin_auth, request->pin_auth_len,
        request->has_pin_protocol, request->pin_protocol, request->rp_id, ZF_PIN_PERMISSION_GA,
        &uv_verified);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    if (request->has_up && !request->up) {
        memset(updated_record, 0, sizeof(*updated_record));
        memset(selected_record, 0, sizeof(*selected_record));

        match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);
        if (match_count == 0) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        if (!uses_allow_list && match_count > 1) {
            uint32_t selected_record_index = 0;

            status = zf_ctap_request_assertion_selection(app, request->rp_id, matches, match_count,
                                                         session_id, &selected_record_index);
            if (status != ZF_CTAP_SUCCESS) {
                goto cleanup;
            }
            status = zf_transport_poll_cbor_control(app, session_id);
            if (status != ZF_CTAP_SUCCESS) {
                goto cleanup;
            }
            if (!zf_ctap_begin_maintenance(app)) {
                status = ZF_CTAP_ERR_NOT_ALLOWED;
                goto cleanup;
            }
            maintenance_acquired = true;

            if (!zf_ctap_load_assertion_record(app, selected_record_index, request->rp_id,
                                               selected_record, &scratch->selected_entry,
                                               scratch->store_io,
                                               sizeof(scratch->store_io))) {
                status = ZF_CTAP_ERR_NO_CREDENTIALS;
                goto cleanup;
            }
            status =
                zf_prepare_assertion_response(request, selected_record, true, uv_verified, false, 1,
                                              true,
                                              updated_record, &scratch->response, out, out_capacity,
                                              out_len);
            if (status != ZF_CTAP_SUCCESS) {
                goto cleanup;
            }

            status = zf_transport_poll_cbor_control(app, session_id);
            if (status != ZF_CTAP_SUCCESS) {
                goto cleanup;
            }
            if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry,
                                                  updated_record,
                                                  &prepared_counter_high_water)) {
                status = ZF_CTAP_ERR_OTHER;
                goto cleanup;
            }

            furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
            if (!zf_ctap_selected_record_still_current_locked(app, selected_record_index,
                                                              selected_record)) {
                furi_mutex_release(app->ui_mutex);
                status = ZF_CTAP_ERR_NO_CREDENTIALS;
                goto cleanup;
            }
            if (!zf_store_publish_counter_advance(&app->store, updated_record,
                                                  prepared_counter_high_water)) {
                furi_mutex_release(app->ui_mutex);
                status = ZF_CTAP_ERR_OTHER;
                goto cleanup;
            }
            zf_ctap_assertion_queue_clear(app);
            furi_mutex_release(app->ui_mutex);
            zerofido_notify_success(app);
            status = ZF_CTAP_SUCCESS;
            goto cleanup;
        }

        if (!zf_ctap_begin_maintenance(app)) {
            status = ZF_CTAP_ERR_NOT_ALLOWED;
            goto cleanup;
        }
        maintenance_acquired = true;
        match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);
        if (match_count == 0 || (!uses_allow_list && match_count > 1)) {
            status = match_count == 0 ? ZF_CTAP_ERR_NO_CREDENTIALS : ZF_CTAP_ERR_NOT_ALLOWED;
            goto cleanup;
        }
        if (!zf_ctap_load_assertion_record(app, matches[0], request->rp_id, selected_record,
                                           &scratch->selected_entry, scratch->store_io,
                                           sizeof(scratch->store_io))) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        status = zf_prepare_assertion_response(request, selected_record, false, uv_verified,
                                               false, 1U, false, updated_record, &scratch->response,
                                               out, out_capacity, out_len);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry,
                                              updated_record, &prepared_counter_high_water)) {
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!zf_ctap_selected_record_still_current_locked(app, matches[0], selected_record)) {
            furi_mutex_release(app->ui_mutex);
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        if (!zf_store_publish_counter_advance(&app->store, updated_record,
                                              prepared_counter_high_water)) {
            furi_mutex_release(app->ui_mutex);
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        zerofido_notify_success(app);
        status = ZF_CTAP_SUCCESS;
        goto cleanup;
    }

    match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);

    if (!uses_allow_list && match_count > 1) {
        uint32_t selected_record_index = 0;
        memset(updated_record, 0, sizeof(*updated_record));
        memset(selected_record, 0, sizeof(*selected_record));

        status = zf_ctap_request_assertion_selection(app, request->rp_id, matches, match_count,
                                                     session_id, &selected_record_index);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        status = zf_transport_poll_cbor_control(app, session_id);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        if (!zf_ctap_begin_maintenance(app)) {
            status = ZF_CTAP_ERR_NOT_ALLOWED;
            goto cleanup;
        }
        maintenance_acquired = true;

        if (!zf_ctap_load_assertion_record(app, selected_record_index, request->rp_id,
                                           selected_record, &scratch->selected_entry,
                                           scratch->store_io,
                                           sizeof(scratch->store_io))) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        status = zf_prepare_assertion_response(request, selected_record, true, uv_verified, false,
                                               1, true, updated_record, &scratch->response, out,
                                               out_capacity, out_len);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }

        status = zf_transport_poll_cbor_control(app, session_id);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry,
                                              updated_record, &prepared_counter_high_water)) {
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!zf_ctap_selected_record_still_current_locked(app, selected_record_index,
                                                          selected_record)) {
            furi_mutex_release(app->ui_mutex);
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        if (!zf_store_publish_counter_advance(&app->store, updated_record,
                                              prepared_counter_high_water)) {
            furi_mutex_release(app->ui_mutex);
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        zerofido_notify_success(app);
        status = ZF_CTAP_SUCCESS;
        goto cleanup;
    }

    status =
        zf_ctap_request_approval(app, "Authenticate", request->rp_id, "Touch required", session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    if (!zf_ctap_begin_maintenance(app)) {
        status = ZF_CTAP_ERR_NOT_ALLOWED;
        goto cleanup;
    }
    maintenance_acquired = true;

    match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);
    if (match_count == 0) {
        status = ZF_CTAP_ERR_NO_CREDENTIALS;
        goto cleanup;
    }

    memset(updated_record, 0, sizeof(*updated_record));
    memset(selected_record, 0, sizeof(*selected_record));
    if (!zf_ctap_load_assertion_record(app, matches[0], request->rp_id, selected_record,
                                       &scratch->selected_entry, scratch->store_io,
                                       sizeof(scratch->store_io))) {
        status = ZF_CTAP_ERR_NO_CREDENTIALS;
        goto cleanup;
    }
    status = zf_prepare_assertion_response(request, selected_record, true, uv_verified,
                                           false, 1U, false, updated_record, &scratch->response, out,
                                           out_capacity, out_len);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry, updated_record,
                                          &prepared_counter_high_water)) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!zf_ctap_selected_record_still_current_locked(app, matches[0], selected_record)) {
        furi_mutex_release(app->ui_mutex);
        status = ZF_CTAP_ERR_NO_CREDENTIALS;
        goto cleanup;
    }
    if (!zf_store_publish_counter_advance(&app->store, updated_record,
                                          prepared_counter_high_water)) {
        furi_mutex_release(app->ui_mutex);
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    zerofido_notify_success(app);
    status = ZF_CTAP_SUCCESS;

cleanup:
    if (maintenance_acquired) {
        zf_ctap_end_maintenance(app);
    }
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    zf_app_command_scratch_release(app);
    return status;
}
