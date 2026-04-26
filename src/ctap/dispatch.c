#include "dispatch.h"

#include <string.h>

#include "approval.h"
#include "assertion_queue.h"
#include "parse.h"
#include "policy.h"
#include "response.h"
#include "../transport/adapter.h"
#include "../u2f/adapter.h"
#include "../u2f/persistence.h"
#include "../zerofido_app_i.h"
#include "../zerofido_crypto.h"
#include "../zerofido_notify.h"
#include "../zerofido_pin.h"
#include "../zerofido_store.h"

static void *zf_ctap_command_scratch(ZerofidoApp *app, size_t size) {
    if (!app || size > sizeof(app->command_scratch.bytes)) {
        return NULL;
    }

    memset(app->command_scratch.bytes, 0, size);
    return app->command_scratch.bytes;
}

static bool zf_ctap_begin_maintenance(ZerofidoApp *app) {
    bool acquired = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->maintenance_busy) {
        app->maintenance_busy = true;
        acquired = true;
    }
    furi_mutex_release(app->ui_mutex);
    return acquired;
}

static void zf_ctap_end_maintenance(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->maintenance_busy = false;
    furi_mutex_release(app->ui_mutex);
}

static uint8_t zf_ctap_require_pin_auth_with_state(
    ZerofidoApp *app, ZfClientPinState *pin_state, bool uv_requested, bool has_pin_auth,
    const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN], const uint8_t *pin_auth,
    size_t pin_auth_len, bool has_pin_protocol, uint64_t pin_protocol, const char *rp_id,
    uint64_t required_permissions, bool *uv_verified) {
    uint8_t status = ZF_CTAP_ERR_OTHER;

    if (!pin_state) {
        return ZF_CTAP_ERR_OTHER;
    }
    if (!zf_ctap_begin_maintenance(app)) {
        return ZF_CTAP_ERR_NOT_ALLOWED;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    *pin_state = app->pin_state;
    furi_mutex_release(app->ui_mutex);

    status = zerofido_pin_require_auth(app->storage, pin_state, uv_requested, has_pin_auth,
                                       client_data_hash, pin_auth, pin_auth_len, has_pin_protocol,
                                       pin_protocol, rp_id, required_permissions, uv_verified);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->pin_state = *pin_state;
    furi_mutex_release(app->ui_mutex);
    zf_ctap_end_maintenance(app);
    return status;
}

static uint8_t zf_handle_selection(ZerofidoApp *app, ZfTransportSessionId session_id,
                                   size_t request_len, size_t *out_len) {
    uint8_t status = zf_ctap_require_empty_payload(request_len);

    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status = zf_ctap_request_approval(app, "Select", "", "Touch required", session_id);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    *out_len = 0;
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_ctap_dispatch_require_idle(ZerofidoApp *app) {
    return zf_ctap_local_maintenance_busy(app) ? ZF_CTAP_ERR_NOT_ALLOWED : ZF_CTAP_SUCCESS;
}

static uint8_t zf_handle_reset(ZerofidoApp *app, ZfTransportSessionId session_id,
                               size_t request_len, size_t *out_len) {
    uint8_t status = zf_ctap_require_empty_payload(request_len);
    bool maintenance_acquired = false;

    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status =
        zf_ctap_request_approval(app, "Reset", "ZeroFIDO", "Erase credentials and PIN", session_id);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    if (!zf_ctap_begin_maintenance(app)) {
        return ZF_CTAP_ERR_NOT_ALLOWED;
    }
    maintenance_acquired = true;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);

    bool wiped = zf_store_wipe_app_data(app->storage) && u2f_data_wipe(app->storage);
    ZfClientPinState next_pin_state = {0};
    ZfPinInitResult pin_init = wiped
                                   ? zerofido_pin_init_with_result(app->storage, &next_pin_state)
                                   : ZfPinInitStorageError;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (wiped) {
        zf_store_clear(&app->store);
        if (pin_init == ZfPinInitOk) {
            app->pin_state = next_pin_state;
        } else {
            zf_crypto_secure_zero(&app->pin_state, sizeof(app->pin_state));
        }
    }
    furi_mutex_release(app->ui_mutex);
    zf_crypto_secure_zero(&next_pin_state, sizeof(next_pin_state));

    if (!wiped || pin_init != ZfPinInitOk) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    zf_u2f_adapter_deinit(app);
    if (app->capabilities.u2f_enabled && !zf_u2f_adapter_init(app)) {
        status = ZF_CTAP_ERR_OTHER;
        goto cleanup;
    }

    zerofido_notify_reset(app);
    *out_len = 0;
    status = ZF_CTAP_SUCCESS;

cleanup:
    if (maintenance_acquired) {
        zf_ctap_end_maintenance(app);
    }
    return status;
}

static uint8_t zf_handle_make_credential(ZerofidoApp *app, ZfTransportSessionId session_id,
                                         const uint8_t *data, size_t data_len, uint8_t *out,
                                         size_t out_capacity, size_t *out_len) {
    typedef struct {
        ZfMakeCredentialRequest request;
        ZfCredentialRecord record;
        ZfClientPinState pin_state;
        ZfMakeCredentialResponseScratch response;
        uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
        uint16_t deleted_indices[ZF_MAX_CREDENTIALS];
        char user_line[96];
    } ZfMakeCredentialScratch;

    _Static_assert(sizeof(ZfMakeCredentialScratch) <= ZF_COMMAND_SCRATCH_SIZE,
                   "makeCredential scratch exceeds command arena");

    ZfMakeCredentialScratch *scratch = zf_ctap_command_scratch(app, sizeof(*scratch));
    bool uv_verified = false;
    bool resident_key = false;
    bool maintenance_acquired = false;
    size_t deleted_count = 0;
    uint8_t status = ZF_CTAP_ERR_OTHER;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }

    status = zf_ctap_parse_make_credential(data, data_len, &scratch->request);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_ctap_validate_pin_auth_protocol(scratch->request.has_pin_auth,
                                                scratch->request.has_pin_protocol,
                                                scratch->request.pin_protocol);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    snprintf(scratch->user_line, sizeof(scratch->user_line), "User: %s",
             scratch->request.user_name[0] ? scratch->request.user_name : "(not provided)");
    if (scratch->request.has_pin_auth && scratch->request.pin_auth_len == 0) {
        status = zf_ctap_handle_empty_pin_auth_probe(app, session_id, "Register",
                                                     scratch->request.rp_id, scratch->user_line);
        goto cleanup;
    }
    if (zf_ctap_effective_uv_requested(scratch->request.has_pin_auth, scratch->request.has_uv,
                                       scratch->request.uv)) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    resident_key = scratch->request.has_rk && scratch->request.rk;
    status = zf_ctap_require_pin_auth_with_state(
        app, &scratch->pin_state, scratch->request.has_uv && scratch->request.uv,
        scratch->request.has_pin_auth, scratch->request.client_data_hash, scratch->request.pin_auth,
        scratch->request.pin_auth_len, scratch->request.has_pin_protocol,
        scratch->request.pin_protocol, scratch->request.rp_id, ZF_PIN_PERMISSION_MC, &uv_verified);
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
    bool excluded = zf_store_has_matching_credential_with_buffer(
        app->storage, &app->store, scratch->request.rp_id,
        zf_ctap_store_entry_matches_descriptor_list, &scratch->request.exclude_list,
        scratch->store_io, sizeof(scratch->store_io));
    zf_ctap_end_maintenance(app);
    if (excluded) {
        status = zf_ctap_request_approval(app, "Register", scratch->request.rp_id,
                                          scratch->user_line, session_id);
        status = status == ZF_CTAP_ERR_KEEPALIVE_CANCEL ? status : ZF_CTAP_ERR_CREDENTIAL_EXCLUDED;
        goto cleanup;
    }
    if (!zf_store_prepare_credential(&scratch->record, scratch->request.rp_id,
                                     scratch->request.user_id, scratch->request.user_id_len,
                                     scratch->request.user_name, scratch->request.user_display_name,
                                     resident_key)) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (scratch->request.has_cred_protect) {
        scratch->record.cred_protect = scratch->request.cred_protect;
    }

    status = zf_ctap_request_approval(app, "Register", scratch->request.rp_id, scratch->user_line,
                                      session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    if (!zf_crypto_generate_credential_keypair(&scratch->record)) {
        status = ZF_CTAP_ERR_KEY_STORE_FULL;
        goto cleanup;
    }
    status = zf_ctap_build_make_credential_response_with_scratch(
        &scratch->response, scratch->request.rp_id, &scratch->record,
        scratch->request.client_data_hash, uv_verified, scratch->request.has_cred_protect, out,
        out_capacity, out_len);
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

    if (resident_key) {
        if (!zf_store_find_resident_credential_indices_for_user_with_buffer(
            app->storage, &app->store, scratch->request.rp_id, scratch->request.user_id,
            scratch->request.user_id_len, scratch->deleted_indices,
            sizeof(scratch->deleted_indices) / sizeof(scratch->deleted_indices[0]), &deleted_count,
            scratch->store_io, sizeof(scratch->store_io))) {
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    size_t effective_count =
        app->store.count >= deleted_count ? app->store.count - deleted_count : app->store.count;
    bool has_capacity = app->store.records && effective_count < ZF_MAX_CREDENTIALS;
    furi_mutex_release(app->ui_mutex);
    if (!has_capacity) {
        status = ZF_CTAP_ERR_KEY_STORE_FULL;
        goto cleanup;
    }

    bool wrote = zf_store_write_record_file_with_buffer(app->storage, &scratch->record,
                                                        scratch->store_io,
                                                        sizeof(scratch->store_io));
    if (!wrote) {
        status = ZF_CTAP_ERR_KEY_STORE_FULL;
        goto cleanup;
    }

    if (resident_key && deleted_count > 0) {
        size_t removed_count = 0;

        if (!zf_store_remove_credential_files_by_indices(app->storage, &app->store,
                                                         scratch->deleted_indices, deleted_count,
                                                         &removed_count)) {
            if (removed_count > 0) {
                furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                zf_store_publish_deleted_indices(&app->store, scratch->deleted_indices,
                                                 removed_count);
                zf_ctap_assertion_queue_clear(app);
                furi_mutex_release(app->ui_mutex);
            }
            (void)zf_store_remove_record_file(app->storage, &scratch->record);
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
        deleted_count = removed_count;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (deleted_count > 0) {
        zf_store_publish_deleted_indices(&app->store, scratch->deleted_indices, deleted_count);
    }
    bool added = zf_store_publish_added_record(&app->store, &scratch->record);
    if (added) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    if (!added) {
        (void)zf_store_remove_record_file(app->storage, &scratch->record);
        status = ZF_CTAP_ERR_KEY_STORE_FULL;
        goto cleanup;
    }
    zerofido_notify_success(app);
    status = ZF_CTAP_SUCCESS;

cleanup:
    if (maintenance_acquired) {
        zf_ctap_end_maintenance(app);
    }
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return status;
}

static uint8_t zf_prepare_assertion_response(const ZfGetAssertionRequest *request,
                                             const ZfCredentialRecord *record, bool user_present,
                                             bool uv_verified, bool include_count,
                                             size_t match_count, ZfCredentialRecord *updated_record,
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
        include_user_details, include_count, match_count, out, out_capacity, out_len);
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

static uint8_t zf_handle_get_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
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
        bool include_count = false;
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
        include_count = uses_allow_list && match_count > 1U;
        if (!zf_ctap_load_assertion_record(app, matches[0], request->rp_id, selected_record,
                                           &scratch->selected_entry, scratch->store_io,
                                           sizeof(scratch->store_io))) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        status = zf_prepare_assertion_response(request, selected_record, false, uv_verified,
                                               include_count, include_count ? match_count : 1U,
                                               updated_record, &scratch->response, out,
                                               out_capacity, out_len);
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
        if (include_count) {
            zf_ctap_assertion_queue_seed(app, session_id, request, uv_verified, matches,
                                         match_count);
        } else {
            zf_ctap_assertion_queue_clear(app);
        }
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
                                               1, updated_record, &scratch->response, out,
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
    bool include_count = uses_allow_list && match_count > 1U;
    status = zf_prepare_assertion_response(request, selected_record, true, uv_verified,
                                           include_count, include_count ? match_count : 1U,
                                           updated_record, &scratch->response, out, out_capacity,
                                           out_len);
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
    if (include_count) {
        zf_ctap_assertion_queue_seed(app, session_id, request, uv_verified, matches, match_count);
    } else {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    zerofido_notify_success(app);
    status = ZF_CTAP_SUCCESS;

cleanup:
    if (maintenance_acquired) {
        zf_ctap_end_maintenance(app);
    }
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return status;
}

uint8_t zf_ctap_dispatch_command(ZerofidoApp *app, const ZfResolvedCapabilities *capabilities,
                                 ZfTransportSessionId session_id, uint8_t cmd,
                                 const uint8_t *request_body, size_t request_body_len,
                                 uint8_t *response_body, size_t response_body_capacity,
                                 size_t *response_body_len) {
    uint8_t status = ZF_CTAP_ERR_INVALID_COMMAND;

    switch (cmd) {
    case ZfCtapeCmdGetInfo: {
        status = zf_ctap_require_empty_payload(request_body_len + 1U);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status =
            zf_ctap_build_get_info_response(capabilities, zf_ctap_pin_is_set(app), response_body,
                                            response_body_capacity, response_body_len);
        break;
    }
    case ZfCtapeCmdClientPin:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        if (!zf_ctap_begin_maintenance(app)) {
            status = ZF_CTAP_ERR_NOT_ALLOWED;
            break;
        }
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        status = zerofido_pin_handle_command(app, request_body, request_body_len, response_body,
                                             response_body_capacity, response_body_len);
        zf_ctap_end_maintenance(app);
        break;
    case ZfCtapeCmdReset:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_reset(app, session_id, request_body_len + 1U, response_body_len);
        break;
    case ZfCtapeCmdMakeCredential:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status =
            zf_handle_make_credential(app, session_id, request_body, request_body_len,
                                      response_body, response_body_capacity, response_body_len);
        break;
    case ZfCtapeCmdGetAssertion:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_get_assertion(app, session_id, request_body, request_body_len,
                                         response_body, response_body_capacity, response_body_len);
        break;
    case ZfCtapeCmdGetNextAssertion:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_ctap_require_empty_payload(request_body_len + 1U);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_ctap_assertion_queue_handle_next(app, session_id, response_body,
                                                     response_body_capacity, response_body_len);
        break;
    case ZfCtapeCmdSelection:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_selection(app, session_id, request_body_len + 1U, response_body_len);
        break;
    default:
        *response_body_len = 0;
        break;
    }

    return status;
}
