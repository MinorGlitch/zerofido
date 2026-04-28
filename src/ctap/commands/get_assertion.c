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

#include "get_assertion.h"

#include <string.h>

#include "../core/approval.h"
#include "../core/assertion_queue.h"
#include "../core/internal.h"
#include "../extensions/hmac_secret.h"
#include "../parse.h"
#include "../policy.h"
#include "../response.h"
#include "../../pin/protocol.h"
#include "../../transport/adapter.h"
#include "../../zerofido_app_i.h"
#include "../../zerofido_crypto.h"
#include "../../zerofido_notify.h"
#include "../../zerofido_store.h"

/*
 * Prepares a signed assertion response and computes the next sign counter, but
 * does not publish the counter. Callers must still reserve/publish the counter
 * only after confirming the selected record is current under the store lock.
 */
static uint8_t zf_prepare_assertion_response(const ZfAssertionRequestData *request,
                                             const ZfClientPinState *pin_state,
                                             const ZfCredentialRecord *record, bool user_present,
                                             bool uv_verified, bool include_user_details,
                                             bool include_count, size_t match_count,
                                             bool user_selected, bool include_user_selected,
                                             uint32_t *out_next_sign_count,
                                             ZfAssertionResponseScratch *response_scratch,
                                             uint8_t *out, size_t out_capacity, size_t *out_len) {
    uint32_t next_sign_count = 0;
    size_t extension_data_len = 0;
    uint8_t status = ZF_CTAP_SUCCESS;

    if (!record || !out_next_sign_count || record->sign_count == UINT32_MAX) {
        return ZF_CTAP_ERR_OTHER;
    }
    next_sign_count = record->sign_count + 1;

    status = zf_ctap_hmac_secret_build_extension(
        pin_state, request, record, uv_verified, &response_scratch->hmac_secret,
        response_scratch->extension_data, sizeof(response_scratch->extension_data),
        &extension_data_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status = zf_ctap_build_assertion_response_with_scratch(
        response_scratch, request, record, user_present, uv_verified, next_sign_count,
        include_user_details, include_count, match_count, include_user_selected, user_selected,
        response_scratch->extension_data, extension_data_len, out, out_capacity, out_len);
    if (status == ZF_CTAP_SUCCESS) {
        *out_next_sign_count = next_sign_count;
    }
    return status;
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

/*
 * Assertion handling has three security-relevant paths:
 * - up=false: no touch, no UP flag, first matching credential only.
 * - multiple discoverable credentials without allowList: UI selection chooses one.
 * - normal flow: touch approval, first match returned, optional continuation queue.
 *
 * Credential records are loaded from a snapshot and revalidated before counter
 * publication so deleted/replaced records cannot be signed or advanced stale.
 */
uint8_t zf_ctap_handle_get_assertion(ZerofidoApp *app, ZfTransportSessionId session_id,
                                     const uint8_t *data, size_t data_len, uint8_t *out,
                                     size_t out_capacity, size_t *out_len) {
    typedef struct {
        ZfGetAssertionRequest request;
        uint16_t matches[ZF_MAX_CREDENTIALS];
        ZfClientPinState pin_state;
        ZfCredentialRecord selected_record;
        ZfCredentialIndexEntry selected_entry;
        union {
            ZfCredentialDescriptor descriptors[ZF_MAX_ALLOW_LIST];
            ZfAssertionResponseScratch response;
            uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
        } work;
    } ZfGetAssertionScratch;

    _Static_assert(sizeof(ZfGetAssertionScratch) <= ZF_COMMAND_SCRATCH_SIZE,
                   "getAssertion scratch exceeds command arena");

    ZfGetAssertionScratch *scratch = zf_ctap_command_scratch(app, sizeof(*scratch));
    size_t match_count = 0;
    bool uv_verified = false;
    bool uses_allow_list = false;
    bool maintenance_acquired = false;
    uint32_t prepared_counter_high_water = 0;
    uint32_t next_sign_count = 0;
    uint8_t status = ZF_CTAP_ERR_OTHER;
    ZfGetAssertionRequest *request = NULL;
    uint16_t *matches = NULL;
    ZfCredentialRecord *selected_record = NULL;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    request = &scratch->request;
    matches = scratch->matches;
    selected_record = &scratch->selected_record;
    request->allow_list.entries = scratch->work.descriptors;
    request->allow_list.capacity =
        sizeof(scratch->work.descriptors) / sizeof(scratch->work.descriptors[0]);

    status = zf_ctap_parse_get_assertion(data, data_len, request);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_ctap_validate_pin_auth_protocol(request->has_pin_auth, request->has_pin_protocol,
                                                request->pin_protocol,
                                                app->capabilities.pin_uv_auth_protocol_2_enabled);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    if (request->assertion.has_hmac_secret &&
        (!zf_pin_protocol_supported(request->assertion.hmac_secret_pin_protocol) ||
         (request->assertion.hmac_secret_pin_protocol == ZF_PIN_PROTOCOL_V2 &&
          !app->capabilities.pin_uv_auth_protocol_2_enabled))) {
        status = ZF_CTAP_ERR_INVALID_PARAMETER;
        goto cleanup;
    }
    if (request->assertion.has_hmac_secret && request->has_up && !request->up) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    if (request->has_pin_auth && request->pin_auth_len == 0) {
        status = zf_ctap_handle_empty_pin_auth_probe(app, session_id, "Authenticate",
                                                     request->assertion.rp_id, "Touch required");
        goto cleanup;
    }
    if (zf_ctap_effective_uv_requested(request->has_pin_auth, request->has_uv, request->uv)) {
        status = ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        goto cleanup;
    }
    uses_allow_list = zf_ctap_request_uses_allow_list(request);
    status = zf_ctap_require_pin_auth_with_state(
        app, &scratch->pin_state, request->has_uv && request->uv, request->has_pin_auth,
        request->assertion.client_data_hash, request->pin_auth, request->pin_auth_len,
        request->has_pin_protocol, request->pin_protocol, request->assertion.rp_id,
        ZF_PIN_PERMISSION_GA, &uv_verified);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    if (request->has_up && !request->up) {
        memset(selected_record, 0, sizeof(*selected_record));
        next_sign_count = 0;

        match_count = zf_ctap_resolve_assertion_matches_snapshot(app, request, uv_verified, matches);
        if (match_count == 0) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
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
        if (!zf_ctap_load_assertion_record(app, matches[0], request->assertion.rp_id,
                                           selected_record,
                                           &scratch->selected_entry, scratch->work.store_io,
                                           sizeof(scratch->work.store_io))) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        status = zf_prepare_assertion_response(
            &request->assertion, &scratch->pin_state, selected_record, false, uv_verified,
            uv_verified && !uses_allow_list, false, 1U, false, false,
            &next_sign_count, &scratch->work.response, out, out_capacity, out_len);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        selected_record->sign_count = next_sign_count;
        if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry,
                                              selected_record, &prepared_counter_high_water)) {
            status = ZF_CTAP_ERR_OTHER;
            goto cleanup;
        }
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!zf_ctap_selected_record_still_current_locked(app, matches[0], selected_record)) {
            furi_mutex_release(app->ui_mutex);
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        if (!zf_store_publish_counter_advance(&app->store, selected_record,
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
        memset(selected_record, 0, sizeof(*selected_record));
        next_sign_count = 0;

        status = zf_ctap_request_assertion_selection(app, request->assertion.rp_id, matches,
                                                     match_count, session_id,
                                                     &selected_record_index);
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

        if (!zf_ctap_load_assertion_record(app, selected_record_index, request->assertion.rp_id,
                                           selected_record, &scratch->selected_entry,
                                           scratch->work.store_io,
                                           sizeof(scratch->work.store_io))) {
            status = ZF_CTAP_ERR_NO_CREDENTIALS;
            goto cleanup;
        }
        status = zf_prepare_assertion_response(&request->assertion, &scratch->pin_state,
                                               selected_record, true, uv_verified, uv_verified,
                                               false, 1, true,
                                               app->capabilities.advertise_fido_2_1,
                                               &next_sign_count, &scratch->work.response, out,
                                               out_capacity, out_len);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        selected_record->sign_count = next_sign_count;

        status = zf_transport_poll_cbor_control(app, session_id);
        if (status != ZF_CTAP_SUCCESS) {
            goto cleanup;
        }
        if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry,
                                              selected_record, &prepared_counter_high_water)) {
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
        if (!zf_store_publish_counter_advance(&app->store, selected_record,
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
        zf_ctap_request_approval(app, "Authenticate", request->assertion.rp_id, "Touch required",
                                 session_id);
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

    memset(selected_record, 0, sizeof(*selected_record));
    next_sign_count = 0;
    if (!zf_ctap_load_assertion_record(app, matches[0], request->assertion.rp_id, selected_record,
                                       &scratch->selected_entry, scratch->work.store_io,
                                       sizeof(scratch->work.store_io))) {
        status = ZF_CTAP_ERR_NO_CREDENTIALS;
        goto cleanup;
    }
    status = zf_prepare_assertion_response(&request->assertion, &scratch->pin_state,
                                           selected_record, true, uv_verified,
                                           uv_verified && !uses_allow_list, false, 1U, false, false,
                                           &next_sign_count, &scratch->work.response, out, out_capacity,
                                           out_len);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }

    status = zf_transport_poll_cbor_control(app, session_id);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    selected_record->sign_count = next_sign_count;
    if (!zf_store_prepare_counter_advance(app->storage, &scratch->selected_entry, selected_record,
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
    if (!zf_store_publish_counter_advance(&app->store, selected_record,
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
