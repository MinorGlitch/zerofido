#include "make_credential.h"

#include <stdio.h>
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

uint8_t zf_ctap_handle_make_credential(ZerofidoApp *app, ZfTransportSessionId session_id,
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
    if (!scratch->request.has_pin_auth && zf_ctap_pin_is_set(app)) {
        status = ZF_CTAP_ERR_PIN_REQUIRED;
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
    bool excluded = zf_ctap_exclude_list_has_visible_match(
        app->storage, &app->store, scratch->request.rp_id, &scratch->request.exclude_list,
        uv_verified, scratch->store_io, sizeof(scratch->store_io));
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
    zf_app_command_scratch_release(app);
    return status;
}
