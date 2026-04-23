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

static uint8_t zf_handle_selection(ZerofidoApp *app, uint32_t cid, size_t request_len,
                                   size_t *out_len) {
    uint8_t status = zf_ctap_require_empty_payload(request_len);

    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status = zf_ctap_request_approval(app, "Select", "", "Touch required", cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    *out_len = 0;
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_ctap_dispatch_require_idle(ZerofidoApp *app) {
    return zf_ctap_local_maintenance_busy(app) ? ZF_CTAP_ERR_NOT_ALLOWED : ZF_CTAP_SUCCESS;
}

static uint8_t zf_handle_reset(ZerofidoApp *app, uint32_t cid, size_t request_len,
                               size_t *out_len) {
    uint8_t status = zf_ctap_require_empty_payload(request_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    status = zf_ctap_request_approval(app, "Reset", "ZeroFIDO", "Erase credentials and PIN", cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->maintenance_busy = true;
    bool wiped = zf_store_wipe_app_data(app->storage) && u2f_data_wipe(app->storage);
    bool store_ok = wiped && zf_store_init(app->storage, &app->store);
    ZfPinInitResult pin_init = store_ok
                                   ? zerofido_pin_init_with_result(app->storage, &app->pin_state)
                                   : ZfPinInitStorageError;
    zf_ctap_assertion_queue_clear(app);
    app->maintenance_busy = false;
    furi_mutex_release(app->ui_mutex);

    if (!wiped || !store_ok || pin_init != ZfPinInitOk) {
        return ZF_CTAP_ERR_OTHER;
    }

    zf_u2f_adapter_deinit(app);
    if (app->capabilities.u2f_enabled && !zf_u2f_adapter_init(app)) {
        return ZF_CTAP_ERR_OTHER;
    }

    zerofido_notify_reset(app);
    *out_len = 0;
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_handle_make_credential(ZerofidoApp *app, uint32_t cid, const uint8_t *data,
                                         size_t data_len, uint8_t *out, size_t out_capacity,
                                         size_t *out_len) {
    ZfMakeCredentialRequest request;
    ZfCredentialRecord record;
    bool uv_verified = false;
    bool resident_key = false;
    uint8_t status = zf_ctap_parse_make_credential(data, data_len, &request);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_ctap_validate_pin_auth_protocol(request.has_pin_auth, request.has_pin_protocol,
                                                request.pin_protocol);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    char user_line[96];
    snprintf(user_line, sizeof(user_line), "User: %s",
             request.user_name[0] ? request.user_name : "(not provided)");
    if (request.has_pin_auth && request.pin_auth_len == 0) {
        return zf_ctap_handle_empty_pin_auth_probe(app, cid, "Register", request.rp_id, user_line);
    }
    if (zf_ctap_effective_uv_requested(request.has_pin_auth, request.has_uv, request.uv)) {
        return ZF_CTAP_ERR_UNSUPPORTED_OPTION;
    }
    resident_key = request.has_rk && request.rk;
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    status = zerofido_pin_require_auth(
        app->storage, &app->pin_state, request.has_uv && request.uv, request.has_pin_auth,
        request.client_data_hash, request.pin_auth, request.pin_auth_len, request.has_pin_protocol,
        request.pin_protocol, request.rp_id, ZF_PIN_PERMISSION_MC, &uv_verified);
    furi_mutex_release(app->ui_mutex);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    bool excluded =
        zf_store_has_excluded_credential(&app->store, request.rp_id, request.exclude_ids,
                                         request.exclude_lens, request.exclude_count);
    furi_mutex_release(app->ui_mutex);
    if (excluded) {
        status = zf_ctap_request_approval(app, "Register", request.rp_id, user_line, cid);
        return status == ZF_CTAP_ERR_KEEPALIVE_CANCEL ? status : ZF_CTAP_ERR_CREDENTIAL_EXCLUDED;
    }
    if (!zf_store_prepare_credential(&record, request.rp_id, request.user_id, request.user_id_len,
                                     request.user_name, request.user_display_name, resident_key)) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    if (request.has_cred_protect) {
        record.cred_protect = request.cred_protect;
    }

    status = zf_ctap_request_approval(app, "Register", request.rp_id, user_line, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    if (!zf_crypto_generate_credential_keypair(&record)) {
        return ZF_CTAP_ERR_KEY_STORE_FULL;
    }
    status = zf_ctap_build_make_credential_response(
        request.rp_id, &record, request.client_data_hash, uv_verified, request.has_cred_protect,
        out, out_capacity, out_len);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    bool replaced = true;
    if (resident_key) {
        replaced = zf_store_delete_resident_credentials_for_user(
            app->storage, &app->store, request.rp_id, request.user_id, request.user_id_len, NULL);
    }
    bool added = replaced && zf_store_add_record(app->storage, &app->store, &record);
    if (added) {
        zf_ctap_assertion_queue_clear(app);
    }
    furi_mutex_release(app->ui_mutex);
    if (!replaced) {
        return ZF_CTAP_ERR_OTHER;
    }
    if (!added) {
        return ZF_CTAP_ERR_KEY_STORE_FULL;
    }
    zerofido_notify_success(app);
    return ZF_CTAP_SUCCESS;
}

static uint8_t zf_prepare_assertion_response(const ZfGetAssertionRequest *request,
                                             const ZfCredentialRecord *record, bool user_present,
                                             bool uv_verified, bool include_count,
                                             size_t match_count, ZfCredentialRecord *updated_record,
                                             uint8_t *out, size_t out_capacity, size_t *out_len) {
    bool include_user_details = uv_verified && !zf_ctap_request_uses_allow_list(request);
    uint32_t next_sign_count = 0;

    if (!record || !updated_record || record->sign_count == UINT32_MAX) {
        return ZF_CTAP_ERR_OTHER;
    }
    next_sign_count = record->sign_count + 1;
    *updated_record = *record;
    updated_record->sign_count = next_sign_count;

    return zf_ctap_build_assertion_response(request, record, user_present, uv_verified,
                                            next_sign_count, include_user_details, include_count,
                                            match_count, out, out_capacity, out_len);
}

static bool zf_ctap_load_assertion_record(ZerofidoApp *app, size_t record_index,
                                          ZfCredentialRecord *record) {
    return zf_store_load_record_by_index(app->storage, &app->store, record_index, record);
}

static uint8_t zf_handle_get_assertion(ZerofidoApp *app, uint32_t cid, const uint8_t *data,
                                       size_t data_len, uint8_t *out, size_t out_capacity,
                                       size_t *out_len) {
    ZfGetAssertionRequest request;
    uint16_t matches[ZF_MAX_CREDENTIALS];
    size_t match_count = 0;
    bool uv_verified = false;
    bool uses_allow_list = false;
    uint8_t status = zf_ctap_parse_get_assertion(data, data_len, &request);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_ctap_validate_pin_auth_protocol(request.has_pin_auth, request.has_pin_protocol,
                                                request.pin_protocol);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    if (request.has_pin_auth && request.pin_auth_len == 0) {
        return zf_ctap_handle_empty_pin_auth_probe(app, cid, "Authenticate", request.rp_id,
                                                   "Touch required");
    }
    if (zf_ctap_effective_uv_requested(request.has_pin_auth, request.has_uv, request.uv)) {
        return ZF_CTAP_ERR_UNSUPPORTED_OPTION;
    }
    uses_allow_list = zf_ctap_request_uses_allow_list(&request);
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    status = zerofido_pin_require_auth(
        app->storage, &app->pin_state, request.has_uv && request.uv, request.has_pin_auth,
        request.client_data_hash, request.pin_auth, request.pin_auth_len, request.has_pin_protocol,
        request.pin_protocol, request.rp_id, ZF_PIN_PERMISSION_GA, &uv_verified);
    furi_mutex_release(app->ui_mutex);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    if (request.has_up && !request.up) {
        ZfCredentialRecord updated_record = {0};
        ZfCredentialRecord selected_record = {0};
        bool include_count = false;

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        match_count =
            zf_ctap_resolve_assertion_matches(&app->store, &request, uv_verified, matches);
        if (match_count == 0) {
            furi_mutex_release(app->ui_mutex);
            return ZF_CTAP_ERR_NO_CREDENTIALS;
        }
        if (!uses_allow_list && match_count > 1) {
            furi_mutex_release(app->ui_mutex);

            uint32_t selected_record_index = 0;

            status = zf_ctap_request_assertion_selection(app, request.rp_id, matches, match_count,
                                                         cid, &selected_record_index);
            if (status != ZF_CTAP_SUCCESS) {
                return status;
            }
            status = zf_transport_poll_cbor_control(app, cid);
            if (status != ZF_CTAP_SUCCESS) {
                return status;
            }

            furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
            if (!app->store.records || selected_record_index >= app->store.count ||
                !app->store.records[selected_record_index].in_use ||
                !zf_ctap_load_assertion_record(app, selected_record_index, &selected_record)) {
                furi_mutex_release(app->ui_mutex);
                return ZF_CTAP_ERR_NO_CREDENTIALS;
            }
            status = zf_prepare_assertion_response(&request, &selected_record, true, uv_verified,
                                                   false, 1, &updated_record, out, out_capacity,
                                                   out_len);
            furi_mutex_release(app->ui_mutex);
            if (status != ZF_CTAP_SUCCESS) {
                return status;
            }

            status = zf_transport_poll_cbor_control(app, cid);
            if (status != ZF_CTAP_SUCCESS) {
                return status;
            }

            furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
            if (!zf_store_update_record(app->storage, &app->store, &updated_record)) {
                furi_mutex_release(app->ui_mutex);
                return ZF_CTAP_ERR_OTHER;
            }
            zf_ctap_assertion_queue_clear(app);
            furi_mutex_release(app->ui_mutex);
            zerofido_notify_success(app);
            return ZF_CTAP_SUCCESS;
        }

        include_count = false;
        if (!zf_ctap_load_assertion_record(app, matches[0], &selected_record)) {
            furi_mutex_release(app->ui_mutex);
            return ZF_CTAP_ERR_NO_CREDENTIALS;
        }
        status = zf_prepare_assertion_response(&request, &selected_record, false, uv_verified,
                                               include_count, 1, &updated_record, out,
                                               out_capacity, out_len);
        if (status == ZF_CTAP_SUCCESS) {
            if (!zf_store_update_record(app->storage, &app->store, &updated_record)) {
                status = ZF_CTAP_ERR_OTHER;
            }
            zf_ctap_assertion_queue_clear(app);
        }
        furi_mutex_release(app->ui_mutex);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }
        zerofido_notify_success(app);
        return ZF_CTAP_SUCCESS;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    match_count = zf_ctap_resolve_assertion_matches(&app->store, &request, uv_verified, matches);
    furi_mutex_release(app->ui_mutex);

    if (!uses_allow_list && match_count > 1) {
        uint32_t selected_record_index = 0;
        ZfCredentialRecord updated_record = {0};
        ZfCredentialRecord selected_record = {0};

        status = zf_ctap_request_assertion_selection(app, request.rp_id, matches, match_count, cid,
                                                     &selected_record_index);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }
        status = zf_transport_poll_cbor_control(app, cid);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!app->store.records || selected_record_index >= app->store.count ||
            !app->store.records[selected_record_index].in_use ||
            !zf_ctap_load_assertion_record(app, selected_record_index, &selected_record)) {
            furi_mutex_release(app->ui_mutex);
            return ZF_CTAP_ERR_NO_CREDENTIALS;
        }
        status = zf_prepare_assertion_response(&request, &selected_record, true, uv_verified,
                                               false, 1, &updated_record, out, out_capacity,
                                               out_len);
        furi_mutex_release(app->ui_mutex);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }

        status = zf_transport_poll_cbor_control(app, cid);
        if (status != ZF_CTAP_SUCCESS) {
            return status;
        }

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!zf_store_update_record(app->storage, &app->store, &updated_record)) {
            furi_mutex_release(app->ui_mutex);
            return ZF_CTAP_ERR_OTHER;
        }
        zf_ctap_assertion_queue_clear(app);
        furi_mutex_release(app->ui_mutex);
        zerofido_notify_success(app);
        return ZF_CTAP_SUCCESS;
    }

    status = zf_ctap_request_approval(app, "Authenticate", request.rp_id, "Touch required", cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }
    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    match_count = zf_ctap_resolve_assertion_matches(&app->store, &request, uv_verified, matches);
    if (match_count == 0) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_NO_CREDENTIALS;
    }

    ZfCredentialRecord updated_record = {0};
    ZfCredentialRecord selected_record = {0};
    if (!zf_ctap_load_assertion_record(app, matches[0], &selected_record)) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_NO_CREDENTIALS;
    }
    status = zf_prepare_assertion_response(&request, &selected_record, true, uv_verified, false, 1,
                                           &updated_record, out, out_capacity, out_len);
    if (status != ZF_CTAP_SUCCESS) {
        furi_mutex_release(app->ui_mutex);
        return status;
    }
    furi_mutex_release(app->ui_mutex);

    status = zf_transport_poll_cbor_control(app, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!zf_store_update_record(app->storage, &app->store, &updated_record)) {
        furi_mutex_release(app->ui_mutex);
        return ZF_CTAP_ERR_OTHER;
    }
    zf_ctap_assertion_queue_clear(app);
    furi_mutex_release(app->ui_mutex);
    zerofido_notify_success(app);
    return ZF_CTAP_SUCCESS;
}

uint8_t zf_ctap_dispatch_command(ZerofidoApp *app, const ZfResolvedCapabilities *capabilities,
                                 uint32_t cid, uint8_t cmd, const uint8_t *request_body,
                                 size_t request_body_len, uint8_t *response_body,
                                 size_t response_body_capacity, size_t *response_body_len) {
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
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        status = zerofido_pin_handle_command(app, request_body, request_body_len, response_body,
                                             response_body_capacity, response_body_len);
        furi_mutex_release(app->ui_mutex);
        break;
    case ZfCtapeCmdReset:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_reset(app, cid, request_body_len + 1U, response_body_len);
        break;
    case ZfCtapeCmdMakeCredential:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_make_credential(app, cid, request_body, request_body_len, response_body,
                                           response_body_capacity, response_body_len);
        break;
    case ZfCtapeCmdGetAssertion:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_get_assertion(app, cid, request_body, request_body_len, response_body,
                                         response_body_capacity, response_body_len);
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
        status = zf_ctap_assertion_queue_handle_next(app, cid, response_body,
                                                     response_body_capacity, response_body_len);
        break;
    case ZfCtapeCmdSelection:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_handle_selection(app, cid, request_body_len + 1U, response_body_len);
        break;
    default:
        *response_body_len = 0;
        break;
    }

    return status;
}
