#include "policy.h"

#include "../zerofido_app_i.h"
#include "../zerofido_pin.h"
#include "../zerofido_store.h"

bool zf_ctap_request_uses_allow_list(const ZfGetAssertionRequest *request) {
    return request->has_allow_list && request->allow_list_count > 0;
}

uint8_t zf_ctap_validate_pin_auth_protocol(bool has_pin_auth, bool has_pin_protocol,
                                           uint64_t pin_protocol) {
    if (!has_pin_auth) {
        return ZF_CTAP_SUCCESS;
    }
    if (!has_pin_protocol) {
        return ZF_CTAP_ERR_MISSING_PARAMETER;
    }
    if (pin_protocol != 1U) {
        return ZF_CTAP_ERR_INVALID_PARAMETER;
    }
    return ZF_CTAP_SUCCESS;
}

bool zf_ctap_effective_uv_requested(bool has_pin_auth, bool has_uv, bool uv) {
    return !has_pin_auth && has_uv && uv;
}

uint8_t zf_ctap_require_empty_payload(size_t request_len) {
    return request_len == 1 ? ZF_CTAP_SUCCESS : ZF_CTAP_ERR_INVALID_LENGTH;
}

bool zf_ctap_local_maintenance_busy(ZerofidoApp *app) {
    bool busy = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    busy = app->maintenance_busy;
    furi_mutex_release(app->ui_mutex);
    return busy;
}

bool zf_ctap_pin_is_set(ZerofidoApp *app) {
    bool pin_is_set = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    pin_is_set = zerofido_pin_is_set(&app->pin_state);
    furi_mutex_release(app->ui_mutex);
    return pin_is_set;
}

static bool zf_ctap_credential_is_allowed_by_cred_protect(const ZfGetAssertionRequest *request,
                                                          const ZfCredentialIndexEntry *record,
                                                          bool uv_verified) {
    if (!record) {
        return false;
    }

    switch (record->cred_protect) {
    case 0:
    case ZF_CRED_PROTECT_UV_OPTIONAL:
        return true;
    case ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID:
        return uv_verified || zf_ctap_request_uses_allow_list(request);
    case ZF_CRED_PROTECT_UV_REQUIRED:
        return uv_verified;
    default:
        return false;
    }
}

size_t zf_ctap_resolve_assertion_matches(ZfCredentialStore *store,
                                         const ZfGetAssertionRequest *request, bool uv_verified,
                                         uint16_t *match_indices) {
    uint16_t resolved[ZF_MAX_CREDENTIALS];
    size_t resolved_count = 0;
    size_t filtered_count = 0;

    if (zf_ctap_request_uses_allow_list(request)) {
        resolved_count = zf_store_find_by_rp_and_allow_list(
            store, request->rp_id, request->allow_list, request->allow_list_lens,
            request->allow_list_count, resolved, ZF_MAX_CREDENTIALS);
    } else {
        resolved_count = zf_store_find_by_rp(store, request->rp_id, resolved, ZF_MAX_CREDENTIALS);
    }

    for (size_t i = 0; i < resolved_count; ++i) {
        if (zf_ctap_credential_is_allowed_by_cred_protect(request, &store->records[resolved[i]],
                                                          uv_verified)) {
            match_indices[filtered_count++] = resolved[i];
        }
    }

    return filtered_count;
}
