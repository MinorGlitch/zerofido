#include "approval.h"

#include "policy.h"
#include "../zerofido_app_i.h"
#include "../zerofido_ui.h"

static uint8_t zf_ctap_status_from_interaction_state(ZfApprovalState state,
                                                     bool timeout_is_denied) {
    switch (state) {
    case ZfApprovalTimedOut:
        return timeout_is_denied ? ZF_CTAP_ERR_OPERATION_DENIED : ZF_CTAP_ERR_USER_ACTION_TIMEOUT;
    case ZfApprovalCanceled:
        return ZF_CTAP_ERR_KEEPALIVE_CANCEL;
    case ZfApprovalDenied:
    case ZfApprovalIdle:
    case ZfApprovalPending:
    case ZfApprovalApproved:
    default:
        return ZF_CTAP_ERR_OPERATION_DENIED;
    }
}

uint8_t zf_ctap_request_approval(ZerofidoApp *app, const char *operation, const char *rp_id,
                                 const char *user_text, uint32_t cid) {
    bool approved = false;
    if (!zerofido_ui_request_approval(app, ZfUiProtocolFido2, operation, rp_id, user_text, cid,
                                      &approved)) {
        return ZF_CTAP_ERR_USER_ACTION_TIMEOUT;
    }
    if (approved) {
        return ZF_CTAP_SUCCESS;
    }

    return zf_ctap_status_from_interaction_state(zerofido_ui_get_interaction_state(app), false);
}

uint8_t zf_ctap_request_assertion_selection(ZerofidoApp *app, const char *rp_id,
                                            const uint16_t *match_indices, size_t match_count,
                                            uint32_t cid, uint32_t *selected_record_index) {
    if (!zerofido_ui_request_assertion_selection(app, rp_id, match_indices, match_count, cid,
                                                 selected_record_index)) {
        return zf_ctap_status_from_interaction_state(zerofido_ui_get_interaction_state(app), true);
    }

    return ZF_CTAP_SUCCESS;
}

uint8_t zf_ctap_handle_empty_pin_auth_probe(ZerofidoApp *app, uint32_t cid, const char *operation,
                                            const char *rp_id, const char *user_text) {
    uint8_t status = zf_ctap_request_approval(app, operation, rp_id, user_text, cid);
    if (status != ZF_CTAP_SUCCESS) {
        return status;
    }

    return zf_ctap_pin_is_set(app) ? ZF_CTAP_ERR_PIN_INVALID : ZF_CTAP_ERR_PIN_NOT_SET;
}
