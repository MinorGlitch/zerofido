#include "dispatch.h"

#include <string.h>

#include "commands/get_assertion.h"
#include "commands/make_credential.h"
#include "commands/reset.h"
#include "core/approval.h"
#include "core/assertion_queue.h"
#include "core/internal.h"
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
        status = zf_ctap_handle_reset(app, session_id, request_body_len + 1U, response_body_len);
        break;
    case ZfCtapeCmdMakeCredential:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_ctap_handle_make_credential(app, session_id, request_body, request_body_len,
                                                response_body, response_body_capacity,
                                                response_body_len);
        break;
    case ZfCtapeCmdGetAssertion:
        status = zf_ctap_dispatch_require_idle(app);
        if (status != ZF_CTAP_SUCCESS) {
            break;
        }
        status = zf_ctap_handle_get_assertion(app, session_id, request_body, request_body_len,
                                              response_body, response_body_capacity,
                                              response_body_len);
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
