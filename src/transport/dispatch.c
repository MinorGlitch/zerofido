#include "dispatch.h"

#include <string.h>

#include "../zerofido_app_i.h"
#include "../zerofido_ctap.h"
#include "../zerofido_notify.h"
#include "../zerofido_runtime_config.h"
#include "../u2f/adapter.h"

static bool zf_transport_dispatch_was_interrupted(const ZfTransportState *transport,
                                                  uint32_t generation) {
    return generation != transport->processing_generation;
}

static void zf_transport_dispatch_error(ZfProtocolDispatchResult *result, uint8_t hid_error) {
    memset(result, 0, sizeof(*result));
    result->send_transport_error = true;
    result->transport_error = hid_error;
}

static void zf_transport_dispatch_begin(ZfProtocolDispatchResult *result,
                                        uint8_t response_command) {
    uint8_t *response = result->response;
    size_t response_capacity = result->response_capacity;

    memset(result, 0, sizeof(*result));
    result->response = response;
    result->response_capacity = response_capacity;
    result->transport_response_command = response_command;
}

static void zf_transport_dispatch_reject_unsupported(ZerofidoApp *app,
                                                     ZfProtocolDispatchResult *result) {
    zerofido_notify_error(app);
    zf_transport_dispatch_error(result, ZF_HID_ERR_INVALID_CMD);
}

static void zf_transport_dispatch_ping(const ZfProtocolDispatchRequest *request,
                                       ZfProtocolDispatchResult *result) {
    zf_transport_dispatch_begin(result, ZF_CTAPHID_PING);
    result->response_len = request->payload_len;
    if (request->payload_len > 0) {
        memcpy(result->response, request->payload, request->payload_len);
    }
}

static void zf_transport_dispatch_u2f(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                      ZfProtocolDispatchResult *result) {
    zf_transport_dispatch_begin(result, ZF_CTAPHID_MSG);
    result->response_len =
        zf_u2f_adapter_handle_msg(app, request->cid, request->payload, request->payload_len,
                                  result->response, result->response_capacity);
}

static void zf_transport_dispatch_cbor(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                       ZfProtocolDispatchResult *result) {
    zf_transport_dispatch_begin(result, ZF_CTAPHID_CBOR);
    result->response_len =
        zerofido_handle_ctap2(app, request->cid, request->payload, request->payload_len,
                              result->response, result->response_capacity);
}

static void zf_transport_dispatch_wink(ZerofidoApp *app, ZfProtocolDispatchResult *result) {
    zf_transport_dispatch_begin(result, ZF_CTAPHID_WINK);
    zf_u2f_adapter_wink(app);
}

static void zf_transport_dispatch_send_result(ZerofidoApp *app,
                                              const ZfProtocolDispatchRequest *request,
                                              const ZfProtocolDispatchResult *result) {
    if (result->send_transport_error) {
        zf_transport_session_send_error(request->cid, result->transport_error);
        return;
    }

    if (result->response_len == 0 && request->transport_command != ZF_CTAPHID_WINK) {
        zerofido_notify_error(app);
        zf_transport_session_send_error(request->cid, ZF_HID_ERR_OTHER);
        return;
    }

    zf_transport_session_send_frames(request->cid, result->transport_response_command,
                                     result->response, result->response_len);
}

static void zf_transport_dispatch_abort_if_interrupted(ZfTransportState *transport,
                                                       uint32_t generation) {
    if (zf_transport_dispatch_was_interrupted(transport, generation)) {
        return;
    }

    transport->processing = false;
}

void zf_transport_dispatch_complete_message(ZerofidoApp *app, ZfTransportState *transport,
                                            uint32_t cid, uint8_t transport_command,
                                            const uint8_t *payload, size_t payload_len) {
    ZfResolvedCapabilities capabilities;
    ZfProtocolDispatchRequest request = {
        .cid = cid,
        .transport_command = transport_command,
        .payload = payload,
        .payload_len = payload_len,
    };
    ZfProtocolDispatchResult result = {0};
    uint32_t generation = transport->processing_generation + 1;
    result.response = app->transport_response_buffer;
    result.response_capacity = ZF_MAX_MSG_SIZE;

    transport->processing_generation = generation;
    transport->processing = true;
    transport->processing_resync = false;
    zf_runtime_get_effective_capabilities(app, &capabilities);

    switch (request.transport_command) {
    case ZF_CTAPHID_PING:
        zf_transport_dispatch_ping(&request, &result);
        break;
    case ZF_CTAPHID_MSG:
        if (!capabilities.u2f_enabled) {
            zf_transport_dispatch_reject_unsupported(app, &result);
            break;
        }
        zf_transport_dispatch_u2f(app, &request, &result);
        break;
    case ZF_CTAPHID_WINK:
        if (!capabilities.transport_wink_enabled || !zf_u2f_adapter_is_available(app)) {
            zf_transport_dispatch_reject_unsupported(app, &result);
            break;
        }
        zf_transport_dispatch_wink(app, &result);
        break;
    case ZF_CTAPHID_CBOR:
        if (!capabilities.fido2_enabled) {
            zf_transport_dispatch_reject_unsupported(app, &result);
            break;
        }
        zf_transport_dispatch_cbor(app, &request, &result);
        break;
    default:
        zf_transport_dispatch_reject_unsupported(app, &result);
        break;
    }

    if (zf_transport_dispatch_was_interrupted(transport, generation)) {
        return;
    }

    if (request.transport_command == ZF_CTAPHID_CBOR && transport->processing_cancel_requested) {
        result.send_transport_error = false;
        result.transport_response_command = ZF_CTAPHID_CBOR;
        result.response[0] = ZF_CTAP_ERR_KEEPALIVE_CANCEL;
        result.response_len = 1;
    }

    zf_transport_dispatch_send_result(app, &request, &result);

    zf_transport_dispatch_abort_if_interrupted(transport, generation);
}
